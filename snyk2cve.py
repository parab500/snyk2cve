#!/usr/bin/env python3


from __future__ import annotations

import json
import random
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# --------------------------------------------------------------------------
# Rich console (single shared instance — stderr=False so output goes to
# stdout, keeping the TXT-file content unaffected by redirection).
# --------------------------------------------------------------------------

console = Console(highlight=False)

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

BASE_URL = "https://security.snyk.io"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
VULN_LINK_PATTERN = re.compile(r"^/vuln/(SNYK-[^/]+|[^/]+:[^/]+)$")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")
SLEEP_MIN_SECONDS = 0.8
SLEEP_MAX_SECONDS = 1.5
REACTIVITY_TAGS = {"ShallowReactive", "Reactive", "ShallowRef", "Ref"}

# Tags used by Nuxt's "devalue" flattened-array serialization format that
# wrap a reference to another index in the same array.


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------


@dataclass
class Advisory:
    """A single Snyk advisory page's relevant extracted data."""

    url: str
    name: Optional[str] = None
    cves: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Rich UI helpers
# --------------------------------------------------------------------------


def print_banner() -> None:
    """Display the application banner."""
    banner = Text(justify="center")
    banner.append("\n  snyk2cve\n", style="bold magenta")
    banner.append("  Snyk CVE Extraction Utility\n", style="magenta")
    console.print(Panel(banner, border_style="magenta", padding=(0, 4)))


def log_info(message: str) -> None:
    """Print a blue informational status line."""
    console.print(f"  [bold blue]\\[INFO][/bold blue]  {message}")


def log_success(message: str) -> None:
    """Print a green success status line."""
    console.print(f"  [bold green]\\[SUCCESS][/bold green] {message}")


def log_warning(message: str) -> None:
    """Print a yellow warning status line."""
    console.print(f"  [bold yellow]\\[WARNING][/bold yellow] {message}")


def log_error(message: str) -> None:
    """Print a red error status line."""
    console.print(f"  [bold red]\\[ERROR][/bold red] {message}")


# --------------------------------------------------------------------------
# HTTP session helpers
# --------------------------------------------------------------------------


def build_session() -> requests.Session:
    """Create a single requests.Session configured with retry logic.

    Retries on common transient HTTP failures (429, 500, 502, 503, 504)
    using an exponential backoff, and sets a realistic browser User-Agent.
    """
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;"
                "q=0.9,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
    )

    retry_strategy = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def fetch_page(session: requests.Session, url: str, timeout: int = 20) -> Optional[str]:
    """Fetch a URL and return its HTML text, or None on failure."""
    try:
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response.text
    except requests.RequestException as exc:
        log_warning(f"Failed to fetch {url}: {exc}")
        return None


def polite_sleep() -> None:
    """Sleep a random short interval to avoid hammering the server."""
    time.sleep(random.uniform(SLEEP_MIN_SECONDS, SLEEP_MAX_SECONDS))


# --------------------------------------------------------------------------
# Package page parsing: collect advisory links
# --------------------------------------------------------------------------


def extract_package_name_version(package_url: str) -> str:
    """Derive a filesystem-friendly "<package>_<version>" label from a URL.

    Example:
        https://security.snyk.io/package/npm/axios/0.21.4
        -> "axios_0.21.4"

    Scoped npm packages (e.g. "@babel/core") are flattened by replacing
    "/" with "_" so the result is still a valid filename.
    """
    path = urlparse(package_url).path
    parts = [p for p in path.split("/") if p]
    # Expected shape: package / <ecosystem> / <name...> / <version>
    if len(parts) < 3:
        # Not enough info to build a clean label; fall back to last segment.
        return parts[-1] if parts else "package"

    ecosystem_index = parts.index("package") + 1 if "package" in parts else 0
    name_and_version = parts[ecosystem_index + 1:]
    if not name_and_version:
        return "_".join(parts)

    version = name_and_version[-1]
    name_parts = name_and_version[:-1]
    name = "-".join(name_parts) if name_parts else "package"
    name = name.replace("/", "_")
    return f"{name}_{version}"


def collect_advisory_urls(session: requests.Session, package_url: str) -> List[str]:
    """Fetch the package page and return every unique advisory URL found."""
    html = fetch_page(session, package_url)
    if html is None:
        raise RuntimeError(f"Could not load package page: {package_url}")

    found: Set[str] = set()

    # Parse only <a href> elements and keep links that are exactly one
    # path segment beneath /vuln/ — e.g.:
    #   /vuln/SNYK-JS-AXIOS-17111060  ✓
    #   /vuln/npm:jquery:20150627     ✓
    #   /vuln                         ✗  (no trailing segment)
    #   /vuln/npm                     ✗  (ecosystem breadcrumb)
    #   /vuln/npm/jquery              ✗  (two trailing segments)
    soup = BeautifulSoup(html, "lxml")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if VULN_LINK_PATTERN.match(href):
            found.add(urljoin(BASE_URL, href))

    return sorted(found)


# --------------------------------------------------------------------------
# Nuxt "__NUXT_DATA__" structured-data resolver
# --------------------------------------------------------------------------


def parse_nuxt_data_array(html: str) -> Optional[List[Any]]:
    """Extract and JSON-decode the raw __NUXT_DATA__ flattened array.

    Returns None if the script tag is missing or cannot be parsed.
    """
    match = re.search(
        r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>',
        html,
        re.DOTALL,
    )
    if not match:
        return None

    raw_text = match.group(1).strip()
    try:
        decoded = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        log_warning(f"Could not decode __NUXT_DATA__ JSON: {exc}")
        return None

    if not isinstance(decoded, list):
        return None
    return decoded


def resolve_nuxt_value(raw: List[Any], index: int, cache: Dict[int, Any]) -> Any:
    """Recursively resolve Nuxt's "devalue"-style flattened-array payload.

    The payload is a single top-level array. Each element may be:
      * a primitive (str, int, float, bool, None) -> returned as-is,
      * a dict whose *values* are integer indices into ``raw`` that must
        be resolved recursively,
      * a list whose *elements* are integer indices into ``raw`` that must
        be resolved recursively, OR a tagged wrapper such as
        ["ShallowReactive", <index>] / ["Reactive", <index>] which simply
        means "the real value lives at <index>".

    ``cache`` memoizes already-resolved indices, which both improves
    performance and protects against possible circular references.
    """
    if index in cache:
        return cache[index]
    if index < 0 or index >= len(raw):
        return None

    value = raw[index]

    # Tagged reactivity wrapper, e.g. ["ShallowReactive", 1]
    if (
        isinstance(value, list)
        and value
        and isinstance(value[0], str)
        and value[0] in REACTIVITY_TAGS
    ):
        cache[index] = None  # placeholder to guard against cycles
        resolved = resolve_nuxt_value(raw, value[1], cache) if len(value) > 1 else None
        cache[index] = resolved
        return resolved

    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        cache[index] = result
        for key, sub_index in value.items():
            if isinstance(sub_index, int):
                result[key] = resolve_nuxt_value(raw, sub_index, cache)
            else:
                # Already a literal (shouldn't normally happen for dict
                # values, but handle defensively).
                result[key] = sub_index
        return result

    if isinstance(value, list):
        result_list: List[Any] = []
        cache[index] = result_list
        for sub_index in value:
            if isinstance(sub_index, int):
                result_list.append(resolve_nuxt_value(raw, sub_index, cache))
            else:
                result_list.append(sub_index)
        return result_list

    # Primitive: string, number, bool, or None.
    cache[index] = value
    return value


def find_vuln_data_in_nuxt(html: str) -> Optional[Dict[str, Any]]:
    """Resolve __NUXT_DATA__ and return the advisory's "vulnData" object.

    Returns None if structured data is unavailable or doesn't have the
    expected shape, so the caller can fall back to HTML scraping.
    """
    raw = parse_nuxt_data_array(html)
    if not raw:
        return None

    try:
        cache: Dict[int, Any] = {}
        root = resolve_nuxt_value(raw, 0, cache)
    except (RecursionError, IndexError, TypeError) as exc:
        log_warning(f"Failed to resolve __NUXT_DATA__ structure: {exc}")
        return None

    if not isinstance(root, dict):
        return None

    data_section = root.get("data")
    if not isinstance(data_section, dict):
        return None

    vuln_data = data_section.get("vulnData")
    if isinstance(vuln_data, dict) and "title" in vuln_data:
        return vuln_data

    # Some pages may nest vulnData under a differently-named root key;
    # search any dict value that looks like a vulnerability record.
    for value in data_section.values():
        if isinstance(value, dict) and "title" in value and "identifiers" in value:
            return value

    return None


def extract_from_nuxt(html: str) -> Optional[Advisory]:
    """Build an Advisory from structured Nuxt data, or None if unavailable."""
    vuln_data = find_vuln_data_in_nuxt(html)
    if vuln_data is None:
        return None

    name = vuln_data.get("title")
    if not isinstance(name, str) or not name.strip():
        return None

    cves: List[str] = []
    identifiers = vuln_data.get("identifiers")
    if isinstance(identifiers, dict):
        cve_list = identifiers.get("CVE")
        if isinstance(cve_list, list):
            cves = [cve for cve in cve_list if isinstance(cve, str) and CVE_PATTERN.fullmatch(cve)]

    return Advisory(url="", name=name.strip(), cves=cves)


# --------------------------------------------------------------------------
# HTML fallback parsing
# --------------------------------------------------------------------------


def extract_from_html(html: str) -> Advisory:
    """Best-effort fallback parser using visible HTML when structured data
    is unavailable. Looks for the page <title>/<h1> for the vulnerability
    name, and scans the full page text for CVE identifiers.
    """
    soup = BeautifulSoup(html, "lxml")

    name: Optional[str] = None
    heading = soup.find("h1")
    if heading and heading.get_text(strip=True):
        name = heading.get_text(strip=True)
    elif soup.title and soup.title.get_text(strip=True):
        # Title is typically "<Vuln Name> in <package> | CVE-... | Snyk"
        title_text = soup.title.get_text(strip=True)
        name = title_text.split(" in ")[0].strip() or title_text

    cves = sorted(set(CVE_PATTERN.findall(soup.get_text(" "))))

    return Advisory(url="", name=name or "Unknown Vulnerability", cves=cves)


# --------------------------------------------------------------------------
# Advisory fetching orchestration
# --------------------------------------------------------------------------


def fetch_advisory(
    session: requests.Session,
    advisory_url: str,
    progress: Progress,
    task_id: Any,
    position: int,
    total: int,
) -> Advisory:
    """Fetch a single advisory page and extract its name + CVEs.

    Updates the shared Rich Progress bar and logs per-advisory status.
    Prefers structured __NUXT_DATA__; falls back to HTML scraping.
    """
    progress.update(task_id, description=f"  [cyan]Fetching advisory {position}/{total}[/cyan]")

    html = fetch_page(session, advisory_url)
    if html is None:
        log_error(f"Failed to fetch advisory  [dim]{advisory_url}[/dim]")
        progress.advance(task_id)
        return Advisory(url=advisory_url, name=None, cves=[])

    advisory = extract_from_nuxt(html)
    if advisory is None:
        log_warning(
            f"Structured data unavailable — falling back to HTML  "
            f"[dim]{advisory_url}[/dim]"
        )
        advisory = extract_from_html(html)

    advisory.url = advisory_url

    if advisory.cves:
        log_success(
            f"[bold white]{advisory.name}[/bold white]  "
            f"[dim]→[/dim]  [green]{', '.join(advisory.cves)}[/green]"
        )
    else:
        log_warning(
            f"[bold white]{advisory.name}[/bold white]  "
            f"[dim]→[/dim]  No CVE"
        )

    progress.advance(task_id)
    return advisory


def fetch_all_advisories(
    session: requests.Session,
    advisory_urls: List[str],
) -> List[Advisory]:
    """Fetch every advisory page behind a Rich progress bar."""
    advisories: List[Advisory] = []
    total = len(advisory_urls)

    progress = Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("{task.description}"),
        BarColumn(bar_width=36, style="cyan", complete_style="bold cyan"),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )

    with progress:
        task_id = progress.add_task(
            f"  [cyan]Fetching advisories[/cyan]",
            total=total,
        )
        for position, advisory_url in enumerate(advisory_urls, start=1):
            advisories.append(
                fetch_advisory(session, advisory_url, progress, task_id, position, total)
            )
            if position < total:
                polite_sleep()

    return advisories


# --------------------------------------------------------------------------
# Grouping and formatting
# --------------------------------------------------------------------------


def group_by_name(advisories: List[Advisory]) -> Dict[str, List[str]]:
    """Group advisories by exact vulnerability name, merging/deduping CVEs.

    Names with no CVEs from any contributing advisory will have an empty
    list as their value.
    """
    grouped: Dict[str, Set[str]] = {}

    for advisory in advisories:
        if not advisory.name:
            continue
        cve_set = grouped.setdefault(advisory.name, set())
        cve_set.update(advisory.cves)

    # Convert sets to sorted lists for stable, deterministic output.
    return {name: sorted(cves) for name, cves in grouped.items()}


def format_results(package_label: str, grouped: Dict[str, List[str]]) -> str:
    """Render the grouped results as the required plain-text report.

    This output is written verbatim to the TXT file — no Rich markup.
    """
    lines: List[str] = []
    separator = "=" * 52

    lines.append(separator)
    lines.append(f"Package: {package_label.replace('_', ' ', 1)}")
    lines.append(separator)
    lines.append("")

    for name in sorted(grouped.keys()):
        cves = grouped[name]
        lines.append(f"{name}:")
        if cves:
            lines.extend(cves)
        else:
            lines.append("No CVE")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def save_to_file(filename: str, content: str) -> None:
    """Write the plain-text report to a TXT file."""
    try:
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        raise RuntimeError(f"Failed to write output file '{filename}': {exc}") from exc


# --------------------------------------------------------------------------
# Rich terminal display of results
# --------------------------------------------------------------------------


def display_summary_table(grouped: Dict[str, List[str]]) -> None:
    """Print a Rich table summarising every vulnerability and its CVE count."""
    table = Table(
        show_header=True,
        header_style="bold white on dark_blue",
        border_style="blue",
        show_lines=True,
        expand=False,
        title="[bold blue]Vulnerability Summary[/bold blue]",
        title_justify="left",
    )
    table.add_column("Vulnerability", style="white", no_wrap=False, min_width=44)
    table.add_column("CVEs", style="cyan", justify="center", min_width=6)

    for name in sorted(grouped.keys()):
        cves = grouped[name]
        count = str(len(cves)) if cves else "[yellow]—[/yellow]"
        table.add_row(name, count)

    console.print()
    console.print(table)


def display_results(grouped: Dict[str, List[str]]) -> None:
    """Print each vulnerability and its CVEs as visually separated blocks."""
    console.print()
    console.print(Rule("[bold white]Results[/bold white]", style="blue"))

    for name in sorted(grouped.keys()):
        cves = grouped[name]
        console.print()

        # Vulnerability name in bold white
        console.print(f"  [bold white]{name}[/bold white]")

        if cves:
            for cve in cves:
                console.print(f"  [green]{cve}[/green]")
        else:
            console.print("  [yellow]No CVE[/yellow]")

    console.print()
    console.print(Rule(style="blue"))


def display_final_summary(
    package_label: str,
    grouped: Dict[str, List[str]],
    total_advisories: int,
    output_filename: str,
    elapsed: float,
) -> None:
    """Print the final statistics panel."""
    package_display = package_label.replace("_", " ", 1)
    all_cves: Set[str] = set()
    for cves in grouped.values():
        all_cves.update(cves)

    lines = Text()
    lines.append("  Package            ", style="dim")
    lines.append(f"{package_display}\n", style="bold white")
    lines.append("  Advisories scanned ", style="dim")
    lines.append(f"{total_advisories}\n", style="bold cyan")
    lines.append("  Unique vuln names  ", style="dim")
    lines.append(f"{len(grouped)}\n", style="bold cyan")
    lines.append("  Unique CVEs        ", style="dim")
    lines.append(f"{len(all_cves)}\n", style="bold cyan")
    lines.append("  Output file        ", style="dim")
    lines.append(f"{output_filename}\n", style="bold green")
    lines.append("  Completed in       ", style="dim")
    lines.append(f"{elapsed:.2f}s", style="bold magenta")

    console.print()
    console.print(
        Panel(
            lines,
            title="[bold white]Done[/bold white]",
            border_style="green",
            padding=(0, 2),
        )
    )
    console.print()


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------


def get_package_url() -> str:
    """Return the package URL from argv[1], or prompt the user for one."""
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    console.print("  [bold blue]Enter Snyk Package URL:[/bold blue] ", end="")
    return input().strip()


def validate_package_url(package_url: str) -> None:
    """Raise ValueError if the URL doesn't look like a Snyk package URL."""
    parsed = urlparse(package_url)
    if parsed.scheme not in ("http", "https") or "snyk.io" not in parsed.netloc:
        raise ValueError(f"'{package_url}' does not look like a valid Snyk URL.")
    if "/package/" not in parsed.path:
        raise ValueError(
            f"'{package_url}' does not look like a Snyk *package* page URL "
            "(expected a path containing '/package/')."
        )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main() -> int:
    start_time = time.monotonic()

    print_banner()

    # ── Input ────────────────────────────────────────────────────────────────
    try:
        package_url = get_package_url()
        validate_package_url(package_url)
    except ValueError as exc:
        log_error(str(exc))
        return 1

    package_label = extract_package_name_version(package_url)
    package_display = package_label.replace("_", " ", 1)
    console.print()
    log_info(f"Target package  [bold white]{package_display}[/bold white]")

    # ── Discover advisories ──────────────────────────────────────────────────
    session = build_session()

    with console.status("[cyan]Loading package page…[/cyan]", spinner="dots"):
        try:
            advisory_urls = collect_advisory_urls(session, package_url)
        except RuntimeError as exc:
            log_error(str(exc))
            return 1

    if not advisory_urls:
        log_warning("No advisories were found for this package.")
        return 0

    log_info(f"Found [bold cyan]{len(advisory_urls)}[/bold cyan] advisories")
    console.print()

    # ── Fetch every advisory ─────────────────────────────────────────────────
    advisories = fetch_all_advisories(session, advisory_urls)

    # ── Group and format ─────────────────────────────────────────────────────
    grouped = group_by_name(advisories)
    report = format_results(package_label, grouped)

    # ── Terminal display ─────────────────────────────────────────────────────
    display_summary_table(grouped)
    display_results(grouped)

    # ── Save TXT file ────────────────────────────────────────────────────────
    output_filename = f"{package_label}_cves.txt"
    try:
        save_to_file(output_filename, report)
    except RuntimeError as exc:
        log_error(str(exc))
        return 1

    # ── Final summary panel ──────────────────────────────────────────────────
    elapsed = time.monotonic() - start_time
    display_final_summary(
        package_label=package_label,
        grouped=grouped,
        total_advisories=len(advisory_urls),
        output_filename=output_filename,
        elapsed=elapsed,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
