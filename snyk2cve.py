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

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

BASE_URL = "https://security.snyk.io"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
VULN_LINK_PATTERN = re.compile(r"/vuln/SNYK-[A-Za-z0-9\-]+")
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
        print(f"[WARN] Failed to fetch {url}: {exc}", file=sys.stderr)
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

    # Primary: search raw HTML/script text for any "/vuln/SNYK-..." path.
    # This catches links embedded both in <a href> tags and in any
    # client-side rendered JSON/JS blobs.
    for match in VULN_LINK_PATTERN.finditer(html):
        found.add(urljoin(BASE_URL, match.group(0)))

    # Secondary (belt-and-braces): explicitly walk anchor tags too, in case
    # relative paths use a different casing or query string.
    soup = BeautifulSoup(html, "lxml")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"]
        if VULN_LINK_PATTERN.search(href):
            match = VULN_LINK_PATTERN.search(href)
            if match:
                found.add(urljoin(BASE_URL, match.group(0)))

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
        print(f"[WARN] Could not decode __NUXT_DATA__ JSON: {exc}", file=sys.stderr)
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
        print(f"[WARN] Failed to resolve __NUXT_DATA__ structure: {exc}", file=sys.stderr)
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


def fetch_advisory(session: requests.Session, advisory_url: str) -> Advisory:
    """Fetch a single advisory page and extract its name + CVEs.

    Prefers structured __NUXT_DATA__; falls back to HTML scraping.
    """
    html = fetch_page(session, advisory_url)
    if html is None:
        return Advisory(url=advisory_url, name=None, cves=[])

    advisory = extract_from_nuxt(html)
    if advisory is None:
        print(
            f"[INFO] Structured data unavailable for {advisory_url}; "
            "falling back to HTML parsing.",
            file=sys.stderr,
        )
        advisory = extract_from_html(html)

    advisory.url = advisory_url
    return advisory


def fetch_all_advisories(session: requests.Session, advisory_urls: List[str]) -> List[Advisory]:
    """Fetch every advisory page, sleeping politely between requests."""
    advisories: List[Advisory] = []
    total = len(advisory_urls)

    for position, advisory_url in enumerate(advisory_urls, start=1):
        print(f"[INFO] ({position}/{total}) Fetching {advisory_url}", file=sys.stderr)
        advisories.append(fetch_advisory(session, advisory_url))
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
    """Render the grouped results as the required human-readable report."""
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
            lines.append("CVE NOT AVAILABLE")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def save_to_file(filename: str, content: str) -> None:
    """Write the report to a TXT file, raising a clear error on failure."""
    try:
        with open(filename, "w", encoding="utf-8") as handle:
            handle.write(content)
    except OSError as exc:
        raise RuntimeError(f"Failed to write output file '{filename}': {exc}") from exc


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------


def get_package_url() -> str:
    """Return the package URL from argv[1], or prompt the user for one."""
    if len(sys.argv) > 1 and sys.argv[1].strip():
        return sys.argv[1].strip()
    return input("Enter Snyk Package URL: ").strip()


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
    try:
        package_url = get_package_url()
        validate_package_url(package_url)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    package_label = extract_package_name_version(package_url)
    session = build_session()

    try:
        advisory_urls = collect_advisory_urls(session, package_url)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if not advisory_urls:
        print("[INFO] No advisories were found for this package.", file=sys.stderr)

    advisories = fetch_all_advisories(session, advisory_urls)
    grouped = group_by_name(advisories)
    report = format_results(package_label, grouped)

    print(report)

    output_filename = f"{package_label}_cves.txt"
    try:
        save_to_file(output_filename, report)
        print(f"[INFO] Results saved to {output_filename}", file=sys.stderr)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
