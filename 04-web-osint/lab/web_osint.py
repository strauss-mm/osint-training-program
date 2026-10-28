#!/usr/bin/env python3
"""
Web Application OSINT Tool

Performs passive reconnaissance on a web application by analyzing HTTP headers,
querying the Wayback Machine for historical data, extracting page resources,
and fingerprinting the technology stack.

All techniques are passive -- no active exploitation or vulnerability scanning.

Usage:
    python web_osint.py --url https://example.com
    python web_osint.py --url https://example.com --output report.json
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Technology Fingerprinting Patterns
# ---------------------------------------------------------------------------
# OSINT Methodology: Web applications reveal their technology stack through
# predictable patterns in HTTP headers, HTML content, and resource paths.
# Each pattern below maps an observable indicator to a technology.

# Header-based detection: servers often advertise software in response headers.
HEADER_FINGERPRINTS: dict[str, list[dict[str, str]]] = {
    "server": [
        {"pattern": r"apache", "tech": "Apache HTTP Server"},
        {"pattern": r"nginx", "tech": "Nginx"},
        {"pattern": r"microsoft-iis", "tech": "Microsoft IIS"},
        {"pattern": r"cloudflare", "tech": "Cloudflare"},
        {"pattern": r"litespeed", "tech": "LiteSpeed"},
        {"pattern": r"openresty", "tech": "OpenResty (Nginx)"},
        {"pattern": r"gunicorn", "tech": "Gunicorn (Python)"},
        {"pattern": r"envoy", "tech": "Envoy Proxy"},
    ],
    # X-Powered-By directly reveals application frameworks.
    "x-powered-by": [
        {"pattern": r"php", "tech": "PHP"},
        {"pattern": r"asp\.net", "tech": "ASP.NET"},
        {"pattern": r"express", "tech": "Express.js (Node.js)"},
        {"pattern": r"next\.js", "tech": "Next.js"},
        {"pattern": r"django", "tech": "Django"},
        {"pattern": r"flask", "tech": "Flask"},
    ],
    # X-Generator is set by many CMS platforms.
    "x-generator": [
        {"pattern": r"wordpress", "tech": "WordPress"},
        {"pattern": r"drupal", "tech": "Drupal"},
        {"pattern": r"joomla", "tech": "Joomla"},
    ],
}

# Cookie-based detection: session cookie names are framework-specific defaults
# that developers rarely change.
COOKIE_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": r"PHPSESSID", "tech": "PHP"},
    {"pattern": r"JSESSIONID", "tech": "Java (Servlet/JSP)"},
    {"pattern": r"ASP\.NET_SessionId", "tech": "ASP.NET"},
    {"pattern": r"csrftoken", "tech": "Django"},
    {"pattern": r"_rails_session", "tech": "Ruby on Rails"},
    {"pattern": r"laravel_session", "tech": "Laravel (PHP)"},
    {"pattern": r"connect\.sid", "tech": "Express.js (Node.js)"},
    {"pattern": r"wp-settings", "tech": "WordPress"},
]

# HTML content patterns: CMS platforms and frameworks leave identifiable
# markers in the page source.
HTML_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', "tech": "WordPress"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "tech": "Drupal"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "tech": "Joomla"},
    {"pattern": r'/wp-content/', "tech": "WordPress"},
    {"pattern": r'/wp-includes/', "tech": "WordPress"},
    {"pattern": r'/sites/default/files/', "tech": "Drupal"},
    {"pattern": r'/static/admin/', "tech": "Django Admin"},
    {"pattern": r'data-reactroot', "tech": "React"},
    {"pattern": r'ng-app|ng-controller|ng-model', "tech": "AngularJS"},
    {"pattern": r'__next', "tech": "Next.js"},
    {"pattern": r'__nuxt', "tech": "Nuxt.js"},
    {"pattern": r'window\.__GATSBY', "tech": "Gatsby"},
]

# JavaScript library detection via script src paths.
JS_FINGERPRINTS: list[dict[str, str]] = [
    {"pattern": r"jquery[.-](\d[\d.]*)", "tech": "jQuery"},
    {"pattern": r"react\.production\.min\.js|react-dom", "tech": "React"},
    {"pattern": r"angular[./]", "tech": "Angular"},
    {"pattern": r"vue\.(?:min\.)?js|vue\.global", "tech": "Vue.js"},
    {"pattern": r"bootstrap[.-](\d[\d.]*)", "tech": "Bootstrap"},
    {"pattern": r"lodash|underscore", "tech": "Lodash/Underscore"},
    {"pattern": r"moment\.min\.js", "tech": "Moment.js"},
    {"pattern": r"gsap|TweenMax", "tech": "GSAP"},
    {"pattern": r"d3\.(?:min\.)?js", "tech": "D3.js"},
    {"pattern": r"tailwindcss|tailwind", "tech": "Tailwind CSS"},
]

# Security headers to check for. Their absence is itself an OSINT finding
# because it reveals the application's security maturity.
SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


def fetch_page(url: str, timeout: int = 15) -> tuple[requests.Response | None, str | None]:
    """Fetch a page and return (response, error_message)."""
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return resp, None
    except requests.exceptions.Timeout:
        return None, f"Timeout after {timeout}s connecting to {url}"
    except requests.exceptions.ConnectionError as exc:
        return None, f"Connection error: {exc}"
    except requests.exceptions.RequestException as exc:
        return None, f"Request failed: {exc}"


# ---------------------------------------------------------------------------
# Header Analysis
# ---------------------------------------------------------------------------

def analyze_headers(response: requests.Response) -> dict[str, Any]:
    """
    Extract technology indicators from HTTP response headers.

    OSINT methodology: HTTP headers are the fastest passive fingerprinting
    technique. Servers advertise software versions, frameworks set default
    headers, and CDNs/WAFs insert their own identifiers.
    """
    result: dict[str, Any] = {
        "all_headers": dict(response.headers),
        "detected_technologies": [],
        "security_headers": {"present": [], "missing": []},
        "interesting_headers": {},
    }

    headers_lower = {k.lower(): v for k, v in response.headers.items()}

    # Match header values against known technology patterns.
    for header_name, patterns in HEADER_FINGERPRINTS.items():
        value = headers_lower.get(header_name, "")
        for fp in patterns:
            if re.search(fp["pattern"], value, re.IGNORECASE):
                result["detected_technologies"].append({
                    "technology": fp["tech"],
                    "source": f"Header: {header_name}",
                    "evidence": value,
                })

    # Check cookies for framework-specific session identifiers.
    set_cookie = headers_lower.get("set-cookie", "")
    for fp in COOKIE_FINGERPRINTS:
        if re.search(fp["pattern"], set_cookie, re.IGNORECASE):
            result["detected_technologies"].append({
                "technology": fp["tech"],
                "source": "Cookie name",
                "evidence": fp["pattern"],
            })

    # Audit security headers -- missing headers are findings.
    for header in SECURITY_HEADERS:
        if header.lower() in headers_lower:
            result["security_headers"]["present"].append(header)
        else:
            result["security_headers"]["missing"].append(header)

    # Flag headers that often contain useful OSINT data.
    interesting = [
        "x-powered-by", "x-aspnet-version", "x-generator",
        "x-drupal-cache", "x-varnish", "x-cache", "x-cdn",
        "x-amz-cf-id", "x-amz-cf-pop", "via",
    ]
    for h in interesting:
        if h in headers_lower:
            result["interesting_headers"][h] = headers_lower[h]

    return result


# ---------------------------------------------------------------------------
# HTML / Technology Fingerprinting
# ---------------------------------------------------------------------------

def analyze_html(html: str, base_url: str) -> dict[str, Any]:
    """
    Parse HTML content to identify technologies and extract resources.

    OSINT methodology: The HTML source contains meta tags, script paths,
    CSS references, and inline code that reveal the application's framework,
    CMS, JavaScript libraries, and third-party integrations.
    """
    soup = BeautifulSoup(html, "lxml")
    result: dict[str, Any] = {
        "detected_technologies": [],
        "scripts": [],
        "stylesheets": [],
        "meta_tags": {},
        "links": {"internal": [], "external": []},
        "forms": [],
        "comments": [],
    }

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc

    # -- Meta tags (generators, descriptions, open graph data) --
    for meta in soup.find_all("meta"):
        name = meta.get("name", meta.get("property", ""))
        content = meta.get("content", "")
        if name and content:
            result["meta_tags"][name] = content

    # -- HTML content pattern matching --
    for fp in HTML_FINGERPRINTS:
        if re.search(fp["pattern"], html, re.IGNORECASE):
            result["detected_technologies"].append({
                "technology": fp["tech"],
                "source": "HTML content",
                "evidence": fp["pattern"],
            })

    # -- Script tags: collect src URLs and check for JS fingerprints --
    for script in soup.find_all("script"):
        src = script.get("src", "")
        if src:
            full_url = urljoin(base_url, src)
            result["scripts"].append(full_url)
            # Check script path against JS library patterns.
            for fp in JS_FINGERPRINTS:
                if re.search(fp["pattern"], src, re.IGNORECASE):
                    result["detected_technologies"].append({
                        "technology": fp["tech"],
                        "source": "JavaScript reference",
                        "evidence": src,
                    })
        # Also check inline script content for framework indicators.
        inline = script.string or ""
        for fp in JS_FINGERPRINTS:
            if re.search(fp["pattern"], inline, re.IGNORECASE):
                result["detected_technologies"].append({
                    "technology": fp["tech"],
                    "source": "Inline JavaScript",
                    "evidence": f"Pattern: {fp['pattern']}",
                })

    # -- Stylesheets --
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href", "")
        if href:
            result["stylesheets"].append(urljoin(base_url, href))

    # -- All links: categorize as internal or external --
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.netloc == base_domain or not parsed.netloc:
            result["links"]["internal"].append(full_url)
        else:
            result["links"]["external"].append(full_url)

    # -- Forms: action URLs and methods reveal application endpoints --
    for form in soup.find_all("form"):
        result["forms"].append({
            "action": urljoin(base_url, form.get("action", "")),
            "method": form.get("method", "GET").upper(),
        })

    # -- HTML comments can contain developer notes, version info, TODOs --
    for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.new_string(""))) is False and hasattr(text, 'strip')):
        pass  # BeautifulSoup Comment detection below
    from bs4 import Comment
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        stripped = comment.strip()
        if stripped and len(stripped) > 3:
            result["comments"].append(stripped[:200])

    # Deduplicate technologies.
    seen = set()
    unique_techs = []
    for tech in result["detected_technologies"]:
        key = tech["technology"]
        if key not in seen:
            seen.add(key)
            unique_techs.append(tech)
    result["detected_technologies"] = unique_techs

    return result


# ---------------------------------------------------------------------------
# Wayback Machine CDX API
# ---------------------------------------------------------------------------

def query_wayback(url: str, limit: int = 20) -> dict[str, Any]:
    """
    Query the Wayback Machine CDX API for historical snapshots.

    OSINT methodology: The Internet Archive captures web pages over time.
    Historical snapshots reveal removed content, old endpoints, technology
    migrations, and configuration changes. The CDX API returns index records
    without downloading full page content, making it efficient for recon.

    CDX API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
    """
    result: dict[str, Any] = {
        "total_snapshots": 0,
        "date_range": {"earliest": None, "latest": None},
        "snapshots": [],
        "status_code_distribution": {},
        "error": None,
    }

    cdx_url = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": url,
        "output": "json",
        "limit": limit,
        "fl": "timestamp,original,statuscode,mimetype,digest",
        "collapse": "digest",  # Deduplicate identical page captures.
    }

    try:
        resp = requests.get(cdx_url, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Wayback Machine CDX API timed out"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"CDX API request failed: {exc}"
        return result
    except (ValueError, json.JSONDecodeError):
        result["error"] = "Failed to parse CDX API response"
        return result

    if len(data) < 2:
        # First row is the header; no data rows means no snapshots.
        return result

    headers = data[0]
    rows = data[1:]
    result["total_snapshots"] = len(rows)

    for row in rows:
        record = dict(zip(headers, row))
        ts = record.get("timestamp", "")
        # Wayback timestamps are in YYYYMMDDHHmmss format.
        try:
            dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
            formatted = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            formatted = ts

        status = record.get("statuscode", "unknown")
        result["status_code_distribution"][status] = (
            result["status_code_distribution"].get(status, 0) + 1
        )

        snapshot = {
            "timestamp": formatted,
            "url": record.get("original", ""),
            "status_code": status,
            "mime_type": record.get("mimetype", ""),
            "wayback_url": f"https://web.archive.org/web/{ts}/{record.get('original', '')}",
        }
        result["snapshots"].append(snapshot)

    if result["snapshots"]:
        result["date_range"]["earliest"] = result["snapshots"][-1]["timestamp"]
        result["date_range"]["latest"] = result["snapshots"][0]["timestamp"]

    return result


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def build_report(url: str, header_analysis: dict, html_analysis: dict,
                 wayback_data: dict) -> dict[str, Any]:
    """Compile all findings into a structured OSINT report."""

    # Merge detected technologies from headers and HTML.
    all_techs: list[dict[str, str]] = []
    seen: set[str] = set()
    for tech in header_analysis.get("detected_technologies", []) + html_analysis.get("detected_technologies", []):
        if tech["technology"] not in seen:
            seen.add(tech["technology"])
            all_techs.append(tech)

    report = {
        "report_metadata": {
            "target_url": url,
            "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": "web_osint.py (OSINT Training Program Module 04)",
        },
        "technology_stack": all_techs,
        "security_headers": header_analysis.get("security_headers", {}),
        "interesting_headers": header_analysis.get("interesting_headers", {}),
        "resources": {
            "scripts": html_analysis.get("scripts", []),
            "stylesheets": html_analysis.get("stylesheets", []),
            "internal_links": len(html_analysis.get("links", {}).get("internal", [])),
            "external_links": len(html_analysis.get("links", {}).get("external", [])),
            "external_domains": sorted(set(
                urlparse(u).netloc
                for u in html_analysis.get("links", {}).get("external", [])
                if urlparse(u).netloc
            )),
            "forms": html_analysis.get("forms", []),
        },
        "html_comments": html_analysis.get("comments", []),
        "meta_tags": html_analysis.get("meta_tags", {}),
        "wayback_machine": {
            "total_snapshots": wayback_data.get("total_snapshots", 0),
            "date_range": wayback_data.get("date_range", {}),
            "status_code_distribution": wayback_data.get("status_code_distribution", {}),
            "sample_snapshots": wayback_data.get("snapshots", [])[:10],
            "error": wayback_data.get("error"),
        },
    }

    return report


def print_report(report: dict[str, Any]) -> None:
    """Print a human-readable summary of the OSINT report."""
    meta = report["report_metadata"]
    print(f"\n{'=' * 70}")
    print(f"  Web Application OSINT Report")
    print(f"  Target: {meta['target_url']}")
    print(f"  Time:   {meta['scan_timestamp']}")
    print(f"{'=' * 70}\n")

    # Technology stack.
    techs = report["technology_stack"]
    print(f"[Technology Stack] ({len(techs)} technologies detected)")
    if techs:
        for t in techs:
            print(f"  - {t['technology']:30s}  (via {t['source']})")
    else:
        print("  No technologies detected from passive analysis.")

    # Security headers.
    sec = report["security_headers"]
    present = sec.get("present", [])
    missing = sec.get("missing", [])
    print(f"\n[Security Headers] ({len(present)} present, {len(missing)} missing)")
    if present:
        print("  Present:")
        for h in present:
            print(f"    + {h}")
    if missing:
        print("  Missing:")
        for h in missing:
            print(f"    - {h}")

    # Interesting headers.
    interesting = report.get("interesting_headers", {})
    if interesting:
        print(f"\n[Interesting Headers]")
        for k, v in interesting.items():
            print(f"  {k}: {v}")

    # Resources.
    res = report["resources"]
    print(f"\n[Page Resources]")
    print(f"  Scripts:          {len(res.get('scripts', []))}")
    print(f"  Stylesheets:      {len(res.get('stylesheets', []))}")
    print(f"  Internal links:   {res.get('internal_links', 0)}")
    print(f"  External links:   {res.get('external_links', 0)}")
    if res.get("external_domains"):
        print(f"  External domains: {', '.join(res['external_domains'][:10])}")
    if res.get("forms"):
        print(f"  Forms:            {len(res['forms'])}")
        for f in res["forms"]:
            print(f"    {f['method']} -> {f['action']}")

    # HTML comments.
    comments = report.get("html_comments", [])
    if comments:
        print(f"\n[HTML Comments] ({len(comments)} found)")
        for c in comments[:5]:
            print(f"  <!-- {c[:80]}{'...' if len(c) > 80 else ''} -->")

    # Wayback Machine.
    wb = report["wayback_machine"]
    print(f"\n[Wayback Machine]")
    if wb.get("error"):
        print(f"  Error: {wb['error']}")
    else:
        print(f"  Total snapshots: {wb.get('total_snapshots', 0)}")
        dr = wb.get("date_range", {})
        if dr.get("earliest"):
            print(f"  Earliest:        {dr['earliest']}")
            print(f"  Latest:          {dr['latest']}")
        dist = wb.get("status_code_distribution", {})
        if dist:
            print(f"  Status codes:    {dist}")
        for snap in wb.get("sample_snapshots", [])[:5]:
            print(f"  [{snap['timestamp']}] {snap['status_code']} {snap['wayback_url']}")

    print(f"\n{'=' * 70}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Web Application OSINT -- passive technology fingerprinting, "
                    "Wayback Machine analysis, and resource extraction.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python web_osint.py --url https://example.com\n"
            "  python web_osint.py --url https://example.com --output report.json\n"
        ),
    )
    parser.add_argument(
        "--url", required=True,
        help="Target URL to analyze",
    )
    parser.add_argument(
        "--output", default=None,
        help="Path to write JSON report (default: stdout only)",
    )
    parser.add_argument(
        "--wayback-limit", type=int, default=20,
        help="Maximum Wayback Machine snapshots to retrieve (default: 20)",
    )
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    print(f"[*] Starting web application OSINT for: {url}")

    # Step 1: Fetch the page.
    print("[*] Fetching page and analyzing HTTP headers...")
    response, error = fetch_page(url)
    if error:
        print(f"[!] {error}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Analyze headers.
    header_results = analyze_headers(response)
    tech_count = len(header_results["detected_technologies"])
    print(f"    Found {tech_count} technologies from headers")

    # Step 3: Analyze HTML content.
    print("[*] Analyzing HTML content and extracting resources...")
    html_results = analyze_html(response.text, url)
    tech_count = len(html_results["detected_technologies"])
    print(f"    Found {tech_count} technologies from HTML")
    print(f"    Extracted {len(html_results['scripts'])} scripts, "
          f"{len(html_results['stylesheets'])} stylesheets")

    # Step 4: Query Wayback Machine.
    print("[*] Querying Wayback Machine CDX API...")
    wayback_results = query_wayback(url, limit=args.wayback_limit)
    if wayback_results.get("error"):
        print(f"    Warning: {wayback_results['error']}")
    else:
        print(f"    Found {wayback_results['total_snapshots']} unique snapshots")

    # Step 5: Compile and output report.
    report = build_report(url, header_results, html_results, wayback_results)
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[*] JSON report written to: {args.output}")


if __name__ == "__main__":
    main()
