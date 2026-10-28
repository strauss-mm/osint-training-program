#!/usr/bin/env python3
"""
OSINT Automation Framework

A mini OSINT collection framework that takes a domain as target and runs
multiple collection modules: DNS resolution, WHOIS lookup, certificate
transparency, HTTP header analysis, Wayback Machine, and robots.txt parsing.
Findings are correlated and output as JSON and/or an HTML dashboard.

Usage:
    python osint_framework.py example.com --quick
    python osint_framework.py example.com --deep --verbose --output-dir ./results
"""

import argparse
import json
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from html import escape

import requests

try:
    import whois as python_whois
except ImportError:
    python_whois = None

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
USER_AGENT = "OSINT-Training-Framework/1.0 (educational)"
REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 1.0  # seconds between external requests

# Subdomains to check in quick vs deep mode
SUBDOMAINS_QUICK = ["www", "mail", "ftp", "api", "dev", "staging", "admin", "vpn"]
SUBDOMAINS_DEEP = SUBDOMAINS_QUICK + [
    "remote", "portal", "cdn", "static", "assets", "blog", "shop", "store",
    "app", "test", "demo", "beta", "internal", "intranet", "wiki", "docs",
    "git", "gitlab", "jenkins", "ci", "monitor", "grafana", "prometheus",
    "elastic", "kibana", "sentry", "status", "health", "auth", "sso",
    "oauth", "login", "signup", "register", "m", "mobile", "webmail",
    "smtp", "imap", "pop", "ns1", "ns2", "mx", "relay",
]

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Technology detection patterns (deep mode only)
TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
    "React": [r"react", r"__NEXT_DATA__", r"_next/static"],
    "Angular": [r"ng-version", r"angular"],
    "Vue.js": [r"vue\.js", r"__vue__", r"vue-router"],
    "jQuery": [r"jquery", r"jQuery"],
    "Bootstrap": [r"bootstrap\.css", r"bootstrap\.min"],
    "Tailwind CSS": [r"tailwindcss", r"tailwind"],
    "Next.js": [r"_next/", r"__NEXT_DATA__"],
    "Django": [r"csrfmiddlewaretoken", r"__admin__"],
    "Ruby on Rails": [r"csrf-token", r"rails"],
    "ASP.NET": [r"__VIEWSTATE", r"aspnet", r"asp\.net"],
    "PHP": [r"\.php", r"PHPSESSID"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
}


def log(msg: str, verbose: bool = True) -> None:
    """Print progress to stderr."""
    if verbose:
        print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Collection Module 1: DNS Resolution
# ---------------------------------------------------------------------------
def collect_dns(domain: str, deep: bool, verbose: bool) -> dict:
    """
    Resolve DNS records for the domain and common subdomains.

    Uses socket.getaddrinfo which queries the system resolver. This finds
    A and AAAA records. For a production tool, you would use dnspython for
    MX, TXT, NS, SOA, and other record types.
    """
    log("[*] Module: DNS Resolution", verbose)
    results = {"domain": domain, "records": [], "subdomains_checked": 0}

    targets = [domain]
    subdomain_list = SUBDOMAINS_DEEP if deep else SUBDOMAINS_QUICK
    targets.extend(f"{sub}.{domain}" for sub in subdomain_list)

    for target in targets:
        results["subdomains_checked"] += 1
        try:
            answers = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set(addr[4][0] for addr in answers))
            if ips:
                results["records"].append({"hostname": target, "ips": ips})
                log(f"  {target} -> {', '.join(ips)}", verbose)
        except socket.gaierror:
            pass  # Subdomain does not resolve -- expected for most

    log(f"  Found {len(results['records'])} resolving hostnames.", verbose)
    return results


# ---------------------------------------------------------------------------
# Collection Module 2: WHOIS Lookup
# ---------------------------------------------------------------------------
def collect_whois(domain: str, verbose: bool) -> dict:
    """
    Query WHOIS data for domain registration information.

    WHOIS provides registrar, creation/expiration dates, name servers, and
    sometimes registrant organization. Many domains use privacy protection
    services that mask this information.
    """
    log("[*] Module: WHOIS Lookup", verbose)

    if python_whois is None:
        log("  [!] python-whois not installed -- skipping.", verbose)
        return {"error": "python-whois not installed"}

    try:
        w = python_whois.whois(domain)
        result = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "registrant_org": getattr(w, "org", None),
            "registrant_country": getattr(w, "country", None),
            "dnssec": getattr(w, "dnssec", None),
            "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
        }
        log(f"  Registrar: {result['registrar']}", verbose)
        log(f"  Created: {result['creation_date']}", verbose)
        log(f"  Expires: {result['expiration_date']}", verbose)
        return result
    except Exception as e:
        log(f"  [!] WHOIS query failed: {e}", verbose)
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Collection Module 3: Certificate Transparency
# ---------------------------------------------------------------------------
def collect_certificates(domain: str, verbose: bool) -> dict:
    """
    Query crt.sh for certificates issued for this domain.

    Certificate Transparency (CT) logs are public, append-only ledgers of
    TLS certificates. Querying them reveals subdomains that have had
    certificates issued -- even internal ones that may not be in public DNS.
    """
    log("[*] Module: Certificate Transparency (crt.sh)", verbose)
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=20)
        if resp.status_code != 200:
            log(f"  [!] crt.sh returned HTTP {resp.status_code}", verbose)
            return {"error": f"HTTP {resp.status_code}", "subdomains": []}

        entries = resp.json()
        # Extract unique subdomain names from common_name and name_value fields
        subdomains = set()
        for entry in entries:
            for field in ("common_name", "name_value"):
                names = entry.get(field, "")
                for name in names.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)

        sorted_subs = sorted(subdomains)
        log(f"  Found {len(sorted_subs)} unique subdomains from CT logs.", verbose)

        return {
            "total_certificates": len(entries),
            "unique_subdomains": len(sorted_subs),
            "subdomains": sorted_subs[:100],  # Cap at 100 for report readability
        }
    except requests.exceptions.RequestException as e:
        log(f"  [!] crt.sh query failed: {e}", verbose)
        return {"error": str(e), "subdomains": []}


# ---------------------------------------------------------------------------
# Collection Module 4: HTTP Headers Analysis
# ---------------------------------------------------------------------------
def collect_headers(domain: str, verbose: bool) -> dict:
    """
    Fetch the domain over HTTPS and analyze response headers.

    Security headers indicate the security posture of a web application.
    Missing headers are potential findings for a security assessment.
    """
    log("[*] Module: HTTP Headers Analysis", verbose)
    result = {
        "url": f"https://{domain}",
        "status_code": None,
        "server": None,
        "security_headers": {},
        "missing_headers": [],
        "all_headers": {},
    }

    try:
        resp = requests.get(
            f"https://{domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        result["status_code"] = resp.status_code
        result["url"] = resp.url  # Final URL after redirects
        result["all_headers"] = dict(resp.headers)
        result["server"] = resp.headers.get("Server", "Not disclosed")

        # Check each security header
        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            if value:
                result["security_headers"][header] = value
            else:
                result["missing_headers"].append(header)

        present = len(result["security_headers"])
        total = len(SECURITY_HEADERS)
        log(f"  Server: {result['server']}", verbose)
        log(f"  Security headers: {present}/{total} present", verbose)

    except requests.exceptions.SSLError as e:
        log(f"  [!] SSL error: {e}", verbose)
        result["error"] = f"SSL error: {e}"
    except requests.exceptions.RequestException as e:
        log(f"  [!] HTTP request failed: {e}", verbose)
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Collection Module 5: Wayback Machine
# ---------------------------------------------------------------------------
def collect_wayback(domain: str, verbose: bool) -> dict:
    """
    Query the Internet Archive's CDX API for historical snapshots.

    The Wayback Machine captures web pages over time. Historical snapshots
    can reveal old content, removed pages, and technology changes.
    """
    log("[*] Module: Wayback Machine", verbose)
    url = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": domain,
        "output": "json",
        "limit": 20,
        "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "timestamp:6",  # One snapshot per month
    }

    try:
        resp = requests.get(
            url, params=params, headers={"User-Agent": USER_AGENT}, timeout=15
        )
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}", "snapshots": []}

        data = resp.json()
        if len(data) < 2:  # First row is header
            log("  No snapshots found.", verbose)
            return {"snapshots": [], "total": 0}

        headers_row = data[0]
        snapshots = []
        for row in data[1:]:
            snapshot = dict(zip(headers_row, row))
            snapshot["wayback_url"] = (
                f"https://web.archive.org/web/{snapshot['timestamp']}/{snapshot['original']}"
            )
            snapshots.append(snapshot)

        if snapshots:
            first = snapshots[0].get("timestamp", "N/A")[:6]
            last = snapshots[-1].get("timestamp", "N/A")[:6]
            log(f"  Found {len(snapshots)} snapshots ({first} to {last}).", verbose)
        return {"snapshots": snapshots, "total": len(snapshots)}

    except requests.exceptions.RequestException as e:
        log(f"  [!] Wayback query failed: {e}", verbose)
        return {"error": str(e), "snapshots": []}


# ---------------------------------------------------------------------------
# Collection Module 6: robots.txt and sitemap.xml
# ---------------------------------------------------------------------------
def collect_robots(domain: str, verbose: bool) -> dict:
    """
    Fetch and parse robots.txt and sitemap.xml for interesting paths.

    robots.txt reveals what the site owner wants hidden from crawlers --
    which is often exactly what an investigator wants to find. Sitemaps
    provide a structured list of all public pages.
    """
    log("[*] Module: robots.txt and sitemap.xml", verbose)
    result = {"robots_txt": None, "disallowed_paths": [], "sitemaps": []}

    # Fetch robots.txt
    try:
        resp = requests.get(
            f"https://{domain}/robots.txt",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            result["robots_txt"] = resp.text[:5000]  # Cap size
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        result["disallowed_paths"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    # Rejoin if the split broke the URL
                    if not sitemap_url.startswith("http"):
                        sitemap_url = ":" + sitemap_url
                        sitemap_url = line.split(" ", 1)[1].strip() if " " in line else sitemap_url
                    result["sitemaps"].append(sitemap_url)
            log(f"  Disallowed paths: {len(result['disallowed_paths'])}", verbose)
            log(f"  Sitemaps found: {len(result['sitemaps'])}", verbose)
        else:
            log(f"  robots.txt: HTTP {resp.status_code}", verbose)
    except requests.exceptions.RequestException as e:
        log(f"  [!] robots.txt fetch failed: {e}", verbose)

    return result


# ---------------------------------------------------------------------------
# Collection Module 7: Technology Detection (Deep only)
# ---------------------------------------------------------------------------
def collect_technology(domain: str, verbose: bool) -> dict:
    """
    Detect web technologies by analyzing the HTML response body.

    This is a basic approach using regex pattern matching. Production tools
    like Wappalyzer use more sophisticated fingerprinting.
    """
    log("[*] Module: Technology Detection", verbose)
    result = {"detected": [], "error": None}

    try:
        resp = requests.get(
            f"https://{domain}",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        body = resp.text.lower()
        headers_str = str(resp.headers).lower()
        combined = body + " " + headers_str

        for tech, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern.lower(), combined):
                    result["detected"].append(tech)
                    break

        log(f"  Detected: {', '.join(result['detected']) or 'none'}", verbose)
    except requests.exceptions.RequestException as e:
        log(f"  [!] Request failed: {e}", verbose)
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# Collection Module 8: Social Media Presence (Deep only)
# ---------------------------------------------------------------------------
def collect_social(domain: str, verbose: bool) -> dict:
    """
    Check for social media profiles associated with the domain.

    Checks common platform profile pages that use the domain name as a handle.
    This is a heuristic -- the found profiles may not belong to the domain owner.
    """
    log("[*] Module: Social Media Presence", verbose)

    # Extract the base name (without TLD) for username guessing
    base_name = domain.split(".")[0]

    platforms = [
        ("Twitter/X", f"https://x.com/{base_name}"),
        ("GitHub", f"https://github.com/{base_name}"),
        ("LinkedIn", f"https://www.linkedin.com/company/{base_name}"),
        ("Facebook", f"https://www.facebook.com/{base_name}"),
    ]

    found = []
    for name, url in platforms:
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            if resp.status_code == 200:
                found.append({"platform": name, "url": url, "status": "found"})
                log(f"  {name}: found", verbose)
            else:
                log(f"  {name}: {resp.status_code}", verbose)
        except requests.exceptions.RequestException:
            log(f"  {name}: error", verbose)
        time.sleep(RATE_LIMIT_DELAY)

    return {"base_name": base_name, "profiles": found}


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------
def correlate_findings(findings: dict) -> dict:
    """
    Cross-reference findings from all modules to produce correlated insights.

    Correlation adds value that no single module provides alone:
    - Merge subdomains from DNS + CT logs
    - Identify unique IPs
    - Calculate a security posture score
    - Build a timeline from WHOIS + Wayback
    """
    correlation = {
        "unique_ips": [],
        "all_subdomains": [],
        "security_score": 0,
        "security_grade": "",
        "timeline": [],
    }

    # Unique IPs from DNS
    ips = set()
    for record in findings.get("dns", {}).get("records", []):
        for ip in record.get("ips", []):
            ips.add(ip)
    correlation["unique_ips"] = sorted(ips)

    # Merge subdomains: DNS + CT logs
    subs = set()
    for record in findings.get("dns", {}).get("records", []):
        subs.add(record["hostname"])
    for sub in findings.get("certificates", {}).get("subdomains", []):
        subs.add(sub)
    correlation["all_subdomains"] = sorted(subs)

    # Security headers score (0-100)
    headers_data = findings.get("headers", {})
    present = len(headers_data.get("security_headers", {}))
    total = len(SECURITY_HEADERS)
    if total > 0:
        score = int((present / total) * 100)
    else:
        score = 0
    correlation["security_score"] = score

    if score >= 85:
        correlation["security_grade"] = "A"
    elif score >= 70:
        correlation["security_grade"] = "B"
    elif score >= 50:
        correlation["security_grade"] = "C"
    elif score >= 30:
        correlation["security_grade"] = "D"
    else:
        correlation["security_grade"] = "F"

    # Timeline
    whois_data = findings.get("whois", {})
    if whois_data.get("creation_date"):
        correlation["timeline"].append(
            {"event": "Domain registered", "date": whois_data["creation_date"]}
        )
    if whois_data.get("expiration_date"):
        correlation["timeline"].append(
            {"event": "Domain expires", "date": whois_data["expiration_date"]}
        )

    wayback = findings.get("wayback", {})
    snapshots = wayback.get("snapshots", [])
    if snapshots:
        first_ts = snapshots[0].get("timestamp", "")[:8]
        correlation["timeline"].append(
            {"event": "First Wayback snapshot", "date": first_ts}
        )
        last_ts = snapshots[-1].get("timestamp", "")[:8]
        correlation["timeline"].append(
            {"event": "Latest Wayback snapshot", "date": last_ts}
        )

    return correlation


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------
def generate_json_report(
    domain: str, mode: str, duration: float, findings: dict, correlation: dict
) -> dict:
    """Build the structured JSON report."""
    return {
        "metadata": {
            "target": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "duration_seconds": round(duration, 2),
            "framework": "OSINT Training Framework v1.0",
        },
        "findings": findings,
        "correlation": correlation,
    }


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------
def generate_html_dashboard(report: dict) -> str:
    """
    Generate a self-contained HTML dashboard with inline CSS.

    No external dependencies -- uses only inline styles for portability.
    The dashboard is professional and readable with a dark theme.
    """
    meta = report["metadata"]
    findings = report["findings"]
    corr = report["correlation"]

    def h(text):
        return escape(str(text)) if text else "N/A"

    # Security header color coding
    def header_color(present: bool) -> str:
        return "#2ecc71" if present else "#e74c3c"

    # Build HTML sections
    dns_rows = ""
    for rec in findings.get("dns", {}).get("records", []):
        dns_rows += f"<tr><td>{h(rec['hostname'])}</td><td>{h(', '.join(rec.get('ips', [])))}</td></tr>\n"

    whois_data = findings.get("whois", {})
    whois_rows = ""
    for key in ["registrar", "creation_date", "expiration_date", "registrant_org", "registrant_country", "dnssec"]:
        val = whois_data.get(key)
        if val:
            label = key.replace("_", " ").title()
            whois_rows += f"<tr><td>{h(label)}</td><td>{h(val)}</td></tr>\n"
    ns_list = whois_data.get("name_servers", [])
    if ns_list:
        whois_rows += f"<tr><td>Name Servers</td><td>{h(', '.join(ns_list))}</td></tr>\n"

    cert_subs = findings.get("certificates", {}).get("subdomains", [])
    cert_count = findings.get("certificates", {}).get("total_certificates", 0)

    headers_data = findings.get("headers", {})
    sec_headers = headers_data.get("security_headers", {})
    missing_headers = headers_data.get("missing_headers", [])
    header_rows = ""
    for hdr in SECURITY_HEADERS:
        present = hdr in sec_headers
        color = header_color(present)
        status = "Present" if present else "Missing"
        value = h(sec_headers.get(hdr, "-"))
        header_rows += (
            f'<tr><td>{h(hdr)}</td><td style="color:{color};font-weight:bold">'
            f'{status}</td><td style="font-size:0.85em">{value}</td></tr>\n'
        )

    wayback_rows = ""
    for snap in findings.get("wayback", {}).get("snapshots", [])[:15]:
        ts = snap.get("timestamp", "")
        wb_url = snap.get("wayback_url", "#")
        status = snap.get("statuscode", "")
        wayback_rows += f'<tr><td>{h(ts)}</td><td>{h(status)}</td><td><a href="{h(wb_url)}" target="_blank">View</a></td></tr>\n'

    robots = findings.get("robots", {})
    disallowed = robots.get("disallowed_paths", [])

    tech_list = findings.get("technology", {}).get("detected", [])
    social_profiles = findings.get("social", {}).get("profiles", [])

    grade = corr.get("security_grade", "?")
    score = corr.get("security_score", 0)
    grade_color = {
        "A": "#2ecc71", "B": "#27ae60", "C": "#f39c12",
        "D": "#e67e22", "F": "#e74c3c",
    }.get(grade, "#95a5a6")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report: {h(meta['target'])}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         background: #1a1a2e; color: #e0e0e0; padding: 20px; line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: #e0e0e0; border-bottom: 2px solid #3a3a5e; padding-bottom: 10px; margin-bottom: 20px; }}
  h2 {{ color: #8be9fd; margin: 30px 0 15px; font-size: 1.2em; }}
  .meta {{ background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 20px;
           display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }}
  .meta-item {{ }}
  .meta-label {{ color: #888; font-size: 0.85em; text-transform: uppercase; }}
  .meta-value {{ font-size: 1.1em; font-weight: bold; }}
  .grade-badge {{ display: inline-block; width: 60px; height: 60px; border-radius: 50%;
                  text-align: center; line-height: 60px; font-size: 1.8em; font-weight: bold;
                  background: {grade_color}22; border: 3px solid {grade_color}; color: {grade_color}; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2a4e; }}
  th {{ background: #16213e; color: #8be9fd; font-weight: 600; }}
  tr:hover {{ background: #16213e44; }}
  a {{ color: #8be9fd; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .tag {{ display: inline-block; background: #3a3a5e; padding: 3px 10px; border-radius: 4px;
          margin: 2px; font-size: 0.85em; }}
  .section {{ background: #16213e; padding: 20px; border-radius: 8px; margin-bottom: 15px; }}
  .collapsible {{ cursor: pointer; }}
  .collapsible:after {{ content: ' [+]'; color: #888; }}
  details summary {{ cursor: pointer; color: #8be9fd; font-weight: 600; padding: 10px 0; }}
  code {{ background: #2a2a4e; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }}
  .footer {{ text-align: center; color: #555; margin-top: 40px; padding-top: 20px;
             border-top: 1px solid #2a2a4e; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
<h1>OSINT Reconnaissance Report</h1>

<div class="meta">
  <div class="meta-item">
    <div class="meta-label">Target</div>
    <div class="meta-value">{h(meta['target'])}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Mode</div>
    <div class="meta-value">{h(meta['mode']).upper()}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Duration</div>
    <div class="meta-value">{meta.get('duration_seconds', 0)}s</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Timestamp</div>
    <div class="meta-value">{h(meta['timestamp'][:19])}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Unique IPs</div>
    <div class="meta-value">{len(corr.get('unique_ips', []))}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Subdomains</div>
    <div class="meta-value">{len(corr.get('all_subdomains', []))}</div>
  </div>
  <div class="meta-item">
    <div class="meta-label">Security Grade</div>
    <div class="grade-badge">{grade}</div>
  </div>
</div>

<div class="section">
<h2>DNS Resolution</h2>
<table>
<tr><th>Hostname</th><th>IP Address(es)</th></tr>
{dns_rows if dns_rows else '<tr><td colspan="2">No DNS records found.</td></tr>'}
</table>
</div>

<div class="section">
<h2>WHOIS Information</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
{whois_rows if whois_rows else '<tr><td colspan="2">WHOIS data not available.</td></tr>'}
</table>
</div>

<div class="section">
<h2>Certificate Transparency</h2>
<p>Total certificates logged: <strong>{cert_count}</strong> | Unique subdomains: <strong>{len(cert_subs)}</strong></p>
<div style="margin-top:10px">
{''.join(f'<span class="tag">{h(s)}</span>' for s in cert_subs[:50]) if cert_subs else '<p>No CT log entries found.</p>'}
</div>
</div>

<div class="section">
<h2>Security Headers Scorecard</h2>
<p>Score: <strong>{score}/100</strong> (Grade: <strong style="color:{grade_color}">{grade}</strong>)</p>
<p>Server: <code>{h(headers_data.get('server', 'N/A'))}</code></p>
<table>
<tr><th>Header</th><th>Status</th><th>Value</th></tr>
{header_rows}
</table>
</div>

<div class="section">
<h2>Wayback Machine</h2>
<table>
<tr><th>Timestamp</th><th>Status</th><th>Archive</th></tr>
{wayback_rows if wayback_rows else '<tr><td colspan="3">No snapshots found.</td></tr>'}
</table>
</div>

<div class="section">
<h2>robots.txt Analysis</h2>
<p>Disallowed paths: <strong>{len(disallowed)}</strong></p>
{''.join(f'<span class="tag">{h(p)}</span>' for p in disallowed[:30]) if disallowed else '<p>No disallowed paths found.</p>'}
</div>
"""

    if tech_list:
        html += f"""
<div class="section">
<h2>Detected Technologies</h2>
<div>{''.join(f'<span class="tag">{h(t)}</span>' for t in tech_list)}</div>
</div>
"""

    if social_profiles:
        social_rows = "".join(
            f'<tr><td>{h(p["platform"])}</td><td><a href="{h(p["url"])}" target="_blank">{h(p["url"])}</a></td></tr>'
            for p in social_profiles
        )
        html += f"""
<div class="section">
<h2>Social Media Presence</h2>
<table>
<tr><th>Platform</th><th>URL</th></tr>
{social_rows}
</table>
</div>
"""

    # Collapsible raw JSON
    json_str = escape(json.dumps(report, indent=2, default=str))
    html += f"""
<details>
<summary>Raw JSON Data</summary>
<pre style="background:#0d1117;padding:15px;border-radius:8px;overflow-x:auto;font-size:0.8em;margin-top:10px">{json_str}</pre>
</details>

<div class="footer">
  Generated by OSINT Training Framework v1.0 | Module 08
</div>
</div>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="OSINT Automation Framework -- multi-module domain reconnaissance "
        "with correlated reporting.",
        epilog="Use --quick for fast recon (fewer subdomains, core modules only) "
        "or --deep for thorough collection (more subdomains, technology "
        "detection, social media checks).",
    )
    parser.add_argument("domain", help="Target domain to investigate")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--quick", action="store_true", default=True,
        help="Quick reconnaissance (default)",
    )
    mode_group.add_argument(
        "--deep", action="store_true",
        help="Deep reconnaissance (more modules, more subdomains)",
    )

    parser.add_argument(
        "--output-dir", default="./output",
        help="Directory for output files (default: ./output)",
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "html", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print detailed progress to stderr",
    )

    args = parser.parse_args()
    deep = args.deep
    mode = "deep" if deep else "quick"
    verbose = args.verbose

    os.makedirs(args.output_dir, exist_ok=True)

    log(f"[*] OSINT Framework -- Target: {args.domain}", True)
    log(f"[*] Mode: {mode.upper()}", True)
    log("", True)

    start_time = time.time()
    findings = {}

    # Run collection modules
    findings["dns"] = collect_dns(args.domain, deep, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    findings["whois"] = collect_whois(args.domain, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    findings["certificates"] = collect_certificates(args.domain, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    findings["headers"] = collect_headers(args.domain, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    findings["wayback"] = collect_wayback(args.domain, verbose)
    time.sleep(RATE_LIMIT_DELAY)

    findings["robots"] = collect_robots(args.domain, verbose)

    # Deep-only modules
    if deep:
        time.sleep(RATE_LIMIT_DELAY)
        findings["technology"] = collect_technology(args.domain, verbose)
        time.sleep(RATE_LIMIT_DELAY)
        findings["social"] = collect_social(args.domain, verbose)

    duration = time.time() - start_time

    # Correlate
    log("", True)
    log("[*] Correlating findings...", True)
    correlation = correlate_findings(findings)
    log(f"  Unique IPs: {len(correlation['unique_ips'])}", True)
    log(f"  Total subdomains: {len(correlation['all_subdomains'])}", True)
    log(f"  Security grade: {correlation['security_grade']} ({correlation['security_score']}/100)", True)

    # Generate reports
    report = generate_json_report(args.domain, mode, duration, findings, correlation)

    safe_domain = args.domain.replace("/", "_")

    if args.output_format in ("json", "both"):
        json_path = os.path.join(args.output_dir, f"{safe_domain}_report.json")
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log(f"\n[+] JSON report: {json_path}", True)

    if args.output_format in ("html", "both"):
        html = generate_html_dashboard(report)
        html_path = os.path.join(args.output_dir, f"{safe_domain}_dashboard.html")
        with open(html_path, "w") as f:
            f.write(html)
        log(f"[+] HTML dashboard: {html_path}", True)

    log(f"\n[*] Done in {duration:.1f} seconds.", True)


if __name__ == "__main__":
    main()
