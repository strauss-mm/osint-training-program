#!/usr/bin/env python3
"""
Network Intelligence Report Generator

Builds a passive network intelligence report for a target IP address or CIDR
range by querying public data sources: IPinfo (geolocation/ASN), Shodan
(ports/services), and reverse DNS. No packets are sent to the target.

Usage:
    python network_intel.py --target 1.1.1.1
    python network_intel.py --target 8.8.8.0/30 --output report.md
"""

import argparse
import ipaddress
import json
import os
import socket
import sys
from datetime import datetime, timezone

import dns.resolver
import dns.reversename
import requests

# ---------------------------------------------------------------------------
# Data collection functions -- each queries one passive intelligence source
# ---------------------------------------------------------------------------


def query_ipinfo(ip: str) -> dict:
    """
    Query IPinfo.io for geolocation, ASN, and organization data.

    IPinfo provides: city, region, country, coordinates, organization name,
    ASN, hostname, and whether the IP belongs to a hosting/datacenter range.
    Free tier: 50,000 requests/month (no API key required for basic lookups).
    """
    url = f"https://ipinfo.io/{ip}/json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        return {"error": f"IPinfo query failed: {e}"}


def query_shodan(ip: str) -> dict:
    """
    Query Shodan for open ports, service banners, and vulnerabilities.

    Shodan continuously scans the internet and indexes what it finds: open
    ports, protocol banners, TLS certificates, HTTP headers, and known CVEs.
    Querying Shodan is purely passive -- the scanning was already done.

    Requires SHODAN_API_KEY environment variable. If not set, this step is
    skipped gracefully with a clear message.
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {
            "skipped": True,
            "reason": "SHODAN_API_KEY not set. Export it to enable Shodan lookups: "
                       "export SHODAN_API_KEY='your-key-here'",
        }

    try:
        import shodan
        api = shodan.Shodan(api_key)
        host = api.host(ip)
        return {
            "ip": host.get("ip_str"),
            "hostnames": host.get("hostnames", []),
            "ports": host.get("ports", []),
            "os": host.get("os"),
            "vulns": host.get("vulns", []),
            "last_update": host.get("last_update"),
            "services": [
                {
                    "port": svc.get("port"),
                    "transport": svc.get("transport"),
                    "product": svc.get("product", "unknown"),
                    "version": svc.get("version", ""),
                    "banner_snippet": (svc.get("data", "")[:200]),
                }
                for svc in host.get("data", [])
            ],
        }
    except ImportError:
        return {"error": "shodan package not installed. Run: pip install shodan"}
    except Exception as e:
        return {"error": f"Shodan query failed: {e}"}


def reverse_dns_lookup(ip: str) -> dict:
    """
    Perform reverse DNS lookup to discover hostnames associated with an IP.

    Reverse DNS maps an IP to its PTR record. This reveals the hostname the
    IP operator has configured, which can indicate the service role (e.g.,
    mail, cdn, load balancer) or organizational naming conventions.
    """
    result = {"ip": ip, "ptr_records": [], "additional_names": []}

    # Method 1: socket.gethostbyaddr -- quick PTR lookup
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        result["ptr_records"].append(hostname)
        result["additional_names"].extend(aliases)
    except (socket.herror, socket.gaierror):
        pass

    # Method 2: dnspython -- explicit PTR query for more control
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            name = str(rdata).rstrip(".")
            if name not in result["ptr_records"]:
                result["ptr_records"].append(name)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass

    return result


# ---------------------------------------------------------------------------
# Report generation -- assemble collected data into Markdown
# ---------------------------------------------------------------------------


def generate_report(ip: str, ipinfo_data: dict, shodan_data: dict,
                    dns_data: dict) -> str:
    """Produce a Markdown-formatted network intelligence report."""
    lines = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append(f"# Network Intelligence Report: {ip}")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**Classification:** OSINT -- Passive Collection Only")
    lines.append("")

    # --- IPinfo section ---
    lines.append("## IP Intelligence (IPinfo)")
    lines.append("")
    if "error" in ipinfo_data:
        lines.append(f"> {ipinfo_data['error']}")
    else:
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        field_map = [
            ("IP", "ip"), ("Hostname", "hostname"), ("City", "city"),
            ("Region", "region"), ("Country", "country"),
            ("Location", "loc"), ("Organization", "org"),
            ("ASN", "asn"), ("Postal", "postal"), ("Timezone", "timezone"),
        ]
        for label, key in field_map:
            val = ipinfo_data.get(key, "N/A")
            if val:
                lines.append(f"| {label} | {val} |")
    lines.append("")

    # --- Reverse DNS section ---
    lines.append("## Reverse DNS")
    lines.append("")
    if dns_data["ptr_records"]:
        for ptr in dns_data["ptr_records"]:
            lines.append(f"- `{ptr}`")
    else:
        lines.append("No PTR records found.")
    if dns_data["additional_names"]:
        lines.append("")
        lines.append("**Additional aliases:**")
        for alias in dns_data["additional_names"]:
            lines.append(f"- `{alias}`")
    lines.append("")

    # --- Shodan section ---
    lines.append("## Shodan Intelligence")
    lines.append("")
    if shodan_data.get("skipped"):
        lines.append(f"> Skipped: {shodan_data['reason']}")
    elif "error" in shodan_data:
        lines.append(f"> {shodan_data['error']}")
    else:
        lines.append(f"**Open Ports:** {', '.join(str(p) for p in shodan_data.get('ports', []))}")
        lines.append(f"**OS:** {shodan_data.get('os', 'Unknown')}")
        lines.append(f"**Last Updated:** {shodan_data.get('last_update', 'Unknown')}")
        lines.append("")

        hostnames = shodan_data.get("hostnames", [])
        if hostnames:
            lines.append(f"**Hostnames:** {', '.join(hostnames)}")
            lines.append("")

        vulns = shodan_data.get("vulns", [])
        if vulns:
            lines.append(f"**Known Vulnerabilities ({len(vulns)}):** {', '.join(vulns[:20])}")
            if len(vulns) > 20:
                lines.append(f"  _(and {len(vulns) - 20} more)_")
            lines.append("")

        services = shodan_data.get("services", [])
        if services:
            lines.append("### Services")
            lines.append("")
            lines.append("| Port | Transport | Product | Version |")
            lines.append("|------|-----------|---------|---------|")
            for svc in services:
                lines.append(
                    f"| {svc['port']} | {svc['transport']} "
                    f"| {svc['product']} | {svc['version']} |"
                )
            lines.append("")
    lines.append("")

    # --- Analysis summary ---
    lines.append("## Analysis Notes")
    lines.append("")
    lines.append("_Review the data above and add your assessment:_")
    lines.append("")
    lines.append("- **Attack surface**: [Summarize exposed services and risk level]")
    lines.append("- **Attribution**: [Organization, hosting provider, geographic region]")
    lines.append("- **Next steps**: [What follow-up collection would fill gaps?]")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------


def expand_targets(target: str) -> list[str]:
    """
    Expand a target specification into a list of IP addresses.

    Accepts a single IP or a CIDR range. For safety, limits CIDR expansion
    to /24 (256 hosts) to prevent accidental mass queries.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 256:
            print(
                f"[!] CIDR /{network.prefixlen} contains {network.num_addresses} "
                f"hosts. Limiting to /24 (256) to avoid excessive API calls.",
                file=sys.stderr,
            )
            # Take first 256 hosts
            return [str(ip) for ip in list(network.hosts())[:256]]
        return [str(ip) for ip in network.hosts()] if network.prefixlen < 32 else [str(network.network_address)]
    except ValueError:
        # Assume single IP
        return [target]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Passive network intelligence report generator. "
                    "Queries IPinfo, Shodan, and reverse DNS for a target IP or CIDR.",
        epilog="Example: python network_intel.py --target 1.1.1.1 --output report.md",
    )
    parser.add_argument(
        "--target", required=True,
        help="Target IP address or CIDR range (e.g., 1.1.1.1 or 8.8.8.0/30)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output file path for the Markdown report (default: stdout)",
    )
    args = parser.parse_args()

    targets = expand_targets(args.target)
    print(f"[*] Processing {len(targets)} target(s)...", file=sys.stderr)

    all_reports = []

    for ip in targets:
        print(f"[*] Collecting intelligence for {ip}...", file=sys.stderr)

        # Collect from all passive sources
        ipinfo_data = query_ipinfo(ip)
        shodan_data = query_shodan(ip)
        dns_data = reverse_dns_lookup(ip)

        # Generate report section
        report = generate_report(ip, ipinfo_data, shodan_data, dns_data)
        all_reports.append(report)

    full_report = "\n---\n\n".join(all_reports)

    if args.output:
        with open(args.output, "w") as f:
            f.write(full_report)
        print(f"[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(full_report)


if __name__ == "__main__":
    main()
