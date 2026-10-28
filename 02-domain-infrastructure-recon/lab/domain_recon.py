#!/usr/bin/env python3
"""Domain & Infrastructure Reconnaissance Tool

Performs multi-source passive reconnaissance against a target domain:
  1. Certificate Transparency log queries via crt.sh
  2. WHOIS registration data lookup
  3. DNS record enumeration (A, AAAA, MX, NS, TXT, SOA)

All queries use publicly available data sources. The CT and WHOIS lookups
are fully passive (no traffic reaches the target). DNS resolution is
semi-passive — queries go to your configured resolver, not the target's
infrastructure directly, but the authoritative NS will see the query.

Usage:
    python domain_recon.py --domain example.com
    python domain_recon.py --domain example.com --output report.json
"""

import argparse
import json
import socket
import sys
from datetime import datetime, timezone

import dns.resolver
import requests
import whois


def query_crt_sh(domain: str) -> dict:
    """Query Certificate Transparency logs via crt.sh.

    CT logs are append-only public records of every TLS certificate issued
    by participating Certificate Authorities. This reveals subdomains the
    organization may not publicize, including internal service names, staging
    environments, and deprecated infrastructure.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    results = {
        "source": "crt.sh",
        "query": domain,
        "certificates": [],
        "unique_subdomains": [],
        "error": None,
    }

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        certs = response.json()

        # Extract unique common names and SAN entries
        seen_names = set()
        for cert in certs:
            name_value = cert.get("name_value", "")
            # crt.sh returns newline-separated names for SAN entries
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name != domain:
                    seen_names.add(name)

            results["certificates"].append({
                "id": cert.get("id"),
                "common_name": cert.get("common_name", ""),
                "name_value": cert.get("name_value", ""),
                "issuer": cert.get("issuer_name", ""),
                "not_before": cert.get("not_before", ""),
                "not_after": cert.get("not_after", ""),
            })

        results["unique_subdomains"] = sorted(seen_names)
        results["total_certificates"] = len(certs)
        results["unique_subdomain_count"] = len(seen_names)

    except requests.exceptions.Timeout:
        results["error"] = "Request timed out — crt.sh can be slow for large domains"
    except requests.exceptions.HTTPError as e:
        results["error"] = f"HTTP error: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        results["error"] = f"Request failed: {str(e)}"
    except (ValueError, KeyError) as e:
        results["error"] = f"Failed to parse response: {str(e)}"

    return results


def query_whois(domain: str) -> dict:
    """Perform WHOIS lookup for domain registration data.

    WHOIS records reveal the registrant organization, registration and
    expiration dates, name servers, and registrar. This data helps establish:
    - Domain age and legitimacy
    - Organizational ownership
    - Infrastructure providers (via name servers)
    - Expiration-based risks (domain hijacking on lapsed registrations)

    Note: Many domains use privacy protection services that mask registrant
    details. The structural metadata (dates, NS, registrar) remains visible.
    """
    results = {
        "source": "whois",
        "query": domain,
        "data": {},
        "error": None,
    }

    try:
        w = whois.whois(domain)

        # Serialize WHOIS data — handle datetime objects and lists
        whois_data = {}
        for key, value in w.items():
            if value is None:
                whois_data[key] = None
            elif isinstance(value, datetime):
                whois_data[key] = value.isoformat()
            elif isinstance(value, list):
                whois_data[key] = [
                    v.isoformat() if isinstance(v, datetime) else str(v)
                    for v in value
                ]
            else:
                whois_data[key] = str(value)

        results["data"] = whois_data

        # Extract key fields for summary
        results["summary"] = {
            "registrar": w.get("registrar"),
            "creation_date": _format_date(w.get("creation_date")),
            "expiration_date": _format_date(w.get("expiration_date")),
            "name_servers": w.get("name_servers", []),
            "registrant": w.get("org") or w.get("registrant_name") or "Privacy Protected",
        }

    except Exception as e:
        results["error"] = f"WHOIS lookup failed: {str(e)}"

    return results


def _format_date(date_val) -> str | None:
    """Format a WHOIS date value (may be datetime, list, or None)."""
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0]
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    return str(date_val)


def enumerate_dns(domain: str) -> dict:
    """Enumerate DNS records for intelligence extraction.

    Each record type reveals different aspects of the target's infrastructure:
    - A/AAAA: IP addresses and hosting providers
    - MX: Email infrastructure (Google Workspace, M365, self-hosted)
    - NS: DNS hosting and potential zone transfer targets
    - TXT: SPF/DKIM/DMARC policies, cloud service verifications
    - SOA: Zone authority, admin contacts, update frequency
    """
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
    results = {
        "source": "dns",
        "query": domain,
        "records": {},
        "errors": {},
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []

            for rdata in answers:
                record = {"type": rtype, "value": str(rdata)}

                # Add context-specific fields
                if rtype == "MX":
                    record["preference"] = rdata.preference
                    record["exchange"] = str(rdata.exchange)
                elif rtype == "SOA":
                    record["mname"] = str(rdata.mname)
                    record["rname"] = str(rdata.rname)
                    record["serial"] = rdata.serial
                    record["refresh"] = rdata.refresh
                    record["retry"] = rdata.retry
                    record["expire"] = rdata.expire
                    record["minimum"] = rdata.minimum
                elif rtype in ("A", "AAAA"):
                    # Attempt reverse DNS for IP context
                    try:
                        hostname = socket.gethostbyaddr(str(rdata))[0]
                        record["reverse_dns"] = hostname
                    except (socket.herror, socket.gaierror):
                        record["reverse_dns"] = None

                records.append(record)

            results["records"][rtype] = records

        except dns.resolver.NoAnswer:
            results["records"][rtype] = []
        except dns.resolver.NXDOMAIN:
            results["errors"][rtype] = "Domain does not exist (NXDOMAIN)"
        except dns.resolver.Timeout:
            results["errors"][rtype] = "DNS query timed out"
        except dns.exception.DNSException as e:
            results["errors"][rtype] = f"DNS error: {str(e)}"

    return results


def generate_report(domain: str) -> dict:
    """Run all reconnaissance modules and compile a structured report."""
    print(f"[*] Starting domain reconnaissance: {domain}")

    print("[*] Querying Certificate Transparency logs (crt.sh)...")
    ct_results = query_crt_sh(domain)
    if ct_results.get("error"):
        print(f"    [!] CT query error: {ct_results['error']}")
    else:
        print(f"    [+] Found {ct_results.get('total_certificates', 0)} certificates, "
              f"{ct_results.get('unique_subdomain_count', 0)} unique subdomains")

    print("[*] Performing WHOIS lookup...")
    whois_results = query_whois(domain)
    if whois_results.get("error"):
        print(f"    [!] WHOIS error: {whois_results['error']}")
    else:
        summary = whois_results.get("summary", {})
        print(f"    [+] Registrar: {summary.get('registrar', 'Unknown')}")
        print(f"    [+] Registrant: {summary.get('registrant', 'Unknown')}")

    print("[*] Enumerating DNS records...")
    dns_results = enumerate_dns(domain)
    total_records = sum(len(v) for v in dns_results["records"].values())
    print(f"    [+] Found {total_records} DNS records across "
          f"{len([k for k, v in dns_results['records'].items() if v])} record types")

    report = {
        "meta": {
            "tool": "domain_recon.py",
            "target": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
        },
        "certificate_transparency": ct_results,
        "whois": whois_results,
        "dns_records": dns_results,
    }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Domain & Infrastructure Reconnaissance Tool — "
                    "Queries CT logs, WHOIS, and DNS records for OSINT collection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python domain_recon.py --domain example.com\n"
               "  python domain_recon.py --domain example.com --output report.json\n",
    )
    parser.add_argument(
        "--domain", "-d",
        required=True,
        help="Target domain to investigate",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path for JSON report (default: stdout only)",
    )

    args = parser.parse_args()

    # Basic domain validation
    domain = args.domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = domain.split("//", 1)[1].split("/")[0]

    report = generate_report(domain)

    # Pretty-print to stdout
    print("\n" + "=" * 60)
    print("RECONNAISSANCE REPORT")
    print("=" * 60)
    print(json.dumps(report, indent=2, default=str))

    # Optionally save to file
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[*] Report saved to {args.output}")

    print("[*] Reconnaissance complete.")


if __name__ == "__main__":
    main()
