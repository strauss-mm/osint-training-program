#!/usr/bin/env python3
"""
OSINT Collection Plan Generator

Generates a structured intelligence collection plan template for a target
organization. The plan follows the five-phase OSINT lifecycle:
Planning -> Collection -> Processing -> Analysis -> Dissemination

This tool produces a baseline template that investigators refine with
domain-specific knowledge. It is not a scanner -- it generates the
planning document that guides subsequent collection activities.

Usage:
    python collection_plan_generator.py --domain example.com
    python collection_plan_generator.py --domain example.com --org "Acme Corp" --output plan.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Collection plan data model
# ---------------------------------------------------------------------------
# Each phase of the OSINT lifecycle has defined tasks, data sources, tools,
# and expected outputs. This structure ensures consistent methodology across
# engagements.

def build_collection_plan(domain: str, org_name: str) -> dict:
    """Build a structured collection plan for the target domain.

    The plan covers five categories of intelligence gathering, each with
    recommended passive data sources and tools. Active techniques (port
    scanning, brute-forcing) are listed separately because they require
    explicit authorization and carry detection risk.
    """
    plan = {
        "meta": {
            "generated": datetime.now(timezone.utc).isoformat(),
            "target_domain": domain,
            "target_organization": org_name,
            "plan_version": "1.0",
            "classification": "CONFIDENTIAL",
            "status": "DRAFT",
        },
        "scope": {
            "in_scope": [
                f"All subdomains of {domain}",
                "Publicly accessible web applications",
                "DNS records and certificate transparency logs",
                "WHOIS and registration data",
                "Publicly indexed documents and metadata",
                "Job postings and technology references",
                "Code repositories (public only)",
            ],
            "out_of_scope": [
                "Employee personal accounts and social media",
                "Authenticated access to any system",
                "Active exploitation or vulnerability testing",
                "Physical security assessment",
                "Social engineering of employees",
            ],
            "legal_constraints": [
                "CFAA: No unauthorized computer access",
                "GDPR: Minimize personal data collection; document lawful basis",
                "Respect robots.txt and API rate limits",
                "No credential stuffing or password spraying",
            ],
        },
        "phases": [
            _phase_domain_infrastructure(domain),
            _phase_network_intelligence(domain),
            _phase_web_application(domain),
            _phase_people_organization(domain, org_name),
            _phase_code_documents(domain, org_name),
        ],
        "opsec": {
            "requirements": [
                "Use a dedicated research VPN (commercial, non-attributable)",
                "Dedicated browser profile with no personal logins or extensions",
                "Sock puppet accounts for platforms requiring authentication",
                "Log all queries with timestamps for evidence chain",
                "Strip metadata from any files before sharing externally",
            ],
            "tools": [
                "VPN service (Mullvad, ProtonVPN)",
                "Browser profile isolation (Firefox containers or separate profile)",
                "Tor Browser for highly sensitive lookups",
            ],
        },
        "reporting": {
            "format": "Structured report with executive summary, technical findings, and raw data appendix",
            "audience": ["CISO", "Security Engineering Team", "Legal/Compliance"],
            "classification": "CONFIDENTIAL",
            "retention": "90 days post-engagement, then secure destruction",
        },
    }
    return plan


def _phase_domain_infrastructure(domain: str) -> dict:
    """Phase 1: Domain and infrastructure reconnaissance.

    This phase maps the target's external footprint using DNS, WHOIS, and
    certificate transparency data. It is almost entirely passive -- the only
    direct target interaction is DNS resolution.
    """
    return {
        "name": "Domain & Infrastructure Reconnaissance",
        "priority": "HIGH",
        "objective": f"Map the complete external footprint of {domain}",
        "tasks": [
            {
                "task": "Subdomain enumeration",
                "sources": ["Certificate Transparency logs", "DNS brute-force wordlists", "Search engine dorking"],
                "tools": ["Amass", "Subfinder", "crt.sh"],
                "expected_data": ["Subdomains", "IP addresses", "Hosting providers"],
                "technique": "passive",
            },
            {
                "task": "DNS record analysis",
                "sources": ["Authoritative DNS servers"],
                "tools": ["DNSRecon", "dig", "dnspython"],
                "expected_data": ["A/AAAA", "MX", "NS", "TXT (SPF/DKIM/DMARC)", "SOA", "CNAME"],
                "technique": "semi-passive",
            },
            {
                "task": "WHOIS and registration analysis",
                "sources": ["WHOIS databases", "Historical WHOIS services"],
                "tools": ["whois CLI", "python-whois", "SecurityTrails"],
                "expected_data": ["Registrant info", "Registration dates", "Name servers", "Registrar"],
                "technique": "passive",
            },
            {
                "task": "Certificate Transparency log analysis",
                "sources": ["CT logs via crt.sh"],
                "tools": ["crt.sh API", "certstream"],
                "expected_data": ["Issued certificates", "SANs", "Issuing CAs", "Validity periods"],
                "technique": "passive",
            },
        ],
    }


def _phase_network_intelligence(domain: str) -> dict:
    """Phase 2: Network-level intelligence.

    Passive queries to internet-wide scan databases reveal what the target
    exposes to the internet without sending any traffic to the target.
    """
    return {
        "name": "Network Intelligence",
        "priority": "HIGH",
        "objective": f"Identify internet-facing services and network topology for {domain}",
        "tasks": [
            {
                "task": "IP geolocation and ASN mapping",
                "sources": ["IP intelligence databases"],
                "tools": ["IPinfo", "ipapi", "BGPView"],
                "expected_data": ["Geolocation", "ASN ownership", "ISP/hosting provider", "Network ranges"],
                "technique": "passive",
            },
            {
                "task": "Internet-facing service enumeration",
                "sources": ["Shodan", "Censys"],
                "tools": ["Shodan CLI/API", "Censys Search"],
                "expected_data": ["Open ports", "Service banners", "TLS certificates", "Software versions"],
                "technique": "passive",
            },
            {
                "task": "Noise and scanner classification",
                "sources": ["GreyNoise"],
                "tools": ["GreyNoise API"],
                "expected_data": ["Scanner classification", "Benign vs malicious traffic attribution"],
                "technique": "passive",
            },
        ],
    }


def _phase_web_application(domain: str) -> dict:
    """Phase 3: Web application reconnaissance.

    Technology fingerprinting and historical analysis reveal the application
    stack, removed content, and potential attack surface.
    """
    return {
        "name": "Web Application OSINT",
        "priority": "MEDIUM",
        "objective": f"Map web application technology stack and discover hidden content for {domain}",
        "tasks": [
            {
                "task": "Technology fingerprinting",
                "sources": ["HTTP response headers", "HTML source", "JavaScript references"],
                "tools": ["Wappalyzer", "BuiltWith", "httpx"],
                "expected_data": ["Web server", "Frameworks", "CMS", "CDN", "Analytics"],
                "technique": "semi-passive",
            },
            {
                "task": "Historical content analysis",
                "sources": ["Wayback Machine", "Google Cache"],
                "tools": ["Wayback CDX API", "WaybackURLs", "GAU"],
                "expected_data": ["Archived pages", "Removed endpoints", "Old configurations"],
                "technique": "passive",
            },
            {
                "task": "URL and endpoint discovery",
                "sources": ["Wayback Machine", "Common Crawl", "AlienVault OTX"],
                "tools": ["GAU", "Photon", "JSParser"],
                "expected_data": ["API endpoints", "Internal paths", "JavaScript-embedded URLs"],
                "technique": "passive",
            },
        ],
    }


def _phase_people_organization(domain: str, org_name: str) -> dict:
    """Phase 4: People and organizational intelligence.

    Public information about employees and organizational structure provides
    context for social engineering risk assessment and attack surface mapping.
    """
    return {
        "name": "People & Organization Intelligence",
        "priority": "MEDIUM",
        "objective": f"Map organizational structure and key personnel for {org_name}",
        "tasks": [
            {
                "task": "Email address harvesting",
                "sources": ["Search engines", "Public data breaches (HIBP)", "Company website"],
                "tools": ["theHarvester", "Hunter.io", "Phonebook.cz"],
                "expected_data": ["Email addresses", "Naming conventions", "Role identification"],
                "technique": "passive",
            },
            {
                "task": "Organizational mapping",
                "sources": ["LinkedIn (public profiles)", "Company website", "Press releases"],
                "tools": ["Manual review", "SpiderFoot"],
                "expected_data": ["Key personnel", "Org structure", "Technology team composition"],
                "technique": "passive",
            },
            {
                "task": "Job posting analysis",
                "sources": ["Job boards", "Company careers page"],
                "tools": ["Manual review"],
                "expected_data": ["Technology stack hints", "Security tool usage", "Cloud providers"],
                "technique": "passive",
            },
        ],
    }


def _phase_code_documents(domain: str, org_name: str) -> dict:
    """Phase 5: Code and document intelligence.

    Public code repositories and indexed documents can leak credentials,
    internal configurations, and architectural details.
    """
    return {
        "name": "Code & Document Intelligence",
        "priority": "LOW",
        "objective": f"Discover public code repositories and documents belonging to {org_name}",
        "tasks": [
            {
                "task": "Public repository search",
                "sources": ["GitHub", "GitLab", "Bitbucket"],
                "tools": ["GitHub search", "Gitrob", "truffleHog"],
                "expected_data": ["Source code", "Configuration files", "Hardcoded credentials", "API keys"],
                "technique": "passive",
            },
            {
                "task": "Document metadata analysis",
                "sources": ["Search engine dorking (filetype:pdf, filetype:xlsx)"],
                "tools": ["Google dorks", "ExifTool", "FOCA"],
                "expected_data": ["Author names", "Software versions", "Internal paths", "Printer names"],
                "technique": "passive",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def plan_to_markdown(plan: dict) -> str:
    """Convert the collection plan to a readable Markdown summary."""
    lines = []
    meta = plan["meta"]
    lines.append(f"# OSINT Collection Plan: {meta['target_organization']}")
    lines.append("")
    lines.append(f"**Target Domain:** {meta['target_domain']}")
    lines.append(f"**Generated:** {meta['generated']}")
    lines.append(f"**Classification:** {meta['classification']}")
    lines.append(f"**Status:** {meta['status']}")
    lines.append("")

    # Scope
    lines.append("## Scope")
    lines.append("")
    lines.append("### In Scope")
    for item in plan["scope"]["in_scope"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Out of Scope")
    for item in plan["scope"]["out_of_scope"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Legal Constraints")
    for item in plan["scope"]["legal_constraints"]:
        lines.append(f"- {item}")
    lines.append("")

    # Phases
    lines.append("## Collection Phases")
    lines.append("")
    for phase in plan["phases"]:
        lines.append(f"### {phase['name']} (Priority: {phase['priority']})")
        lines.append("")
        lines.append(f"**Objective:** {phase['objective']}")
        lines.append("")
        lines.append("| Task | Sources | Tools | Technique |")
        lines.append("|------|---------|-------|-----------|")
        for task in phase["tasks"]:
            sources = ", ".join(task["sources"])
            tools = ", ".join(task["tools"])
            lines.append(f"| {task['task']} | {sources} | {tools} | {task['technique']} |")
        lines.append("")

    # OPSEC
    lines.append("## OPSEC Requirements")
    lines.append("")
    for req in plan["opsec"]["requirements"]:
        lines.append(f"- {req}")
    lines.append("")

    # Reporting
    lines.append("## Reporting")
    lines.append("")
    rpt = plan["reporting"]
    lines.append(f"- **Format:** {rpt['format']}")
    lines.append(f"- **Audience:** {', '.join(rpt['audience'])}")
    lines.append(f"- **Classification:** {rpt['classification']}")
    lines.append(f"- **Retention:** {rpt['retention']}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate a structured OSINT collection plan template for a target organization.",
        epilog="Example: python collection_plan_generator.py --domain example.com --org 'Acme Corp'",
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="Target domain (e.g., example.com)",
    )
    parser.add_argument(
        "--org",
        default=None,
        help="Target organization name (defaults to the domain)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path for the JSON plan (also writes a .md summary alongside it)",
    )
    args = parser.parse_args()

    org_name = args.org if args.org else args.domain
    plan = build_collection_plan(args.domain, org_name)

    # JSON output
    plan_json = json.dumps(plan, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(plan_json)
        print(f"[+] JSON plan written to {args.output}")

        # Write Markdown summary alongside the JSON
        md_path = args.output.rsplit(".", 1)[0] + ".md"
        with open(md_path, "w") as f:
            f.write(plan_to_markdown(plan))
        print(f"[+] Markdown summary written to {md_path}")
    else:
        # Print Markdown summary to stdout for quick review
        print(plan_to_markdown(plan))
        print("\n---")
        print("Tip: Use --output plan.json to save the structured plan to disk.")


if __name__ == "__main__":
    main()
