#!/usr/bin/env python3
"""
Multi-Source Threat Intelligence Lookup Tool

Accepts an IP address, domain, or file hash (auto-detected), queries AbuseIPDB
and VirusTotal, maps findings to MITRE ATT&CK techniques, and generates a
Markdown threat intelligence brief.

API keys are read from environment variables:
  - ABUSEIPDB_API_KEY
  - VIRUSTOTAL_API_KEY
"""

import argparse
import os
import re
import sys
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Indicator type detection
# ---------------------------------------------------------------------------

# IPv4 regex: four octets 0-255
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Domain: at least one dot, alphanumeric labels, 2-63 char TLD
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def detect_indicator_type(indicator: str) -> str:
    """
    Auto-detect whether the indicator is an IPv4 address, domain, or file hash.
    Hash detection is based on string length and hex character composition:
      - 32 hex chars = MD5
      - 40 hex chars = SHA-1
      - 64 hex chars = SHA-256
    """
    if IPV4_PATTERN.match(indicator):
        return "ip"
    if DOMAIN_PATTERN.match(indicator):
        return "domain"
    # Check for hex hash by length
    if re.match(r"^[a-fA-F0-9]+$", indicator):
        length = len(indicator)
        if length == 32:
            return "hash_md5"
        elif length == 40:
            return "hash_sha1"
        elif length == 64:
            return "hash_sha256"
    return "unknown"


# ---------------------------------------------------------------------------
# ATT&CK Technique Mapping
#
# This is a simplified, keyword-based mapping. Production systems use
# structured threat intelligence feeds (STIX/TAXII) for accurate TTP mapping.
# ---------------------------------------------------------------------------
ATTACK_MAPPINGS = {
    "malware": [
        ("T1204", "User Execution"),
        ("T1059", "Command and Scripting Interpreter"),
    ],
    "trojan": [
        ("T1204", "User Execution"),
        ("T1055", "Process Injection"),
    ],
    "ransomware": [
        ("T1486", "Data Encrypted for Impact"),
        ("T1490", "Inhibit System Recovery"),
    ],
    "phishing": [
        ("T1566", "Phishing"),
        ("T1598", "Phishing for Information"),
    ],
    "c2": [
        ("T1071", "Application Layer Protocol"),
        ("T1573", "Encrypted Channel"),
    ],
    "command and control": [
        ("T1071", "Application Layer Protocol"),
        ("T1573", "Encrypted Channel"),
    ],
    "botnet": [
        ("T1583.005", "Botnet"),
        ("T1071", "Application Layer Protocol"),
    ],
    "scanner": [
        ("T1595", "Active Scanning"),
        ("T1046", "Network Service Discovery"),
    ],
    "brute": [
        ("T1110", "Brute Force"),
    ],
    "exploit": [
        ("T1190", "Exploit Public-Facing Application"),
        ("T1203", "Exploitation for Client Execution"),
    ],
    "miner": [
        ("T1496", "Resource Hijacking"),
    ],
    "ddos": [
        ("T1498", "Network Denial of Service"),
    ],
    "spam": [
        ("T1566.001", "Spearphishing Attachment"),
    ],
}


def map_to_attack(text: str) -> list[tuple[str, str]]:
    """
    Scan text for keywords and return matching ATT&CK technique tuples.
    Deduplicates by technique ID.
    """
    text_lower = text.lower()
    seen = set()
    techniques = []
    for keyword, mappings in ATTACK_MAPPINGS.items():
        if keyword in text_lower:
            for tid, tname in mappings:
                if tid not in seen:
                    seen.add(tid)
                    techniques.append((tid, tname))
    return techniques


# ---------------------------------------------------------------------------
# AbuseIPDB query (IP addresses only)
# Docs: https://docs.abuseipdb.com/#check-endpoint
# ---------------------------------------------------------------------------
def query_abuseipdb(ip: str, api_key: str, verbose: bool = False) -> dict | None:
    """Query AbuseIPDB for IP reputation data."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    if verbose:
        print(f"  [AbuseIPDB] Querying {ip}...", file=sys.stderr)

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        else:
            print(
                f"  [AbuseIPDB] HTTP {resp.status_code}: {resp.text[:200]}",
                file=sys.stderr,
            )
            return None
    except requests.exceptions.RequestException as e:
        print(f"  [AbuseIPDB] Error: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# VirusTotal query
# Docs: https://docs.virustotal.com/reference/overview
# ---------------------------------------------------------------------------
def query_virustotal(
    indicator: str, indicator_type: str, api_key: str, verbose: bool = False
) -> dict | None:
    """Query VirusTotal for analysis data based on indicator type."""
    base = "https://www.virustotal.com/api/v3"

    if indicator_type == "ip":
        url = f"{base}/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        url = f"{base}/domains/{indicator}"
    elif indicator_type.startswith("hash"):
        url = f"{base}/files/{indicator}"
    else:
        return None

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    if verbose:
        print(f"  [VirusTotal] Querying {indicator}...", file=sys.stderr)

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("data", {})
        elif resp.status_code == 404:
            if verbose:
                print("  [VirusTotal] Indicator not found in database.", file=sys.stderr)
            return None
        else:
            print(
                f"  [VirusTotal] HTTP {resp.status_code}: {resp.text[:200]}",
                file=sys.stderr,
            )
            return None
    except requests.exceptions.RequestException as e:
        print(f"  [VirusTotal] Error: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def calculate_risk(
    abuseipdb_data: dict | None, vt_data: dict | None, indicator_type: str
) -> tuple[str, str]:
    """
    Calculate a risk level based on available data.
    Returns (risk_level, rationale).
    """
    score = 0
    reasons = []

    # AbuseIPDB scoring
    if abuseipdb_data:
        confidence = abuseipdb_data.get("abuseConfidenceScore", 0)
        total_reports = abuseipdb_data.get("totalReports", 0)
        if confidence >= 80:
            score += 40
            reasons.append(f"AbuseIPDB confidence {confidence}%")
        elif confidence >= 50:
            score += 25
            reasons.append(f"AbuseIPDB confidence {confidence}%")
        elif confidence > 0:
            score += 10
            reasons.append(f"AbuseIPDB confidence {confidence}%")
        if total_reports > 100:
            score += 15
            reasons.append(f"{total_reports} abuse reports")

    # VirusTotal scoring
    if vt_data:
        attrs = vt_data.get("attributes", {})
        if indicator_type.startswith("hash"):
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 1
            ratio = malicious / max(total, 1)
            if ratio > 0.5:
                score += 40
                reasons.append(f"VT: {malicious}/{total} vendors flagged malicious")
            elif ratio > 0.2:
                score += 25
                reasons.append(f"VT: {malicious}/{total} vendors flagged malicious")
            elif malicious > 0:
                score += 10
                reasons.append(f"VT: {malicious}/{total} vendors flagged malicious")
        elif indicator_type in ("ip", "domain"):
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious + suspicious > 5:
                score += 30
                reasons.append(f"VT: {malicious} malicious, {suspicious} suspicious")
            elif malicious + suspicious > 0:
                score += 15
                reasons.append(f"VT: {malicious} malicious, {suspicious} suspicious")

    # Map score to risk level
    if score >= 60:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFORMATIONAL"

    rationale = "; ".join(reasons) if reasons else "No threat indicators detected"
    return level, rationale


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
def generate_brief(
    indicator: str,
    indicator_type: str,
    abuseipdb_data: dict | None,
    vt_data: dict | None,
    attack_techniques: list[tuple[str, str]],
    risk_level: str,
    risk_rationale: str,
) -> str:
    """Generate a Markdown threat intelligence brief."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    type_label = indicator_type.replace("_", " ").upper()

    lines = [
        "# Threat Intelligence Brief",
        "",
        f"**Indicator:** `{indicator}`",
        f"**Type:** {type_label}",
        f"**Generated:** {now}",
        f"**Risk Level:** {risk_level}",
        "",
        "---",
        "",
    ]

    # AbuseIPDB section
    if indicator_type == "ip":
        lines.append("## AbuseIPDB Results")
        lines.append("")
        if abuseipdb_data:
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(
                f"| Abuse Confidence Score | {abuseipdb_data.get('abuseConfidenceScore', 'N/A')}% |"
            )
            lines.append(
                f"| Total Reports | {abuseipdb_data.get('totalReports', 'N/A')} |"
            )
            lines.append(
                f"| Country | {abuseipdb_data.get('countryCode', 'N/A')} |"
            )
            lines.append(f"| ISP | {abuseipdb_data.get('isp', 'N/A')} |")
            lines.append(f"| Domain | {abuseipdb_data.get('domain', 'N/A')} |")
            lines.append(
                f"| Usage Type | {abuseipdb_data.get('usageType', 'N/A')} |"
            )
            lines.append(
                f"| Is Tor | {abuseipdb_data.get('isTor', 'N/A')} |"
            )
            lines.append(
                f"| Is Whitelisted | {abuseipdb_data.get('isWhitelisted', 'N/A')} |"
            )
        else:
            lines.append("*No AbuseIPDB data available (missing API key or query failed).*")
        lines.append("")

    # VirusTotal section
    lines.append("## VirusTotal Results")
    lines.append("")
    if vt_data:
        attrs = vt_data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        lines.append("### Analysis Statistics")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for category in ["malicious", "suspicious", "undetected", "harmless", "timeout"]:
            lines.append(f"| {category.capitalize()} | {stats.get(category, 0)} |")

        # Additional attributes based on type
        if indicator_type.startswith("hash"):
            lines.append("")
            lines.append("### File Details")
            lines.append("")
            for field in [
                "meaningful_name",
                "type_description",
                "size",
                "sha256",
                "md5",
            ]:
                val = attrs.get(field, "N/A")
                lines.append(f"- **{field}:** {val}")

        elif indicator_type == "domain":
            lines.append("")
            registrar = attrs.get("registrar", "N/A")
            creation = attrs.get("creation_date", "N/A")
            lines.append(f"- **Registrar:** {registrar}")
            lines.append(f"- **Creation Date:** {creation}")

        elif indicator_type == "ip":
            lines.append("")
            owner = attrs.get("as_owner", "N/A")
            country = attrs.get("country", "N/A")
            lines.append(f"- **AS Owner:** {owner}")
            lines.append(f"- **Country:** {country}")
    else:
        lines.append(
            "*No VirusTotal data available (missing API key or query failed).*"
        )
    lines.append("")

    # ATT&CK mapping
    lines.append("## MITRE ATT&CK Mapping")
    lines.append("")
    if attack_techniques:
        lines.append("| Technique ID | Technique Name | Reference |")
        lines.append("|-------------|----------------|-----------|")
        for tid, tname in attack_techniques:
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            lines.append(f"| {tid} | {tname} | [ATT&CK]({url}) |")
    else:
        lines.append("*No ATT&CK techniques mapped from available data.*")
    lines.append("")

    # Risk assessment
    lines.append("## Risk Assessment")
    lines.append("")
    lines.append(f"**Level:** {risk_level}")
    lines.append(f"**Rationale:** {risk_rationale}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Generated by OSINT Training Program - Module 06*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-source threat intelligence lookup. Accepts an IP address, "
        "domain, or file hash, queries AbuseIPDB and VirusTotal, and produces "
        "a threat intelligence brief with ATT&CK mapping.",
    )
    parser.add_argument(
        "indicator",
        help="IP address, domain, or file hash (MD5/SHA1/SHA256) to investigate",
    )
    parser.add_argument(
        "--output", help="Save Markdown brief to this file path"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print detailed progress to stderr"
    )

    args = parser.parse_args()

    # Detect indicator type
    indicator_type = detect_indicator_type(args.indicator)
    if indicator_type == "unknown":
        print(
            f"[!] Could not determine indicator type for: {args.indicator}",
            file=sys.stderr,
        )
        print(
            "    Supported types: IPv4 address, domain name, MD5/SHA1/SHA256 hash",
            file=sys.stderr,
        )
        sys.exit(1)

    type_label = indicator_type.replace("_", " ").upper()
    print(f"[*] Indicator: {args.indicator}", file=sys.stderr)
    print(f"[*] Detected type: {type_label}", file=sys.stderr)
    print(file=sys.stderr)

    # Read API keys from environment
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    if not abuseipdb_key:
        print(
            "[!] ABUSEIPDB_API_KEY not set -- skipping AbuseIPDB query.",
            file=sys.stderr,
        )
    if not vt_key:
        print(
            "[!] VIRUSTOTAL_API_KEY not set -- skipping VirusTotal query.",
            file=sys.stderr,
        )

    # Query sources
    abuseipdb_data = None
    vt_data = None
    all_text = ""

    if indicator_type == "ip" and abuseipdb_key:
        print("[*] Querying AbuseIPDB...", file=sys.stderr)
        abuseipdb_data = query_abuseipdb(args.indicator, abuseipdb_key, args.verbose)
        if abuseipdb_data:
            all_text += str(abuseipdb_data)
            print("    Done.", file=sys.stderr)

    if vt_key:
        print("[*] Querying VirusTotal...", file=sys.stderr)
        vt_data = query_virustotal(
            args.indicator, indicator_type, vt_key, args.verbose
        )
        if vt_data:
            all_text += str(vt_data)
            print("    Done.", file=sys.stderr)

    # Map to ATT&CK
    print("[*] Mapping to MITRE ATT&CK...", file=sys.stderr)
    techniques = map_to_attack(all_text)
    if techniques:
        print(f"    Mapped {len(techniques)} technique(s).", file=sys.stderr)
    else:
        print("    No techniques mapped.", file=sys.stderr)

    # Risk assessment
    risk_level, risk_rationale = calculate_risk(
        abuseipdb_data, vt_data, indicator_type
    )
    print(f"[*] Risk level: {risk_level}", file=sys.stderr)

    # Generate brief
    brief = generate_brief(
        args.indicator,
        indicator_type,
        abuseipdb_data,
        vt_data,
        techniques,
        risk_level,
        risk_rationale,
    )

    if args.output:
        with open(args.output, "w") as f:
            f.write(brief)
        print(f"\n[+] Brief saved to: {args.output}", file=sys.stderr)
    else:
        print()
        print(brief)


if __name__ == "__main__":
    main()
