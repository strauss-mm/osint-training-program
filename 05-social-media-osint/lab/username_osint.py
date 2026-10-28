#!/usr/bin/env python3
"""
Username OSINT Investigation Tool

Checks whether a username exists on common platforms using HTTP status codes,
generates candidate email addresses, and produces a Markdown profile card.

ETHICAL NOTICE: Only use this tool against accounts you own or have explicit
written permission to investigate. Unauthorized investigation of individuals
is unethical and potentially illegal.
"""

import argparse
import sys
import time
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Platform definitions
# Each entry: (name, url_template, method, expected_status_for_exists)
#
# Detection strategy: We send a HEAD or GET request to the profile URL.
# If the platform returns a 200, the account likely exists. A 404 indicates
# no account. Some platforms redirect (301/302) for nonexistent users, or
# return 200 with a "not found" page body -- these are noted as limitations.
# ---------------------------------------------------------------------------
PLATFORMS = [
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Reliable -- GitHub returns 404 for nonexistent users.",
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Generally reliable; suspended accounts may return 403.",
    },
    {
        "name": "Twitter/X",
        "url": "https://x.com/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Unreliable -- X often requires JavaScript or auth. May show false negatives.",
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "method": "GET",
        "expect": 200,
        "note": "May require login; returns 200 for login redirect on private/nonexistent.",
    },
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Heavy anti-scraping; frequently returns 999 or CAPTCHA. High false-negative rate.",
    },
    {
        "name": "HackerNews",
        "url": "https://news.ycombinator.com/user?id={username}",
        "method": "GET",
        "expect": 200,
        "note": "Reliable -- returns blank page body for nonexistent users (still 200).",
    },
    {
        "name": "Medium",
        "url": "https://medium.com/@{username}",
        "method": "GET",
        "expect": 200,
        "note": "Redirects to homepage for nonexistent users (check final URL).",
    },
    {
        "name": "Keybase",
        "url": "https://keybase.io/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Reliable 404 for nonexistent users. Service is in maintenance mode.",
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "method": "GET",
        "expect": 200,
        "note": "Reliable -- returns 404 for nonexistent users.",
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/{username}/",
        "method": "GET",
        "expect": 200,
        "note": "May redirect to login for nonexistent users.",
    },
]

# Common email providers for pattern generation
EMAIL_PROVIDERS = [
    ("Gmail", "gmail.com"),
    ("ProtonMail", "protonmail.com"),
    ("Outlook", "outlook.com"),
    ("Yahoo", "yahoo.com"),
]


def print_banner():
    """Display ethical use banner."""
    banner = """
============================================================
  Username OSINT Investigation Tool
============================================================
  ETHICAL USE ONLY -- This tool performs passive checks
  against publicly accessible URLs. Only investigate
  accounts you own or have written authorization to check.
============================================================
"""
    print(banner, file=sys.stderr)


def check_platform(username: str, platform: dict, timeout: int) -> dict:
    """
    Check if a username exists on a given platform.

    Strategy: Send an HTTP request to the profile URL and check the status code.
    This is a simple heuristic -- not all platforms return clean 404s for missing
    accounts. Some use JavaScript rendering, redirects, or CAPTCHAs.

    Returns a dict with platform name, URL, status, and existence determination.
    """
    url = platform["url"].format(username=username)
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    result = {
        "platform": platform["name"],
        "url": url,
        "status_code": None,
        "exists": None,
        "note": platform["note"],
        "error": None,
    }

    try:
        resp = requests.get(
            url, headers=headers, timeout=timeout, allow_redirects=True
        )
        result["status_code"] = resp.status_code

        # Simple heuristic: 200 = likely exists, 404 = likely not
        if resp.status_code == platform["expect"]:
            result["exists"] = True
        elif resp.status_code == 404:
            result["exists"] = False
        else:
            # Ambiguous -- could be rate limiting (429), auth required (401/403), etc.
            result["exists"] = None
            result["note"] = f"Ambiguous status {resp.status_code}. {platform['note']}"

    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


def generate_email_patterns(username: str) -> list[dict]:
    """
    Generate candidate email addresses based on the username.

    This is speculative -- these addresses may or may not exist. Tools like
    holehe (https://github.com/megadose/holehe) can check whether an email
    is registered on specific services.
    """
    patterns = []
    for provider_name, domain in EMAIL_PROVIDERS:
        patterns.append(
            {
                "email": f"{username}@{domain}",
                "provider": provider_name,
                "pattern": "exact_username",
            }
        )
    return patterns


def generate_profile_card(
    username: str, results: list[dict], emails: list[dict]
) -> str:
    """
    Generate a Markdown-formatted profile card summarizing findings.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    found = [r for r in results if r["exists"] is True]
    not_found = [r for r in results if r["exists"] is False]
    ambiguous = [r for r in results if r["exists"] is None and r["error"] is None]
    errors = [r for r in results if r["error"] is not None]

    lines = [
        f"# OSINT Profile Card: {username}",
        "",
        f"**Generated:** {now}",
        f"**Platforms checked:** {len(results)}",
        f"**Accounts found:** {len(found)}",
        f"**Not found:** {len(not_found)}",
        f"**Ambiguous:** {len(ambiguous)}",
        f"**Errors:** {len(errors)}",
        "",
        "---",
        "",
        "## Platform Results",
        "",
        "| Platform | Status | URL | Notes |",
        "|----------|--------|-----|-------|",
    ]

    for r in results:
        if r["error"]:
            status = "ERROR"
            note = r["error"]
        elif r["exists"] is True:
            status = "FOUND"
            note = ""
        elif r["exists"] is False:
            status = "NOT FOUND"
            note = ""
        else:
            status = "AMBIGUOUS"
            note = r.get("note", "")

        lines.append(f"| {r['platform']} | {status} | {r['url']} | {note} |")

    lines.extend(
        [
            "",
            "## Candidate Email Addresses",
            "",
            "These are speculative patterns -- verification requires additional tools.",
            "",
            "| Email | Provider | Pattern |",
            "|-------|----------|---------|",
        ]
    )

    for e in emails:
        lines.append(f"| {e['email']} | {e['provider']} | {e['pattern']} |")

    lines.extend(
        [
            "",
            "---",
            "",
            "*This report was generated for authorized investigative purposes only.*",
        ]
    )

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Username OSINT investigation tool. Checks username existence "
        "across multiple platforms and generates a profile card.",
        epilog="ETHICAL USE ONLY: Only investigate accounts you own or have "
        "explicit written permission to check.",
    )
    parser.add_argument(
        "--username", required=True, help="Username to investigate"
    )
    parser.add_argument(
        "--output",
        help="Save Markdown profile card to this file path",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()
    print_banner()

    username = args.username
    print(f"[*] Investigating username: {username}", file=sys.stderr)
    print(
        f"[*] Checking {len(PLATFORMS)} platforms with {args.timeout}s timeout",
        file=sys.stderr,
    )
    print(file=sys.stderr)

    # -----------------------------------------------------------------------
    # Phase 1: Platform enumeration
    # We check each platform sequentially with a delay between requests to
    # avoid triggering rate limits. In production tools like Sherlock, this
    # is done concurrently with asyncio for speed.
    # -----------------------------------------------------------------------
    results = []
    for i, platform in enumerate(PLATFORMS):
        print(
            f"  [{i + 1}/{len(PLATFORMS)}] Checking {platform['name']}...",
            file=sys.stderr,
            end="",
        )

        result = check_platform(username, platform, args.timeout)
        results.append(result)

        if result["error"]:
            print(f" ERROR: {result['error']}", file=sys.stderr)
        elif result["exists"] is True:
            print(" FOUND", file=sys.stderr)
        elif result["exists"] is False:
            print(" not found", file=sys.stderr)
        else:
            print(f" ambiguous ({result['status_code']})", file=sys.stderr)

        # Rate limiting: 1.5 seconds between requests to be respectful
        if i < len(PLATFORMS) - 1:
            time.sleep(1.5)

    # -----------------------------------------------------------------------
    # Phase 2: Email pattern generation
    # -----------------------------------------------------------------------
    print(file=sys.stderr)
    print("[*] Generating candidate email patterns...", file=sys.stderr)
    emails = generate_email_patterns(username)

    # -----------------------------------------------------------------------
    # Phase 3: Profile card generation
    # -----------------------------------------------------------------------
    print("[*] Generating profile card...", file=sys.stderr)
    card = generate_profile_card(username, results, emails)

    if args.output:
        with open(args.output, "w") as f:
            f.write(card)
        print(f"\n[+] Profile card saved to: {args.output}", file=sys.stderr)
    else:
        print("\n" + card)

    # Summary
    found_count = sum(1 for r in results if r["exists"] is True)
    print(
        f"\n[*] Done. {found_count}/{len(results)} platforms returned positive.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
