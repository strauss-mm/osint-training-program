# Lab 08: Building an Automated OSINT Collection Framework

**Difficulty:** Advanced
**Estimated Time:** 150 minutes
**Prerequisites:** Python 3.9+, internet access, modules 01-07 completed

---

## Objectives

- Run an automated multi-module OSINT collection against a target domain
- Understand the difference between quick and deep reconnaissance modes
- Examine correlated findings across collection modules
- Analyze a generated HTML dashboard report
- Extend the framework with custom collection modules

## Setup

```bash
cd /Users/mmstrauss/dev/osint-training-program/08-osint-automation/lab
pip install -r requirements.txt
```

## Exercise 1: Quick Reconnaissance

Run the framework in quick mode against a domain you own or `example.com`:

```bash
python osint_framework.py example.com --quick
```

Review the terminal output. The framework runs each collection module in sequence:
DNS resolution, WHOIS lookup, certificate transparency, HTTP headers, Wayback Machine,
and robots.txt/sitemap analysis.

**Question:** How long did the quick scan take? How many findings were collected?

## Exercise 2: Examine the JSON Report

Open the generated JSON report in the output directory:

```bash
cat output/example.com_report.json | python -m json.tool | less
```

Note the structure:
- `metadata`: target, timestamp, mode, duration
- `findings`: organized by module (dns, whois, certificates, headers, wayback, robots)
- `correlation`: cross-referenced data (unique IPs, merged subdomains, security score)

## Exercise 3: Review the HTML Dashboard

Open the HTML dashboard in a browser:

```bash
open output/example.com_dashboard.html    # macOS
```

Examine each section:
- Summary statistics
- DNS resolution results
- WHOIS registration details
- Certificate transparency subdomains
- Security headers scorecard (green/yellow/red indicators)
- Wayback Machine timeline
- Discovered paths from robots.txt

## Exercise 4: Deep Reconnaissance

Run the framework in deep mode and compare:

```bash
python osint_framework.py example.com --deep --verbose
```

**Questions:**
- What additional modules ran in deep mode?
- How many more subdomains were discovered?
- How did the scan duration compare to quick mode?
- Were any technologies detected?

## Exercise 5: Add a Custom Module

Create a new collection module. For example, add a function that checks for common
security-related files:

- `/.well-known/security.txt`
- `/humans.txt`
- `/.well-known/change-password`

Add it to the module pipeline and re-run the framework.

## Exercise 6: Operational Considerations

Discuss or document answers to these questions:

1. How does the framework handle rate limiting? What happens if a source blocks you?
2. What User-Agent string does the framework send? Is it identifiable?
3. How would you add proxy support for anonymous collection?
4. What data validation should be added before trusting any single source?
5. How would you handle targets with WAF/CDN protection (Cloudflare, Akamai)?

## Challenge Exercises

### Challenge A: Async Collection

Refactor the collection modules to use `asyncio` and `aiohttp` for concurrent execution.
Measure the performance improvement over sequential collection.

### Challenge B: Add a New Data Source

Integrate the Shodan API (https://developer.shodan.io/) to add open port and service
information to the report. Handle the case where no API key is configured.

### Challenge C: Correlation Rules

Add correlation rules that flag interesting patterns:
- Domain registered recently (< 1 year) with no Wayback history (potential phishing)
- Multiple subdomains resolving to the same IP (shared hosting or CDN)
- Missing critical security headers (potential misconfiguration)

## Cleanup

```bash
rm -rf output/
```

## Key Takeaways

- Automation transforms manual OSINT from hours of work into minutes, but requires
  careful error handling and rate limiting.
- The quick/deep distinction reflects real operational trade-offs between speed and
  thoroughness.
- Correlation across sources produces insights that no single source can provide alone.
- A well-structured report (JSON for machines, HTML for humans) serves different audiences
  from the same collection run.
- This framework is a starting point. Production OSINT tools like SpiderFoot and Recon-ng
  build on the same principles at much larger scale.
