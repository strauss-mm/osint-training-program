# Module 08: OSINT Automation and Workflow

## Overview

This capstone module brings together techniques from all previous modules into an automated
collection and reporting framework. You will build a mini OSINT framework that performs
DNS resolution, WHOIS lookups, certificate transparency searches, HTTP header analysis,
and Wayback Machine queries -- then correlates findings into a unified JSON report and
an HTML dashboard.

## Learning Objectives

- Design and implement automated OSINT collection pipelines
- Correlate data from multiple sources into unified reports
- Generate professional HTML dashboard reports
- Understand rate limiting, error handling, and API management at scale
- Distinguish between quick reconnaissance and deep collection modes

## Prerequisites

- Python 3.9+
- Modules 01-07 completed
- Understanding of DNS, HTTP, TLS, and WHOIS protocols

## Key Concepts

| Concept | Description |
|---------|-------------|
| Collection management | Organizing what to collect, from where, and in what order |
| Data correlation | Cross-referencing findings from multiple sources for new insights |
| Automated enrichment | Programmatically adding context to raw indicators |
| Report generation | Producing structured output (JSON, HTML) for different audiences |
| Rate limiting | Respecting API quotas and avoiding detection/blocking |
| Quick vs deep recon | Balancing speed against thoroughness based on operational needs |
| Structured output | Machine-readable JSON for downstream tooling integration |

## Tool Reference

| Tool | Description | Link |
|------|-------------|------|
| SpiderFoot | Automated OSINT collection with 200+ modules | https://github.com/smicallef/spiderfoot |
| Recon-ng | Modular web reconnaissance framework | https://github.com/lanmaster53/recon-ng |
| Maltego CE | Visual link analysis and data mining | https://www.maltego.com/maltego-community/ |
| theHarvester | Email, subdomain, and name gathering | https://github.com/laramies/theHarvester |
| sn0int | Semi-automatic OSINT framework and package manager | https://github.com/kpcyrd/sn0int |
| Hunchly | Web page capture and evidence collection | https://www.hunchly.com/ |
| aiohttp | Async HTTP client/server for Python | https://docs.aiohttp.org/ |
| Jupyter | Interactive notebooks for analysis workflows | https://jupyter.org/ |

## Architecture

The lab framework follows a modular pipeline:

```
Target Domain
    |
    v
[ Collection Modules ] --> DNS, WHOIS, CT Logs, Headers, Wayback, robots.txt
    |
    v
[ Correlation Engine ] --> Deduplication, cross-referencing, scoring
    |
    v
[ Report Generator  ] --> JSON report + HTML dashboard
```

## Further Reading

- SpiderFoot documentation: https://www.spiderfoot.net/documentation/
- Recon-ng wiki: https://github.com/lanmaster53/recon-ng/wiki
- "Automating OSINT" by Justin Seitz (Black Hat Python author)
- SANS SEC487: Open-Source Intelligence Gathering and Analysis

## Lab

Proceed to [lab/LAB.md](lab/LAB.md) for the hands-on exercise.
