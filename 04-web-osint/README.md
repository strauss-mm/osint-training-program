# Module 04: Web Application OSINT

Passive reconnaissance of web applications to identify technology stacks, discover hidden endpoints, and analyze historical changes — all without sending a single exploit.

## Learning Objectives

- Fingerprint web technologies from HTTP headers, HTML patterns, and JavaScript references
- Query the Wayback Machine for historical snapshots and content drift analysis
- Extract and catalog URLs from multiple passive sources
- Analyze JavaScript files for undocumented API endpoints
- Map the full attack surface of a web application through passive observation

## Key Concepts

### Technology Fingerprinting

Web applications leak technology information through multiple channels:

- **HTTP headers** — `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` headers directly reveal server software
- **Cookie names** — `PHPSESSID` (PHP), `JSESSIONID` (Java), `ASP.NET_SessionId` (.NET), `csrftoken` (Django)
- **HTML meta tags** — `<meta name="generator">` tags identify CMS platforms
- **Script and CSS references** — Framework-specific paths (`/wp-content/`, `/static/admin/`, `react.production.min.js`)
- **Response behavior** — Default error pages, URL routing patterns, and header ordering

### Historical Web Data

The Wayback Machine archives billions of web pages over time. For OSINT, historical data reveals:

- Removed pages that contained sensitive information
- Old subdomains and endpoints no longer linked from the live site
- Technology stack changes (migration from one framework to another)
- Developer comments, debug endpoints, and staging references that were later cleaned up

The CDX API provides programmatic access to the index without downloading full page content.

### URL Extraction and Endpoint Discovery

Passive URL collection aggregates data from multiple sources:

- **Certificate Transparency logs** — domains associated with issued certificates
- **Wayback Machine** — all URLs ever archived for a domain
- **Common Crawl** — web crawl data from the Common Crawl project
- **AlienVault OTX** — threat intelligence URL feeds

### JavaScript Analysis

Modern single-page applications embed API endpoints, authentication flows, and internal paths directly in JavaScript bundles. Analyzing these files can reveal:

- REST API routes and GraphQL endpoints
- Internal service hostnames and staging URLs
- API keys and tokens accidentally embedded in client-side code
- Authentication and authorization logic

## Tool Reference

| Tool | Purpose | Link |
|------|---------|------|
| Wappalyzer | Technology fingerprinting (browser extension + CLI) | [GitHub](https://github.com/wappalyzer/wappalyzer) |
| BuiltWith | Technology stack lookup (web service) | [builtwith.com](https://builtwith.com/) |
| Wayback Machine | Historical web page snapshots | [web.archive.org](https://web.archive.org/) |
| Wayback CDX API | Programmatic access to Wayback Machine index | [GitHub](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) |
| WaybackURLs | Extract all URLs from Wayback Machine for a domain | [GitHub](https://github.com/tomnomnom/waybackurls) |
| GAU | Fetch URLs from Wayback, Common Crawl, OTX, URLScan | [GitHub](https://github.com/lc/gau) |
| Photon | Fast web crawler designed for OSINT | [GitHub](https://github.com/s0md3v/Photon) |
| httpx | HTTP probing and technology detection | [GitHub](https://github.com/projectdiscovery/httpx) |

## Prerequisites

- Completion of Module 01 (OSINT Fundamentals) and Module 02 (Domain Recon)
- Understanding of HTTP protocol (methods, headers, status codes)
- Python 3.11+
- Basic HTML/JavaScript literacy

## Lab

| Lab | Focus | Difficulty | Est. Time |
|-----|-------|-----------|-----------|
| [Web Application OSINT](lab/LAB.md) | Technology fingerprinting, Wayback analysis, link extraction | Intermediate | 3 hours |

## Further Reading

- [OWASP Web Security Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [Wayback CDX Server API Documentation](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [Wappalyzer Technology Categories](https://www.wappalyzer.com/technologies/)
- [ProjectDiscovery httpx Documentation](https://docs.projectdiscovery.io/tools/httpx/overview)
- [Bug Bounty Bootcamp by Vickie Li](https://nostarch.com/bug-bounty-bootcamp) — Chapter 5: Web Hacking Reconnaissance
