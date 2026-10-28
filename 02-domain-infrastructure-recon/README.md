# Module 02: Domain & Infrastructure Reconnaissance

Mapping an organization's external footprint through DNS, certificate transparency, WHOIS, and subdomain enumeration — the foundation of any infrastructure assessment.

## Learning Objectives

- Enumerate subdomains using passive and active techniques
- Extract intelligence from DNS record types (A, MX, NS, TXT, SOA)
- Query Certificate Transparency logs to discover hidden assets
- Analyze WHOIS registration data for organizational context
- Distinguish passive reconnaissance (no target interaction) from active probing

## Key Concepts

### Passive vs Active Reconnaissance

| Approach | Description | Detection Risk |
|----------|-------------|---------------|
| **Passive** | Queries third-party data sources (CT logs, WHOIS databases, search engines) without touching the target | None — target sees no traffic |
| **Active** | Directly queries target infrastructure (DNS resolution, zone transfers, port scans) | Moderate — appears in target logs |

Passive collection should always precede active probing. Many investigations require passive-only constraints.

### DNS Records as Intelligence Sources

| Record | Intelligence Value |
|--------|-------------------|
| **A / AAAA** | Maps hostnames to IPs; reveals hosting providers and infrastructure layout |
| **MX** | Identifies mail infrastructure; often reveals third-party email services |
| **NS** | Shows DNS hosting; NS changes over time indicate infrastructure migrations |
| **TXT** | SPF, DKIM, DMARC policies; cloud service verification tokens (Google, Microsoft, AWS) |
| **SOA** | Administrative contact, zone serial numbers, refresh intervals |
| **CNAME** | Alias chains reveal CDN usage, SaaS integrations, potential subdomain takeover targets |

### Certificate Transparency

Certificate Transparency (CT) is a public logging framework (RFC 6962) that requires CAs to publish all issued certificates. For OSINT:

- Reveals subdomains the organization may not intend to be public
- Historical certificates show infrastructure changes over time
- Wildcard certificates indicate domain scope
- Pre-certificates expose domains before they go live

### WHOIS Intelligence

Registration records provide:
- Registrant organization and contact details (where not privacy-protected)
- Registration and expiration dates (expiring domains are acquisition targets)
- Name server history (via historical WHOIS services)
- Registrar information (shared registrars can link related organizations)

## Tools Reference

| Tool | Type | Description | Link |
|------|------|-------------|------|
| Amass | Subdomain Enumeration | OWASP project; combines passive sources, DNS brute-force, and graph analysis | [GitHub](https://github.com/owasp-amass/amass) |
| Subfinder | Passive Subdomain Discovery | Fast passive enumeration using dozens of data sources | [GitHub](https://github.com/projectdiscovery/subfinder) |
| DNSRecon | DNS Enumeration | Zone transfers, brute-force, SRV enumeration, cache snooping | [GitHub](https://github.com/darkoperator/dnsrecon) |
| theHarvester | Multi-Source Harvesting | Collects emails, subdomains, hosts, and names from public sources | [GitHub](https://github.com/laramies/theHarvester) |
| Shodan CLI | Asset Search | Query internet-wide scan data for open ports, banners, and vulnerabilities | [Docs](https://cli.shodan.io/) |
| crt.sh | CT Log Search | Web interface and API for querying Certificate Transparency logs | [Website](https://crt.sh/) |
| SecurityTrails | DNS Intelligence | Historical DNS data, WHOIS history, and associated domains | [Website](https://securitytrails.com/) |

## Lab

| Lab | Focus | Difficulty | Est. Time |
|-----|-------|-----------|-----------|
| [Domain Recon Script](lab/LAB.md) | CT logs, WHOIS, DNS enumeration with Python | Intermediate | 3 hours |

## Prerequisites

- Python 3.11+
- Basic understanding of DNS (record types, resolution process)
- Familiarity with command-line HTTP tools (curl, wget)
- Completion of Module 01 recommended

## Further Reading

- [Certificate Transparency — How CT Works](https://certificate.transparency.dev/howctworks/)
- [OWASP Testing Guide — Enumerate Infrastructure and Application Admin Interfaces](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces)
- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [ICANN WHOIS Lookup](https://lookup.icann.org/)
- [DNS Dumpster — Free domain research tool](https://dnsdumpster.com/)
