# OSINT Training Program

**Marna Marie Strauss** | Global Lead Security Engineer | OSINT Skills Development

Comprehensive OSINT training program with 8 hands-on modules covering intelligence fundamentals through advanced automation. Each module includes theory, open-source tool documentation, and practical labs designed for security engineers building investigative capabilities.

---

## Modules

| # | Module | Focus | Difficulty | Status |
|---|--------|-------|------------|--------|
| 01 | [OSINT Fundamentals](01-osint-fundamentals/) | Intelligence cycle, legal frameworks, OPSEC | Beginner | Complete |
| 02 | [Domain & Infrastructure Recon](02-domain-infrastructure-recon/) | DNS, WHOIS, certificate transparency, subdomain enumeration | Beginner | Complete |
| 03 | [Network Intelligence](03-network-intelligence/) | Shodan, Censys, IP analysis, BGP/ASN research | Intermediate | Complete |
| 04 | [Web Application OSINT](04-web-osint/) | Tech fingerprinting, Wayback Machine, JS analysis | Intermediate | Complete |
| 05 | [Social Media & People OSINT](05-social-media-osint/) | Username enumeration, email discovery, profile correlation | Intermediate | Complete |
| 06 | [Threat Intelligence](06-threat-intelligence/) | CTI feeds, IOC analysis, MITRE ATT&CK mapping | Advanced | Complete |
| 07 | [Geospatial Intelligence](07-geospatial-intelligence/) | EXIF analysis, geolocation, satellite imagery | Advanced | Complete |
| 08 | [OSINT Automation](08-osint-automation/) | Recon frameworks, workflow orchestration, reporting | Advanced | Complete |

See [CURRICULUM.md](CURRICULUM.md) for the 8-week phased learning path and [RESOURCES.md](RESOURCES.md) for curated external references.

---

## Prerequisites

- Python 3.10+
- Basic networking knowledge (DNS, HTTP, TCP/IP)
- Familiarity with command-line tools
- API keys (free tiers sufficient) for: Shodan, VirusTotal, AbuseIPDB, IPinfo

---

## Setup

```bash
git clone https://github.com/strauss-mm/osint-training-program.git
cd osint-training-program
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

To install dependencies for a specific module only:

```bash
pip install -r 02-domain-infrastructure-recon/lab/requirements.txt
```

---

## Tool Ecosystem

Master reference of all open-source tools covered across the program.

| Tool | Category | License | Link |
|------|----------|---------|------|
| Amass | Recon | Apache 2.0 | [github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) |
| Subfinder | Recon | MIT | [github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| DNSRecon | Recon | GPL 2.0 | [github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) |
| theHarvester | Recon | GPL 2.0 | [github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) |
| Shodan | Network | Proprietary | [shodan.io](https://www.shodan.io/) |
| Censys | Network | Proprietary | [search.censys.io](https://search.censys.io/) |
| GreyNoise | Network | Proprietary | [greynoise.io](https://www.greynoise.io/) |
| Masscan | Network | AGPL 3.0 | [github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) |
| Nmap | Network | NPSL | [nmap.org](https://nmap.org/) |
| Wappalyzer | Web | MIT | [github.com/wappalyzer/wappalyzer](https://github.com/AliasIO/wappalyzer) |
| Wayback Machine | Web | N/A | [web.archive.org](https://web.archive.org/) |
| GAU | Web | MIT | [github.com/lc/gau](https://github.com/lc/gau) |
| httpx | Web | MIT | [github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| Photon | Web | GPL 3.0 | [github.com/s0md3v/Photon](https://github.com/s0md3v/Photon) |
| Sherlock | Social/People | MIT | [github.com/sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) |
| Maigret | Social/People | MIT | [github.com/soxoj/maigret](https://github.com/soxoj/maigret) |
| holehe | Social/People | GPL 3.0 | [github.com/megadose/holehe](https://github.com/megadose/holehe) |
| SpiderFoot | Automation | MIT | [github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) |
| MISP | Threat Intel | AGPL 3.0 | [github.com/MISP/MISP](https://github.com/MISP/MISP) |
| OpenCTI | Threat Intel | Apache 2.0 | [github.com/OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) |
| VirusTotal | Threat Intel | Proprietary | [virustotal.com](https://www.virustotal.com/) |
| AbuseIPDB | Threat Intel | Proprietary | [abuseipdb.com](https://www.abuseipdb.com/) |
| AlienVault OTX | Threat Intel | Proprietary | [otx.alienvault.com](https://otx.alienvault.com/) |
| ExifTool | GEOINT | Artistic/GPL | [exiftool.org](https://exiftool.org/) |
| Folium | GEOINT | MIT | [github.com/python-visualization/folium](https://github.com/python-visualization/folium) |
| Google Earth Pro | GEOINT | Proprietary | [earth.google.com](https://earth.google.com/intl/en/earth/download/gep/agree.html) |
| Recon-ng | Automation | GPL 3.0 | [github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) |
| Maltego CE | Automation | Proprietary | [maltego.com](https://www.maltego.com/) |
| sn0int | Automation | GPL 3.0 | [github.com/kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) |
| Hunchly | Automation | Proprietary | [hunch.ly](https://www.hunch.ly/) |

---

## Open Source Documentation

Essential OSINT references and methodologies:

| Resource | Description |
|----------|-------------|
| [OSINT Framework](https://osintframework.com/) | Categorized collection of OSINT tools organized by data type |
| [Bellingcat Online Investigation Toolkit](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/) | Curated spreadsheet of investigation tools maintained by Bellingcat |
| OSINT Techniques (Michael Bazzell) | Comprehensive book covering personal and organizational OSINT methodology |
| [SANS OSINT Resources](https://www.sans.org/blog/list-of-resource-links-from-open-source-intelligence-summit-2021/) | Curated links from the SANS Open Source Intelligence Summit |
| [PTES - Intelligence Gathering](http://www.pentest-standard.org/index.php/Intelligence_Gathering) | Penetration Testing Execution Standard intelligence gathering phase |
| [OWASP Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/) | OWASP web application information gathering methodology |

---

## Ethical Guidelines

- Obtain explicit written authorization before performing OSINT collection against any organization or individual
- Comply with all applicable laws including CFAA, GDPR, ECPA, and local regulations
- Respect privacy boundaries and do not access systems or data beyond your authorized scope
- Document all collection activities with timestamps, sources, and methods for accountability
- Use collected intelligence only for its stated defensive or investigative purpose
- Report vulnerabilities discovered during OSINT activities through responsible disclosure channels

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
