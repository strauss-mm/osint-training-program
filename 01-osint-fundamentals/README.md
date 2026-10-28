# Module 01: OSINT Fundamentals

The foundation — understanding intelligence disciplines, the OSINT lifecycle, legal boundaries, and operational security before touching any tool.

## Difficulty

Beginner | Estimated Time: 2 hours

## Learning Objectives

- Distinguish OSINT from other intelligence disciplines
- Apply the five-phase OSINT lifecycle to a real collection task
- Identify legal and ethical constraints that govern OSINT activities
- Implement basic OPSEC practices for investigations
- Select appropriate frameworks and methodologies for different objectives

## Key Concepts

### Intelligence Disciplines

| Discipline | Full Name | Description |
|-----------|-----------|-------------|
| OSINT | Open Source Intelligence | Publicly available information (web, DNS, filings, social media) |
| HUMINT | Human Intelligence | Information from human sources (interviews, social engineering) |
| SIGINT | Signals Intelligence | Intercepted communications and electronic signals |
| GEOINT | Geospatial Intelligence | Imagery, mapping, and location-based data |
| IMINT | Imagery Intelligence | Satellite and aerial imagery analysis |

OSINT is unique: it draws exclusively from publicly accessible sources, making it legal by default — but collection methods, data handling, and intent still carry legal risk.

### The OSINT Lifecycle

1. **Planning** — Define objectives, scope, legal boundaries, and required outputs
2. **Collection** — Gather raw data from identified sources using passive and active techniques
3. **Processing** — Normalize, deduplicate, and structure raw data into usable formats
4. **Analysis** — Correlate findings, identify patterns, assess confidence levels
5. **Dissemination** — Produce actionable reports tailored to the audience

Each phase feeds the next. Poor planning produces noisy collection; unstructured collection makes analysis unreliable.

### Legal and Ethical Frameworks

| Framework | Scope | Key Constraint |
|-----------|-------|----------------|
| CFAA (Computer Fraud and Abuse Act) | US federal | Unauthorized access to computer systems is a felony |
| GDPR (General Data Protection Regulation) | EU/EEA | Processing personal data requires lawful basis; data subjects have rights |
| ECPA (Electronic Communications Privacy Act) | US federal | Intercepting electronic communications without authorization is prohibited |
| Responsible Disclosure | Industry norm | Vulnerabilities found during OSINT should be reported, not exploited |

**Rule of thumb**: If you need to authenticate, bypass access controls, or exploit a vulnerability to obtain data, it is not OSINT.

### OPSEC for Investigators

- **Sock puppet accounts** — Use dedicated research accounts, never personal ones
- **VPN/Tor** — Mask your source IP; some targets monitor and log visitors
- **Browser isolation** — Use a dedicated browser profile with no personal extensions or logins
- **Metadata hygiene** — Strip metadata from documents before sharing; be aware of what your tools leak
- **Attribution awareness** — Every query you make (DNS, WHOIS, web request) leaves a trace somewhere

### Methodologies and Frameworks

| Framework | Author/Org | Focus |
|-----------|-----------|-------|
| OSINT Techniques | Michael Bazzell | Comprehensive personal and organizational investigation methodology |
| PTES (Penetration Testing Execution Standard) | PTES.org | Intelligence gathering phase of penetration testing |
| OWASP Testing Guide | OWASP | Information gathering for web application security assessments |
| Intelligence Cycle (JP 2-0) | US DoD | Military intelligence process adapted for civilian OSINT |

## Tools Reference

| Tool | Type | Description | Link |
|------|------|-------------|------|
| Maltego | Graph analysis | Visual link analysis and data mining | [maltego.com](https://www.maltego.com/) |
| SpiderFoot | Automated OSINT | Modular reconnaissance automation (100+ data sources) | [GitHub](https://github.com/smicallef/spiderfoot) |
| Recon-ng | Framework | Modular web reconnaissance framework | [GitHub](https://github.com/lanmaster53/recon-ng) |
| theHarvester | Harvesting | Email, subdomain, and name gathering | [GitHub](https://github.com/laramies/theHarvester) |
| OSINT Framework | Directory | Categorized collection of OSINT tools and resources | [osintframework.com](https://osintframework.com/) |
| Hunchly | Evidence capture | Web investigation capture and reporting | [hunch.ly](https://www.hunch.ly/) |

## Prerequisites

- No prior OSINT experience required
- Basic familiarity with web browsers, DNS, and HTTP
- Python 3.11+ (for the lab exercise)

## Further Reading

- Bazzell, Michael. *OSINT Techniques: Resources for Uncovering Online Information* (10th Edition)
- Hassan, Nihad & Hijazi, Rami. *Open Source Intelligence Methods and Tools*
- NATO Open Source Intelligence Handbook (2001) — foundational doctrine
- [Bellingcat's Online Investigation Toolkit](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/)
- [SANS FOR498: Digital Acquisition and Rapid Triage](https://www.sans.org/cyber-security-courses/digital-acquisition-rapid-triage/)

## Lab

[Build an OSINT Collection Plan](lab/LAB.md) — Create a structured intelligence collection plan for a fictional target organization using the OSINT lifecycle.
