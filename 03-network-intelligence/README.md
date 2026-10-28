# Module 03: Network Intelligence

Mapping the internet's infrastructure through passive data sources and targeted queries -- IP geolocation, ASN ownership, BGP routing, and internet-wide scan databases -- to build network-level intelligence without touching the target.

## Learning Objectives

- Query IP intelligence APIs for geolocation, ASN ownership, and hosting provider data
- Analyze BGP routing to understand network topology and peering relationships
- Use internet-wide scanning databases (Shodan, Censys) to enumerate services passively
- Distinguish passive network intelligence from active scanning and understand legal boundaries
- Filter noise and false positives from large-scale internet scan data
- Correlate multiple network data sources into a coherent intelligence picture

## Key Concepts

### IP Intelligence and Geolocation

IP geolocation maps addresses to physical locations, ISPs, and organizations. Accuracy varies -- city-level is typical for broadband, datacenter IPs resolve to facility locations. ASN (Autonomous System Number) analysis reveals the organization operating the network, upstream providers, and peering relationships.

### Internet-Wide Scanning Databases

Services like Shodan and Censys continuously scan the IPv4 space and index open ports, banners, TLS certificates, and protocol responses. These databases let you query what a target exposes to the internet without sending a single packet yourself -- pure passive intelligence.

### Passive vs Active Network Intelligence

| Approach | Method | Detection Risk | Legal Risk |
|----------|--------|---------------|------------|
| Passive | Query existing databases (Shodan, BGPView, IPinfo) | None | Minimal |
| Semi-passive | DNS lookups, WHOIS, certificate queries | Very low | Low |
| Active | Port scanning, banner grabbing, service probing | High | Requires authorization |

Passive sources are the foundation. Active scanning is only performed with explicit written authorization.

### Noise Filtering

Internet-wide scan data contains noise -- scanners, bots, and misconfigured devices. GreyNoise classifies IPs as "benign scanner," "malicious," or "unknown," helping separate real targets from internet background radiation.

## Tool Reference

| Tool | Purpose | Type | Link |
|------|---------|------|------|
| Shodan | Internet device search engine; indexes banners, ports, certs | Passive DB | [shodan.io](https://www.shodan.io/) / [API docs](https://developer.shodan.io/) |
| Censys | Internet-wide scanning and certificate search | Passive DB | [censys.io](https://censys.io/) / [API docs](https://search.censys.io/api) |
| GreyNoise | Internet noise classification; identifies scanners and bots | Noise filter | [greynoise.io](https://www.greynoise.io/) / [API docs](https://docs.greynoise.io/) |
| IPinfo | IP geolocation, ASN, hosting detection, privacy detection | IP intel | [ipinfo.io](https://ipinfo.io/) / [API docs](https://ipinfo.io/developers) |
| BGPView | BGP routing data, ASN details, prefix lookups | Routing intel | [bgpview.io](https://bgpview.io/) |
| BGPStream | Real-time and historical BGP data from RouteViews and RIPE RIS | Routing intel | [bgpstream.caida.org](https://bgpstream.caida.org/) |
| Masscan | Fastest port scanner; scans entire internet in minutes | Active scanner | [GitHub](https://github.com/robertdavidgraham/masscan) |
| Nmap | Network scanner with NSE scripting for service identification | Active scanner | [nmap.org](https://nmap.org/) |

## Lab

| Lab | Focus | Difficulty | Est. Time |
|-----|-------|-----------|-----------|
| [Network Intelligence Report](lab/) | IP/CIDR recon with IPinfo, Shodan, reverse DNS | Intermediate | 3 hours |

## Prerequisites

- Completion of Module 02 (Domain & Infrastructure Reconnaissance)
- Networking fundamentals: IP addressing, CIDR notation, DNS, TCP/IP
- Python 3.11+
- Free API keys: [IPinfo](https://ipinfo.io/signup) (50k requests/month), [Shodan](https://account.shodan.io/register) (limited free tier)

## Further Reading

- [Shodan Dorks -- the Shodan Search Query Guide](https://github.com/jakejarvis/awesome-shodan-queries)
- [BGP Routing Security (NIST SP 800-189)](https://csrc.nist.gov/publications/detail/sp/800-189/final)
- [IPinfo Academy -- IP Geolocation Accuracy](https://ipinfo.io/accuracy)
- [GreyNoise Visualizer](https://viz.greynoise.io/) -- explore internet noise in real time
- [Masscan Usage Guide](https://github.com/robertdavidgraham/masscan/blob/master/doc/bot.md)
