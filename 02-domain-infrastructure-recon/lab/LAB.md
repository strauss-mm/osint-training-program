# Lab: Domain & Infrastructure Reconnaissance

## Objective

Use a purpose-built Python script to perform multi-source domain reconnaissance — querying Certificate Transparency logs, WHOIS databases, and DNS records — then analyze the results to build an infrastructure profile of the target organization.

**Difficulty:** Intermediate
**Estimated Time:** 3 hours
**Target:** Use `example.com` or any domain you own / have authorization to investigate

## Setup

```bash
cd 02-domain-infrastructure-recon/lab
pip install -r requirements.txt
```

## Part 1: Running the Recon Script

Run the domain reconnaissance tool against a target domain:

```bash
# Basic scan with console output
python domain_recon.py --domain example.com

# Save structured report to file
python domain_recon.py --domain example.com --output report.json
```

Review the JSON output. It contains three sections: `certificate_transparency`, `whois`, and `dns_records`.

## Part 2: Analyzing the Results

### Exercise 2.1 — Certificate Transparency Analysis

Examine the `certificate_transparency` section of your report.

1. How many unique subdomains were discovered through CT logs?
2. Are there any subdomains that suggest internal services (e.g., `vpn.*`, `staging.*`, `dev.*`)?
3. Do any certificates use wildcard patterns? What does this tell you about the organization's certificate management?
4. Look at the `not_before` and `not_after` dates. Are there certificates that have expired but reveal historical infrastructure?

### Exercise 2.2 — WHOIS Intelligence

Examine the `whois` section:

1. Who is the registrar? Is privacy protection enabled?
2. When was the domain registered? When does it expire?
3. What name servers are listed? Do they belong to a hosting provider or are they self-hosted?
4. If registrant details are visible, what organizational information can you extract?

### Exercise 2.3 — DNS Record Analysis

Examine the `dns_records` section:

1. What hosting provider(s) are revealed by the A records? Use `whois` on the IPs to confirm.
2. What email infrastructure is indicated by MX records? (Google Workspace, Microsoft 365, self-hosted?)
3. Examine TXT records — are there SPF, DKIM, or DMARC entries? What third-party services are authorized to send email?
4. Do the NS records match the WHOIS name servers? Discrepancies may indicate a recent migration.

## Part 3: Extending the Script

### Exercise 3.1 — Add Reverse DNS Lookups

Modify `domain_recon.py` to perform reverse DNS (PTR) lookups on each A record IP address. This can reveal co-hosted domains and shared infrastructure.

Hint: Use `dns.reversename.from_address()` and query for PTR records.

### Exercise 3.2 — Add Historical Context

The crt.sh API returns certificate issuance dates. Add logic to:
1. Sort certificates by issuance date
2. Identify subdomains that appeared and then disappeared (decommissioned services)
3. Flag recently issued certificates (last 30 days) as potentially new infrastructure

### Exercise 3.3 — Subdomain Takeover Detection

For each CNAME record discovered, check if the target is a known service that may be vulnerable to subdomain takeover (e.g., GitHub Pages, Heroku, AWS S3, Azure). Add a `takeover_risk` field to CNAME results.

Reference: [Can I Take Over XYZ?](https://github.com/EdOverflow/can-i-take-over-xyz)

## Part 4: Correlation Challenge

Using only the output from this script (no additional tools), answer:

1. Build a network diagram showing the relationship between the domain, its subdomains, IP addresses, and mail infrastructure
2. Identify which services are self-hosted vs. third-party SaaS
3. Estimate the organization's cloud provider(s) based on IP ranges and TXT verification records
4. List potential attack surface items that would warrant deeper investigation in a real engagement

## Key Takeaways

- Certificate Transparency is one of the highest-value passive OSINT sources — organizations cannot opt out
- DNS records reveal far more than hostnames: mail providers, cloud services, security policies, and infrastructure architecture
- WHOIS data quality varies significantly by TLD and privacy protection status
- Combining multiple data sources produces a richer picture than any single source alone
