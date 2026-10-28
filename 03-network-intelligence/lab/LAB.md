# Lab 03: Network Intelligence Report

## Objective

Build a network intelligence report for a target IP address or CIDR range using passive data sources. You will query IP intelligence APIs, check internet-wide scan databases, perform reverse DNS lookups, and produce a structured Markdown report -- all without sending a single probe packet to the target.

## Difficulty

Intermediate

## Estimated Time

3 hours

## What You Will Build

A Python-based network intelligence tool that:

1. Queries IPinfo for geolocation, ASN, and organization data
2. Checks Shodan for open ports and service banners (when API key is available)
3. Performs reverse DNS lookups for hostname discovery
4. Aggregates findings into a structured Markdown report

## Setup

```bash
cd 03-network-intelligence/lab
pip install -r requirements.txt

# Optional: set Shodan API key for enhanced results
export SHODAN_API_KEY="your-key-here"
```

## Running the Tool

```bash
# Basic report for a single IP (uses a safe target -- Cloudflare's public DNS)
python network_intel.py --target 1.1.1.1

# Save report to file
python network_intel.py --target 1.1.1.1 --output report.md

# Query a CIDR range (expands and reports on each IP)
python network_intel.py --target 8.8.8.0/30
```

## Exercises

### Exercise 1: Analyze a Cloud Provider IP

Run the tool against a known cloud provider IP (e.g., `13.107.42.14` -- Microsoft). Analyze the output:

- What ASN owns this IP? What organization?
- What does the hosting flag tell you about the infrastructure?
- How does Shodan data differ from what you expected?

### Exercise 2: Compare Hosting Providers

Run reports for IPs belonging to different hosting providers:

- `151.101.1.140` (Fastly CDN)
- `104.16.132.229` (Cloudflare)
- `52.84.150.11` (AWS CloudFront)

Compare the ASN data, geolocation accuracy, and service fingerprints. What patterns distinguish CDN IPs from origin servers?

### Exercise 3: CIDR Range Analysis

Choose a small CIDR (e.g., `8.8.8.0/29`) and run the tool. Examine:

- How many IPs in the range are active?
- Do they share ASN and organization data?
- What does clustering of services in a CIDR tell you about the target?

### Exercise 4: Extend the Tool

Add one or more of the following capabilities:

1. **GreyNoise integration**: Query the [GreyNoise Community API](https://docs.greynoise.io/docs/using-the-greynoise-community-api) to classify whether the IP is a known scanner or noise source. Add a "Noise Classification" section to the report.

2. **BGPView ASN detail**: Query `https://api.bgpview.io/asn/{asn}` to pull the full list of prefixes announced by the target's ASN. How large is the organization's network footprint?

3. **Historical Shodan data**: Use `shodan host --history` to show how the target's exposed services have changed over time. What does service churn indicate?

### Exercise 5: Threat Assessment

Using the report output from Exercise 1, write a one-page threat assessment that answers:

- What is the target's attack surface based on exposed services?
- Which services present the highest risk (outdated versions, known CVEs)?
- What defensive measures are visible (WAF headers, rate limiting, TLS configuration)?

## Key Takeaways

- Passive network intelligence reveals substantial detail without alerting the target
- IP geolocation is useful for attribution but accuracy varies by IP type
- ASN analysis maps organizational network boundaries and hosting relationships
- Shodan and Censys provide port/service data without active scanning
- Correlating multiple passive sources produces higher-confidence intelligence than any single source alone
