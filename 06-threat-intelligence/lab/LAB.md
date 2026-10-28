# Lab 06: Multi-Source Threat Intelligence Lookup

**Difficulty:** Intermediate
**Estimated Time:** 120 minutes
**Prerequisites:** Python 3.9+, AbuseIPDB API key (free), VirusTotal API key (free)

---

## Objectives

- Query multiple threat intelligence APIs from a single tool
- Auto-detect indicator types and route queries appropriately
- Map findings to MITRE ATT&CK techniques
- Generate structured threat intelligence briefs
- Handle API failures gracefully

## Setup

### 1. Install Dependencies

```bash
cd /Users/mmstrauss/dev/osint-training-program/06-threat-intelligence/lab
pip install -r requirements.txt
```

### 2. Obtain API Keys

- **AbuseIPDB:** Register at https://www.abuseipdb.com/ and generate a free API key
  (1,000 checks/day on free tier).
- **VirusTotal:** Register at https://www.virustotal.com/ and get your API key from
  the profile page (4 requests/minute on free tier).

### 3. Set Environment Variables

```bash
export ABUSEIPDB_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
```

## Exercise 1: Hash Lookup (EICAR Test File)

The EICAR test file is a standard anti-malware test string. Its SHA-256 hash is universally
detected as malicious by security vendors:

```bash
python threat_intel_lookup.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

**Questions:**
- How many vendors detected this hash?
- What ATT&CK techniques were mapped?
- What risk level was assigned?

## Exercise 2: IP Reputation Check

Query a known-reported IP address (check AbuseIPDB's "recently reported" page for a
current example, or use a test IP you control):

```bash
python threat_intel_lookup.py 185.220.101.1 --verbose
```

**Questions:**
- What is the abuse confidence score?
- How many reports has this IP received?
- What country is the IP geolocated to?

## Exercise 3: Domain Analysis

Query a well-known domain:

```bash
python threat_intel_lookup.py example.com
```

Then try a known-malicious domain from VirusTotal's documentation or a threat report.

**Question:** How does the output differ between benign and malicious domains?

## Exercise 4: Save a Threat Brief

Generate a saved Markdown report:

```bash
python threat_intel_lookup.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f --output threat_brief.md
```

Review the report structure. This format can be used for sharing intelligence with
stakeholders or feeding into a TIP.

## Exercise 5: Graceful Degradation

Test the script without API keys to verify it handles missing credentials:

```bash
unset ABUSEIPDB_API_KEY
unset VIRUSTOTAL_API_KEY
python threat_intel_lookup.py 8.8.8.8
```

The script should warn about missing keys and still produce a partial report.

## Challenge Exercises

### Challenge A: Add AlienVault OTX

Extend the script to query the AlienVault OTX API
(https://otx.alienvault.com/api/v1/indicators/) for additional context. The OTX API is
free and does not require authentication for basic queries.

### Challenge B: STIX Output

Using the `stix2` library, convert the threat brief output into a STIX 2.1 bundle
containing Indicator and Relationship objects.

### Challenge C: Bulk Lookup

Modify the script to accept a file of indicators (one per line) and process them
sequentially with rate limiting, producing a summary report.

## Cleanup

```bash
rm -f threat_brief.md
```

## Key Takeaways

- No single threat intelligence source is authoritative; correlation across multiple
  sources increases confidence.
- ATT&CK mapping transforms raw indicators into actionable context for defenders.
- Free-tier API keys are sufficient for learning and small-scale investigations; production
  use requires commercial licenses or self-hosted platforms like MISP.
