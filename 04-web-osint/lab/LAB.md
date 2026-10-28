# Lab: Web Application OSINT

## Objective

Use passive techniques to fingerprint a web application's technology stack, retrieve historical snapshots, extract all linked resources, and compile a structured OSINT report — without active scanning or exploitation.

## Difficulty

Intermediate

## Estimated Time

3 hours

## Prerequisites

- Python 3.11+ with virtual environment
- Internet access (queries public APIs)
- No API keys required (all data sources are free)

## Setup

```bash
cd 04-web-osint/lab
pip install -r requirements.txt
```

## Exercises

### Exercise 1: Basic Technology Fingerprinting

Run the web OSINT script against a well-known target with a rich technology stack.

```bash
# Analyze a public website (use only sites you have permission to scan,
# or public sites that expect automated access like example.com)
python web_osint.py --url https://example.com

# Save the report to a file
python web_osint.py --url https://example.com --output report.json
```

Review the output and answer:

1. What server software is the target running?
2. Which technologies were detected from HTTP headers vs HTML content?
3. Were any security headers present (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`)?
4. What do missing security headers tell you about the application's security posture?

### Exercise 2: Historical Analysis with Wayback Machine

Run the script and examine the Wayback Machine results.

1. How many historical snapshots exist for the target?
2. What is the date range of archived content?
3. Compare the earliest and most recent snapshots — what changed?
4. Were any status codes other than 200 captured? What do 301/302 redirects reveal about infrastructure changes?

### Exercise 3: Link and Resource Extraction

Examine the extracted links and resources from the page.

1. Categorize the extracted links: internal vs external, same-domain vs third-party
2. What JavaScript libraries are loaded? Do version numbers appear in the URLs?
3. Are any CDN domains referenced? What does CDN choice suggest about the organization?
4. Look for patterns in URL structure — do paths suggest a specific framework or CMS?

### Exercise 4: Extend the Technology Detection

The script includes a set of technology fingerprints. Add detection for three additional technologies:

1. **Vue.js** — Look for `vue.js` or `vue.min.js` in script sources, `data-v-` attributes in HTML, or `__vue__` in inline scripts
2. **Cloudflare** — Check for `cf-ray` header, `__cfduid` cookie, or `cloudflare` in server header
3. **Nginx** — Look for `nginx` in server header, default error page patterns

Modify `web_osint.py` to include these patterns and test against appropriate targets.

### Exercise 5: Combining Sources (Advanced)

Using the techniques from this module alongside Modules 02 and 03:

1. Start with a domain from Module 02 results
2. Run the web OSINT script against discovered subdomains
3. Cross-reference technology stacks — are subdomains running different technologies?
4. Check if any discovered JavaScript files reference internal hostnames or API endpoints
5. Write a summary report connecting findings across all three modules

## Key Takeaways

- HTTP headers and HTML content passively reveal significant technology information
- Historical snapshots expose content that was intentionally removed
- Link extraction maps the application's dependency and integration landscape
- Combining multiple passive sources produces a comprehensive picture without triggering alerts
- Technology fingerprinting informs vulnerability research — knowing the stack narrows the CVE search space

## Clean Up

Remove any generated report files:

```bash
rm -f report.json
```
