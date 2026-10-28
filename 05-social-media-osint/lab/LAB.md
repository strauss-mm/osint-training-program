# Lab 05: Username and Email OSINT Investigation

**Difficulty:** Intermediate
**Estimated Time:** 90 minutes
**Prerequisites:** Python 3.9+, internet access, modules 01-04 completed

---

## ETHICAL DISCLAIMER

**Only test this tool against your own accounts or accounts for which you have explicit
written permission.** Unauthorized investigation of real individuals is unethical and
potentially illegal under privacy laws including GDPR, CCPA, and computer fraud statutes.
This lab is for educational purposes only.

---

## Objectives

- Enumerate a username across multiple platforms using HTTP status codes
- Generate candidate email addresses from a username
- Produce a structured Markdown profile card
- Understand the limitations and false-positive rates of status-code-based detection

## Setup

```bash
cd /Users/mmstrauss/dev/osint-training-program/05-social-media-osint/lab
pip install -r requirements.txt
```

## Exercise 1: Basic Username Enumeration

Run the script against your own username:

```bash
python username_osint.py --username YOUR_USERNAME
```

Review the output. Note which platforms returned positive results. Verify manually that
the results are accurate by visiting the URLs.

**Question:** Which platforms gave false positives or false negatives? Why might
status-code-based detection be unreliable for some sites?

## Exercise 2: Save and Review a Profile Card

Generate a saved Markdown report:

```bash
python username_osint.py --username YOUR_USERNAME --output profile_report.md
```

Open `profile_report.md` and review the profile card format. Consider what an investigator
could infer from this information alone.

## Exercise 3: Adjust Timeout and Observe Behavior

Test with different timeout values:

```bash
python username_osint.py --username YOUR_USERNAME --timeout 3
python username_osint.py --username YOUR_USERNAME --timeout 15
```

**Question:** How does timeout affect results? Which platforms are slower to respond?

## Exercise 4: Analyze Email Patterns

Review the email pattern section of the output. The script generates candidate email
addresses based on the username.

**Question:** How would you validate whether these email addresses are actually in use?
What tools from the module README could help? (Hint: holehe)

## Exercise 5: OPSEC Discussion

Based on the results, answer these questions:

1. If you were a target, what could an investigator learn from your username alone?
2. Do you use the same username across multiple platforms?
3. What steps would you take to reduce your social media footprint?
4. How does username reuse create correlation risks?

## Challenge Exercises

### Challenge A: Add a New Platform

Add support for checking a platform not currently in the script (e.g., Mastodon, Bluesky,
Stack Overflow, Telegram). You will need to research the URL pattern and expected status
codes for that platform.

### Challenge B: Integrate holehe

Install holehe (`pip install holehe`) and extend the script to check if a generated email
address is registered on common services.

### Challenge C: Rate Limiting Analysis

Modify the script to log response times for each platform. Identify which sites implement
rate limiting and how they signal it (429 status, CAPTCHA redirect, etc.).

## Cleanup

Remove any generated report files:

```bash
rm -f profile_report.md
```

## Key Takeaways

- Status-code-based enumeration is fast but imprecise; many platforms use redirects,
  CAPTCHAs, or JavaScript rendering that defeats simple HTTP checks.
- Username correlation across platforms is a powerful OSINT technique with direct
  implications for personal OPSEC.
- Ethical boundaries must be maintained at all times -- tooling capability does not
  equal authorization.
