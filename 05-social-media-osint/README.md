# Module 05: Social Media and People OSINT

## Overview

This module covers techniques for investigating individuals and organizations through their
social media presence, email accounts, and public online footprints. Social media OSINT is
one of the most widely used intelligence disciplines but also the most ethically sensitive.
Every technique here must be applied within legal and ethical boundaries.

## Learning Objectives

- Enumerate accounts across platforms using username correlation
- Identify email addresses and associated services
- Build a profile card from publicly available information
- Understand the OPSEC implications of social media footprints
- Recognize ethical and legal boundaries of people OSINT

## Prerequisites

- Python 3.9+
- Modules 01-04 completed
- Familiarity with HTTP requests and status codes

## Key Concepts

| Concept | Description |
|---------|-------------|
| Username correlation | Searching for the same handle across multiple platforms |
| Email OSINT | Discovering which services an email is registered on |
| Social footprint mapping | Building a unified view of a target's online presence |
| OPSEC awareness | Understanding what metadata you expose about yourself |
| Sock puppet management | Creating and maintaining research accounts safely |
| Platform-specific behaviors | Each site handles 404s, redirects, and auth differently |

## Tool Reference

| Tool | Description | Link |
|------|-------------|------|
| Sherlock | Username search across 400+ social networks | https://github.com/sherlock-project/sherlock |
| Maigret | Advanced username OSINT (Sherlock fork, 2500+ sites) | https://github.com/soxoj/maigret |
| holehe | Check if an email is registered on various sites | https://github.com/megadose/holehe |
| GHunt | Google account investigation tool | https://github.com/mxrch/GHunt |
| snscrape | Social network scraper (Twitter, Reddit, etc.) | https://github.com/JustAnotherArchivist/snscrape |
| email2phonenumber | Discover phone numbers linked to email accounts | https://github.com/martinvigo/email2phonenumber |
| theHarvester | Email, subdomain, and name harvesting | https://github.com/laramies/theHarvester |
| SpiderFoot | Automated OSINT collection framework | https://github.com/smicallef/spiderfoot |

## Ethical Guidelines

Social media and people OSINT carries significant ethical responsibility:

- **Only investigate accounts you own or have explicit written permission to investigate.**
- Passive collection of public data is generally legal; active interaction (messaging,
  friending, social engineering) crosses ethical and often legal lines.
- Never create fake accounts to deceive individuals.
- Be aware of jurisdiction-specific privacy laws (GDPR, CCPA, etc.).
- Document your methodology and authorization for every investigation.
- If you discover sensitive personal information, handle it with the same care as PII.

## Further Reading

- Bazzell, M. "Open Source Intelligence Techniques" (10th Edition)
- OSINT Framework: https://osintframework.com/
- Bellingcat's Online Investigation Toolkit
- SANS FOR578: Cyber Threat Intelligence
- The Privacy, Data Protection and Cybersecurity Law Review (country-specific regulations)

## Lab

Proceed to [lab/LAB.md](lab/LAB.md) for the hands-on exercise.
