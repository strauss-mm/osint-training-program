# Module 06: Threat Intelligence

## Overview

This module covers the collection, analysis, and operationalization of cyber threat
intelligence (CTI). You will learn to query multiple threat intelligence sources, correlate
indicators of compromise (IoCs), and map findings to the MITRE ATT&CK framework to produce
actionable intelligence briefs.

## Learning Objectives

- Understand the threat intelligence lifecycle (direction, collection, processing, analysis, dissemination)
- Query public and commercial TI APIs programmatically
- Auto-detect indicator types (IP, domain, file hash)
- Map findings to MITRE ATT&CK techniques
- Produce structured threat intelligence briefs

## Prerequisites

- Python 3.9+
- Modules 01-05 completed
- Free API keys: AbuseIPDB (https://www.abuseipdb.com/), VirusTotal (https://www.virustotal.com/)

## Key Concepts

| Concept | Description |
|---------|-------------|
| Intelligence lifecycle | Direction, collection, processing, analysis, dissemination, feedback |
| Indicators of compromise | Observable artifacts: IPs, domains, hashes, URLs, email addresses |
| TTP mapping | Linking indicators to adversary tactics, techniques, and procedures |
| Diamond Model | Intrusion analysis: adversary, capability, infrastructure, victim |
| Cyber Kill Chain | Lockheed Martin's 7-phase attack model |
| STIX/TAXII | Standards for structured threat information exchange |
| Confidence scoring | Rating the reliability and accuracy of intelligence |

## Tool Reference

| Tool | Description | Link |
|------|-------------|------|
| MISP | Open-source threat intelligence sharing platform | https://github.com/MISP/MISP |
| OpenCTI | Cyber threat intelligence platform | https://github.com/OpenCTI-Platform/opencti |
| Yeti | Organize observables, IoCs, TTPs, and knowledge | https://github.com/yeti-platform/yeti |
| AbuseIPDB | Community-driven IP reputation database | https://docs.abuseipdb.com/ |
| VirusTotal | File, URL, IP, and domain analysis service | https://docs.virustotal.com/reference/overview |
| AlienVault OTX | Open Threat Exchange community intelligence | https://otx.alienvault.com/api |
| Pulsedive | Threat intelligence search and enrichment | https://pulsedive.com/api/ |
| ATT&CK Navigator | Visualization tool for MITRE ATT&CK matrices | https://github.com/mitre-attack/attack-navigator |
| Sigma | Generic detection rule format for SIEM systems | https://github.com/SigmaHQ/sigma |
| python-stix2 | Python library for STIX 2.x content | https://github.com/oasis-open/cti-python-stix2 |

## Further Reading

- MITRE ATT&CK: https://attack.mitre.org/
- FIRST Traffic Light Protocol (TLP): https://www.first.org/tlp/
- NIST SP 800-150: Guide to Cyber Threat Information Sharing
- Recorded Future "What is Threat Intelligence?" guide
- SANS FOR578: Cyber Threat Intelligence course

## Lab

Proceed to [lab/LAB.md](lab/LAB.md) for the hands-on exercise.
