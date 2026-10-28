# Lab 01: Build an OSINT Collection Plan

## Objective

Design a structured OSINT collection plan for a fictional organization, applying the five-phase intelligence lifecycle. Then use the provided Python script to generate a baseline plan template and customize it.

## Difficulty

Beginner | Estimated Time: 90 minutes

## Scenario

**Nexacore Technologies** is a mid-size SaaS company headquartered in Austin, TX. They provide data integration services to enterprise customers and operate a cloud platform at `nexacore.io` (fictional). Your security team has been asked to perform an OSINT assessment as part of a pre-engagement reconnaissance phase.

**Scope**: Passive reconnaissance only. No active scanning, no authentication attempts, no social engineering.

**Deliverable**: A structured collection plan document that a junior analyst could follow independently.

## Exercises

### Exercise 1: Define Collection Requirements

Before opening any tool, answer these questions in writing:

1. What is the objective of this collection? (e.g., attack surface mapping, executive profiling, technology stack identification)
2. What categories of information are relevant? (domains, IPs, emails, employees, technologies, third-party services)
3. What sources will you use for each category?
4. What legal constraints apply? (jurisdiction, data types, PII handling)
5. What is your OPSEC posture? (VPN, sock puppets, browser isolation)

Write your answers in a file called `collection_requirements.md`.

### Exercise 2: Generate a Baseline Plan

Use the provided script to generate a collection plan template:

```bash
python collection_plan_generator.py --domain nexacore.io --org "Nexacore Technologies" --output plan.json

# Also generate a Markdown summary
python collection_plan_generator.py --domain nexacore.io --org "Nexacore Technologies" --format markdown --output plan.md
```

Review the generated plan. It covers standard OSINT phases and data sources.

### Exercise 3: Customize the Plan

The generated template is generic. Tailor it to the scenario:

1. **Remove irrelevant sources** — Which data sources in the template do not apply to a SaaS company?
2. **Add domain-specific sources** — What SaaS-specific sources are missing? (e.g., cloud provider status pages, job postings for tech stack hints, API documentation)
3. **Prioritize** — Rank the collection tasks by expected intelligence value vs. effort
4. **Add acceptance criteria** — For each phase, define what "done" looks like

Save your customized plan as `custom_plan.md`.

### Exercise 4: Map Sources to the Intelligence Lifecycle

Create a table mapping each source from your plan to lifecycle phases:

| Source | Collection | Processing | Analysis | Notes |
|--------|-----------|-----------|----------|-------|
| crt.sh | Query target domain | Parse JSON, extract subdomains | Map to IP ranges | Passive, no auth required |
| LinkedIn | Search company page | Extract employee names/roles | Org chart, tech stack hints | OPSEC: use sock puppet |
| ... | ... | ... | ... | ... |

### Exercise 5: OPSEC Review

Review your plan for OPSEC gaps:

1. Which collection activities could alert the target?
2. Which tools phone home or leak your identity?
3. What metadata would your queries leave in server logs?
4. How would you modify your approach for a covert assessment vs. an overt one?

Document your findings in `opsec_review.md`.

## Expected Deliverables

| File | Description |
|------|-------------|
| `collection_requirements.md` | Answers to Exercise 1 questions |
| `plan.json` | Generated baseline plan (from script) |
| `plan.md` | Markdown version of baseline plan |
| `custom_plan.md` | Customized and prioritized collection plan |
| `opsec_review.md` | OPSEC gap analysis |

## Key Takeaways

- A collection plan is a document, not a tool output — tools execute the plan, they do not replace it
- Time spent in the Planning phase directly reduces noise in Collection and Analysis
- OPSEC is not optional — even passive OSINT leaves traces
- The same target requires different plans depending on objective (red team vs. threat intel vs. due diligence)
- Generic templates are starting points; every engagement needs customization

## Bonus Challenge

Extend `collection_plan_generator.py` to accept a `--profile` flag with values like `red-team`, `threat-intel`, or `due-diligence` that adjusts the generated plan's focus areas and tool recommendations.
