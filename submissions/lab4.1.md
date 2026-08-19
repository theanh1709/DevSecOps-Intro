# Lab 4.1 — Submission

## Task 1: Syft + Grype on Juice Shop

### SBOM stats

- `juice-shop.cdx.json` component count: 3069 <jq '.components | length' output>
- `juice-shop.cdx.json` size: 3436407 <ls output>
- `juice-shop.spdx.json` component count: 909 <jq '.packages | length' output>

### Grype severity breakdown (paste table or JSON)

| Severity | Count |
|----------|------:|
| Critical | 12 |
| High | 70 |
| Medium | 11 |
| Low | 55 |
| Negligible | 7 |
| **Total** | 155 |

### Top 10 CVEs (paste from jq output)

| CVE | Severity | Package | Installed | Fix |
|-----|----------|---------|-----------|-----|
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.1.0 | 4.2.2 |
| GHSA-c7hr-j4mj-j2w6 | Critical | jsonwebtoken | 0.4.0 | 4.2.2 |
| GHSA-jf85-cpcp-j695 | Critical | lodash | 2.4.2 | 4.17.12 |
| GHSA-mp2f-45pm-3cg9 | Critical | decompress | 4.2.1 |  |
| GHSA-xwcq-pm8m-c4vf | Critical | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-5450 | Critical | libc6 | 2.41-12+deb13u2 |  |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 4.4.19 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 6.2.1 | 7.5.19 |
| GHSA-23hp-3jrh-7fpw | Critical | tar | 7.5.15 | 7.5.19 |
| CVE-2026-34182 | Critical | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Fix-available rate

Out of the top 10 CVEs, how many have a fix available? What does that say about your
patch cadence priorities? (2-3 sentences. Reference Lecture 4's triage shortcut:
*sort by fix-available AND severity ≥ HIGH first*.)

- Out of the top 10 CVEs, 8 have a fix available and 2 do not
- Since all listed items are Critical, patch cadence should prioritize the 8 fix-available Critical issues first

## How to Submit

```bash
# Commit the SBOM files (so Lab 8 can use them) but NOT the scan output files (too large, regenerable)
git add labs/lab4/juice-shop.cdx.json
git add labs/lab4/juice-shop.spdx.json
git add submissions/lab4.1.md
git commit -m "feat(lab4.1): juice-shop SBOMs + Grype CVE analysis"
git push -u origin feature/lab4.1
```

> **Do NOT commit** `labs/lab4/grype-from-sbom.*` — they're regeneratable and large. Add them to your fork's `.gitignore` if helpful. The submission paste-in is the evidence.

PR checklist body:

```text
- [x] Task 1 — Syft SBOMs + Grype scan + top-10 CVE analysis
```