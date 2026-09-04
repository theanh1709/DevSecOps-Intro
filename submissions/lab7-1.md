# Lab 7.1 — Submission

## Task 1: Trivy Image + Config Scan

### Image scan severity breakdown

| Severity | Total | With fix available |
|----------|-------|--------------------|
| Critical | 0 | 8 |
| High | 1 | 1 |
| **Total** | 1 | 9 |

### Top 10 CVEs with fixes

| CVE | Severity | Package | Installed | Fix |
| --- | -------- | ------- | --------- | --- |
| CVE-2023-46233 | CRITICAL | crypto-js | 3.3.0 | 4.2.0 |
| CVE-2026-71851 | CRITICAL | crypto-js | 3.3.0 | 4.0.0 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.1.0 | 4.2.2 |
| CVE-2015-9235 | CRITICAL | jsonwebtoken | 0.4.0 | 4.2.2 |
| CVE-2019-10744 | CRITICAL | lodash | 2.4.2 | 4.17.12 |
| CVE-2026-59873 | CRITICAL | tar | 4.4.19 | 7.5.19 |
| CVE-2026-59873 | CRITICAL | tar | 6.2.1 | 7.5.19 |
| CVE-2026-59873 | CRITICAL | tar | 7.5.15 | 7.5.19 |
| CVE-2026-14456 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.7-1~deb13u2 |
| CVE-2026-45447 | HIGH | libssl3t64 | 3.5.5-1~deb13u2 | 3.5.6-1~deb13u2 |

### Compared to Lab 4's Grype scan
Look back at your Lab 4 Grype results on the same image. Pick **two CVEs**:

1. One that BOTH Grype and Trivy found

**CVE found by both Grype and Trivy: `CVE-2019-10744` (`lodash`)**

Both Grype and Trivy found this CVE because `lodash@2.4.2` is clearly present in the Juice Shop Node.js dependency tree, and this is an older, well-known vulnerability with stable records in GHSA/NVD. Trivy reports it as `CRITICAL`; Grype may show slightly different scoring or metadata, but that difference is mostly from severity/EPSS enrichment rather than package detection.

2. One that ONE tool found and the OTHER missed
For each: explain why the tools differ (DB freshness? Different package matching?
EPSS scoring? Lecture 7 + Lecture 4 give context.) (2-3 sentences per CVE.)

**CVE found by Trivy but missed by Grype: `CVE-2026-73566` (`tar`)**

Trivy found `CVE-2026-73566` in multiple `tar` packages, including `tar@4.4.19`, `tar@6.2.1`, and `tar@7.5.15`, with the fixed version listed as `7.5.21`. If Grype missed it in Lab 4, the likely reason is database freshness: this CVE was published on `2026-08-13`, while the Trivy scan was created on `2026-09-04`, so Trivy may have had a newer GHSA/advisory database. Another possible reason is different package matching, since Trivy may detect nested npm dependencies and map them to GHSA advisories differently than Grype.

---

## How to Submit

```bash
git add submissions/lab7.1.md
git commit -m "feat(lab7.1): trivy image + config scan + grype comparison"
git push -u origin feature/lab7.1
```

PR checklist body:

```text
- [x] Task 1 — Trivy image + config scans + Grype comparison
```

---
