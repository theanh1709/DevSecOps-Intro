# Lab 6.1 — Submission

## Task 1: Checkov on Terraform

### Terraform scan (passed/failed per framework)
| Framework | Passed | Failed |
|-----------|-------:|-------:|
| terraform | 49 | 78 |
| secrets | 0 | 2 |

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | Ensures IAM policies do not allow permission management or resource exposure without appropriate constraints. |
| CKV_AWS_355 | 4 | Ensures IAM policy statements do not use wildcard (`*`) resources for actions that can be restricted to specific resources. |
| CKV_AWS_23 | 3 | Ensures every security group and security group rule has a description.|
| CKV_AWS_288 | 3 | Ensures IAM policies do not grant permissions that could enable unrestricted data exfiltration.  |
| CKV_AWS_290 | 3 | Ensures IAM policies do not allow write access without appropriate resource or condition constraints.  |

### Module-leverage analysis (Lecture 6 slide 17)

The highest-leverage fix would be to update the shared IAM policy module to remove `Resource: "*"` and replace it with specific resource ARNs and appropriate conditions. This single module-level change would address recurring CKV_AWS_355, CKV_AWS_289, and CKV_AWS_290 findings across multiple IAM policies, eliminating far more findings than fixing each policy individually.

---

## How to Submit

```bash
git add submissions/lab6-1.md
git commit -m "feat(lab6.1): Checkov Terraform scan + module-leverage analysis"
git push -u origin feature/lab6.1
```

> **Do NOT commit** `labs/lab6/results/` — scanner output is regeneratable. Submission paste-ins are the evidence.

PR checklist body:

```text
- [x] Task 1 — Checkov on Terraform with top-5 rules and module-leverage analysis
```