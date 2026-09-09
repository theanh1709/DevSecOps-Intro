# Lab 6.2 — Submission

## Task 2: Custom Checkov Policy

### Policy file (paste full contents of labs/lab6/policies/my-custom-policy.yaml)

```yaml
metadata:
  id: "CKV2_CUSTOM_1"
  name: "Ensure RDS instances enable IAM database authentication"
  category: "IAM"
  severity: "HIGH"

definition:
  and:
    - cond_type: "filter"
      attribute: "resource_type"
      operator: "within"
      value:
        - "aws_db_instance"

    - cond_type: "attribute"
      resource_types:
        - "aws_db_instance"
      attribute: "iam_database_authentication_enabled"
      operator: "equals"
      value: true
```

### Rule fires

Output of the 6.2.4 jq (must show ≥1 failed check whose `check_id` starts with `CKV2_CUSTOM_`):

```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure RDS instances enable IAM database authentication",
    "result": "FAILED",
    "resource": "aws_db_instance.unencrypted_db",
    "file_path": "/database.tf"
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure RDS instances enable IAM database authentication",
    "result": "FAILED",
    "resource": "aws_db_instance.weak_db",
    "file_path": "/database.tf"
  }
]
```

### Why this rule matters

2-3 sentences: what real-world incident or compliance requirement does your custom policy address?
(References to specific incidents or NIST/CIS controls strengthen the answer.)

Requiring IAM database authentication for Amazon RDS reduces the risk of database compromise caused by leaked, hard-coded, or long-lived passwords by replacing them with short-lived, centrally managed authentication tokens. This policy supports NIST SP 800-53 controls IA-2 (Identification and Authentication), IA-5 (Authenticator Management), and AC-2 (Account Management), while improving credential rotation, revocation, and auditability.

PR checklist body:

```text
- [x] Task 2 — Custom Checkov policy demonstrably firing on the vulnerable sample
```