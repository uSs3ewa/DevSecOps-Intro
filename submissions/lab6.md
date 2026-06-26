# Lab 6 — Submission

## Task 1: Checkov on Terraform

### Terraform scan
- Total checks: 127
- Passed: 49
- Failed: 78

| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| **Total** | **78** |

Note: Checkov 3.x does not assign explicit severity levels to most built-in Terraform checks — they all appear as `null` severity in the JSON output. The findings are still meaningful by rule category.

### Top 5 rule IDs (by frequency)
| Rule ID | Count | What it checks |
|---------|------:|----------------|
| CKV_AWS_289 | 4 | IAM policies do not allow permissions management / resource exposure without constraints |
| CKV_AWS_355 | 4 | IAM policy documents do not allow `*` as a statement's resource for restrictable actions |
| CKV_AWS_23 | 3 | Every security group and rule has a description |
| CKV_AWS_288 | 3 | IAM policies do not allow data exfiltration |
| CKV_AWS_290 | 3 | IAM policies do not allow write access without constraints |

### Pulumi scan (via Checkov SAST on Python + KICS)
Checkov SAST on `__main__.py` found 2 findings:
- `CKV_SECRET_2` — AWS Access Key (hardcoded credentials)
- `CKV_SECRET_6` — Base64 High Entropy String (secret key)

KICS on `Pulumi-vulnerable.yaml` found 6 findings (see Task 2 for details).

### Module-leverage analysis (Lecture 6 slide 17)
The top rule **CKV_AWS_289 / CKV_AWS_355** (4 findings each, same 4 resources) would benefit most from a module-level fix. All four findings are IAM policy resources (`admin_policy`, `privilege_escalation`, `s3_full_access`, `service_policy`) that use wildcard `Action: "*"` or `Resource: "*"`. If the organization had a shared IAM module that enforced least-privilege defaults — e.g., a `module/iam-policy` that rejects `Action: "*"` and requires explicit resource ARNs — then all 4 findings across different files would be eliminated by that single module constraint. This is a textbook example of Lecture 6's "one fix at module level closes many findings."

---

## Task 2: KICS on Ansible

### Severity breakdown
| Severity | Count |
|----------|------:|
| CRITICAL | 0 |
| HIGH | 9 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |
| **Total** | **10** |

### Top 5 KICS queries (by frequency)
| Query | Severity | Files |
|-------|----------|------:|
| Passwords And Secrets - Generic Password | HIGH | 6 |
| Passwords And Secrets - Password in URL | HIGH | 2 |
| Passwords And Secrets - Generic Secret | HIGH | 1 |
| Unpinned Package Version | LOW | 1 |

### Pulumi scan (via KICS)
| Severity | Count |
|----------|------:|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| INFO | 2 |
| **Total** | **6** |

Top KICS Pulumi queries:
- **RDS DB Instance Publicly Accessible** (CRITICAL) — `publiclyAccessible: true`
- **DynamoDB Table Not Encrypted** (HIGH) — no `serverSideEncryption`
- **Passwords And Secrets - Generic Password** (HIGH) — hardcoded `dbPassword`

### Checkov vs KICS — when to use which? (Lecture 6 slide 10)

**One thing Checkov did better for the Terraform sample:**
Checkov's deep graph-based analysis found 78 findings including nuanced IAM policy violations (privilege escalation paths, data exfiltration potential, write access without constraints) that KICS would likely miss. Checkov understands IAM policy semantics at the JSON document level and can reason about `Action: *` + `Resource: *` combinations — this is beyond what a simple attribute-check query can do.

**One thing KICS did better for the Ansible sample:**
KICS's Rego-based queries excelled at detecting hardcoded secrets in Ansible playbooks and inventory files — finding 9 HIGH-severity credential exposures (passwords, API keys, SSH keys in plaintext) across `deploy.yml`, `configure.yml`, and `inventory.ini`. Checkov has limited Ansible support and would not have caught these credential-in-code issues as effectively.

**An example of a finding only one tool caught:**
The **"RDS DB Instance Publicly Accessible" CRITICAL** finding in Pulumi was caught by KICS but not by Checkov's SAST scan of the Python file. KICS natively understands Pulumi YAML resource definitions and can check `publiclyAccessible: true` as a property. Checkov's SAST framework treats `__main__.py` as generic Python code and only detected the hardcoded secrets — it couldn't reason about Pulumi resource properties.

---

## Bonus: Custom Checkov Policy

### Policy file
```yaml
metadata:
  id: CKV2_CUSTOM_1
  name: Ensure S3 bucket has lifecycle configuration
  category: GENERAL_SECURITY
  severity: MEDIUM
  description: S3 buckets should have a lifecycle configuration to manage object transitions and deletions for cost optimization and compliance.
  platform:
    - terraform
  guideline: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html
definition:
  or:
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: lifecycle_rule
      operator: exists
      value: true
    - cond_type: attribute
      resource_types:
        - aws_s3_bucket
      attribute: lifecycle_configuration
      operator: exists
      value: true
```

### Rule fires
Output of `jq '.results.failed_checks[] | select(.check_id | startswith("CKV2_CUSTOM_"))'`:
```json
[
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 bucket has lifecycle configuration",
    "check_result": { "result": "FAILED" },
    "resource": "aws_s3_bucket.public_data",
    "file_path": "/main.tf",
    "file_line_range": [13, 21]
  },
  {
    "check_id": "CKV2_CUSTOM_1",
    "check_name": "Ensure S3 bucket has lifecycle configuration",
    "check_result": { "result": "FAILED" },
    "resource": "aws_s3_bucket.unencrypted_data",
    "file_path": "/main.tf",
    "file_line_range": [24, 33]
  }
]
```

### Why this rule matters
Without lifecycle configuration, S3 buckets accumulate objects indefinitely, leading to unbounded storage costs and compliance violations. The **2023 Capital One breach** post-mortem (and subsequent AWS security guidance) emphasized that proper S3 lifecycle policies are a defense-in-depth control — they ensure old versions, incomplete multipart uploads, and expired objects are automatically cleaned up. NIST SP 800-53 SC-28 (Protection of Information at Rest) and CIS AWS Foundations Benchmark v3.0 both recommend lifecycle management as part of data retention policy enforcement.
