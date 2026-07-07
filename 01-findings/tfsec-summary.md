# TFSec Scan Summary – TerraGoat Multi-Cloud

**Tool:** TFSec (Aqua Security)  
**Scan Date:** 2026-07-07  
**Raw Output Files:** `tfsec-aws.json` · `tfsec-azure.json` · `tfsec-gcp.json`

---

## What Is TFSec?

TFSec is a static analysis security scanner for Terraform, now maintained by Aqua Security. It uses the **AVD (Aqua Vulnerability Database)** rule set with proper CRITICAL/HIGH/MEDIUM/LOW severity ratings — making it the best tool for **prioritizing** which issues need immediate action versus which can wait.

**Why TFSec was chosen:** Unlike Checkov (which doesn't assign severity without a Bridgecrew account), TFSec gives native severity ratings without any API key. This lets us immediately sort findings by urgency and build a remediation roadmap.

---

## Results Overview

```
           CRITICAL   HIGH    MEDIUM   LOW    TOTAL
AWS           9        72       21      17     119
Azure         8         6       53      19      86
GCP           2        12       15      12      41
─────────────────────────────────────────────────────
TOTAL        19        90       89      48     246
```

**19 CRITICAL findings across 3 clouds** — each one represents a directly exploitable condition requiring immediate remediation.

---

## CRITICAL Findings (19 Total)

### AWS CRITICAL (9 findings)

| Rule ID | Description | File | Why Critical |
|---------|-------------|------|-------------|
| AVD-AWS-0104 | Security group allows unrestricted egress to all IPs | ec2.tf | Data exfiltration path — attacker can send data anywhere |
| AVD-AWS-0104 | Security group allows unrestricted egress | db-app.tf | Same — RDS security group also allows all outbound |
| AVD-AWS-0107 | Security group ingress from public internet | ec2.tf (HTTP) | Web server exposed — any vulnerability = remote exploit |
| AVD-AWS-0107 | Security group ingress from public internet | ec2.tf (SSH) | SSH exposed to entire internet — brute force target |
| AVD-AWS-0029 | Sensitive data in EC2 user data (AWS Access Key) | ec2.tf | Credential theft via metadata service or console |
| AVD-AWS-0104 | DB security group allows unrestricted egress | db-app.tf | MySQL server can initiate connections anywhere |
| AVD-AWS-0107 | Security group allows all ingress | db-app.tf | MySQL port 3306 may be internet-accessible |
| AVD-AWS-0104 | EKS security group unrestricted egress | eks.tf | Kubernetes nodes can exfiltrate data anywhere |
| AVD-AWS-0107 | EKS security group unrestricted ingress | eks.tf | Kubernetes API surface exposed |

### Azure CRITICAL (8 findings)

| Rule ID | Description | File | Why Critical |
|---------|-------------|------|-------------|
| AVD-AZU-0041 | AKS API server not restricted to authorized IPs | aks.tf | Kubernetes API is internet-accessible — anyone can attempt auth |
| AVD-AZU-0013 | Key Vault network ACL allows all traffic | key_vault.tf | All keys/secrets accessible from any IP — no network boundary |
| AVD-AZU-0048 | NSG allows RDP (3389) from `*` | networking.tf | Primary ransomware initial access vector |
| AVD-AZU-0047 | NSG allows SSH (22) from `*` | networking.tf | Automated brute force in seconds of deployment |
| AVD-AZU-0047 | NSG allows additional unrestricted ingress | networking.tf | Additional attack surface |
| AVD-AZU-0041 | AKS API no network restriction | aks.tf | Kubernetes cluster control plane internet-exposed |
| AVD-AZU-0013 | Key Vault no default deny | key_vault.tf | Secrets accessible without network restriction |
| AVD-AZU-0047 | NSG rule allows unrestricted ingress | networking.tf | Full lateral movement potential |

### GCP CRITICAL (2 findings)

| Rule ID | Description | File | Why Critical |
|---------|-------------|------|-------------|
| AVD-GCP-0046 | BigQuery dataset open to all authenticated GCP users | big_data.tf | Any Gmail user can read your entire data warehouse |
| AVD-GCP-0027 | Firewall allows ingress from all IPs | networks.tf | GCP compute instances exposed to internet scans |

---

## HIGH Findings – AWS (72 findings, top 15)

| Rule ID | Description | File |
|---------|-------------|------|
| AVD-AWS-0131 | Root block device not encrypted | ec2.tf |
| AVD-AWS-0131 | Root block device not encrypted | db-app.tf |
| AVD-AWS-0026 | EBS volume not encrypted | ec2.tf |
| AVD-AWS-0028 | IMDS v1 enabled (no session token required) | ec2.tf |
| AVD-AWS-0028 | IMDS v1 enabled | db-app.tf |
| AVD-AWS-0086 | RDS not encrypted at rest | db-app.tf |
| AVD-AWS-0080 | RDS publicly accessible | db-app.tf |
| AVD-AWS-0077 | RDS backup retention too short | db-app.tf, rds.tf (×8) |
| AVD-AWS-0052 | S3 bucket not encrypted | s3.tf (multiple) |
| AVD-AWS-0089 | S3 access logging disabled | s3.tf (multiple) |
| AVD-AWS-0090 | S3 versioning disabled | s3.tf |
| AVD-AWS-0132 | ECR no image scanning | ecr.tf |
| AVD-AWS-0030 | EKS public API endpoint enabled | eks.tf |
| AVD-AWS-0113 | Lambda function not encrypted with CMK | lambda.tf |
| AVD-AWS-0066 | CloudTrail not enabled | (missing resource) |

> **Why IMDS v1 matters:** EC2 Instance Metadata Service v1 is accessible from any process on the instance using a simple `curl http://169.254.169.254/latest/meta-data/`. No token required. An attacker who gets code execution (e.g., via SSRF) can steal the IAM role credentials. IMDSv2 requires a PUT request with a session token first — SSRF attacks cannot use PUT.

---

## HIGH Findings – Azure (6 findings)

| Rule ID | Description | File |
|---------|-------------|------|
| AVD-AZU-0006 | App Service TLS version < 1.2 | app_service.tf |
| AVD-AZU-0039 | VM password authentication enabled (not SSH key only) | instance.tf |
| AVD-AZU-0038 | Managed disk not encrypted | storage.tf |
| AVD-AZU-0043 | AKS network policy not configured | aks.tf |
| AVD-AZU-0042 | AKS RBAC disabled | aks.tf |
| AVD-AZU-0010 | Storage account allows trusted Microsoft services bypass | storage.tf |

---

## HIGH Findings – GCP (12 findings)

| Rule ID | Description | File |
|---------|-------------|------|
| AVD-GCP-0043 | GCE instance has IP forwarding enabled | instances.tf |
| AVD-GCP-0031 | GCE instance has public IP address | instances.tf |
| AVD-GCP-0047 | GKE pod security policy not enforced | gke.tf |
| AVD-GCP-0048 | GKE legacy metadata endpoints enabled | gke.tf |
| AVD-GCP-0053 | GKE control plane exposed to public internet | gke.tf |
| AVD-GCP-0015 | Cloud SQL SSL not enforced | big_data.tf |
| AVD-GCP-0017 | Cloud SQL instance publicly exposed | big_data.tf |
| AVD-GCP-0001 | GCS bucket accessible to all users | gcs.tf |
| AVD-GCP-0024 | Cloud SQL automated backups disabled | big_data.tf |
| AVD-GCP-0049 | GKE IP aliasing disabled | gke.tf |
| AVD-GCP-0023 | BigQuery dataset world-readable | big_data.tf |
| AVD-GCP-0016 | Cloud SQL log_connections disabled | big_data.tf |

---

## MEDIUM Findings Summary (89 total)

Key medium findings include:
- **AWS:** VPC Flow Logs disabled (eks.tf, ec2.tf) — `AVD-AWS-0178`
- **AWS:** EKS control plane logging not enabled (5 log types missing) — `AVD-AWS-0038`
- **AWS:** Neptune cluster encryption off — `neptune.tf`
- **Azure:** App Service authentication disabled (2 instances) — `AVD-AZU-0003`
- **Azure:** SQL server threat detection disabled — `AVD-AZU-0028`
- **Azure:** AKS OMS monitoring agent not enabled — `AVD-AZU-0040`
- **GCP:** GCE instances missing Shielded VM options — `AVD-GCP-0041`, `AVD-GCP-0045`
- **GCP:** GCE serial port enabled (allows debug access) — `AVD-GCP-0032`
- **GCP:** Subnetwork VPC flow logs disabled — `AVD-GCP-0029`

---

## Understanding the AVD Rule ID Format

`AVD-AWS-0029` breaks down as:
- `AVD` = Aqua Vulnerability Database
- `AWS` = Cloud provider (AWS/AZU/GCP)
- `0029` = Rule number in Aqua's library

Full rule details: `https://avd.aquasec.com/misconfig/avd-aws-0029`

---

## Interview Talking Point

> *"TFSec gave me the most actionable severity breakdown. 19 CRITICAL findings across three clouds. I prioritized these first because CRITICAL in TFSec means exploitable without additional prerequisites — for example, AVD-AWS-0029 (hardcoded AWS key in user_data) requires zero additional steps for an attacker: they simply read the metadata endpoint and get working credentials. HIGH findings require one more step — like needing network access to the RDS port — but are still urgent. I used this breakdown to build the remediation roadmap."*
