# Trivy Scan Summary – TerraGoat Multi-Cloud

**Tool:** Trivy (Aqua Security)  
**Scan Date:** 2026-07-07  
**Raw Output Files:** `trivy-aws.json` · `trivy-azure.json` · `trivy-gcp.json`

---

## What Is Trivy?

Trivy is an all-in-one security scanner that covers:
1. **IaC Misconfigurations** — Terraform, CloudFormation, Kubernetes manifests
2. **Container Image Vulnerabilities** — OS packages, language dependencies
3. **Secret Detection** — API keys, tokens in code
4. **SBOM Generation** — Software Bill of Materials

**Why Trivy was chosen alongside TFSec/Checkov:** Trivy uses a different rule engine (its own policy library, separate from both Checkov and TFSec). Any finding appearing in all three tools = extremely high confidence. Trivy is also the go-to tool in Kubernetes-native environments and CI pipelines like GitHub Actions.

---

## Results Overview

```
           CRITICAL   HIGH    MEDIUM   LOW    TOTAL
AWS           6        61       26      22     115
Azure         7         6       55      22      90
GCP           2        11       22      14      49
─────────────────────────────────────────────────────
TOTAL        15        78      103      58     254
```

**254 total misconfigurations** validated by Trivy's independent rule set, confirming the findings from Checkov and TFSec.

---

## CRITICAL Findings – AWS (6)

| Trivy ID | Title | File | Analysis |
|----------|-------|------|---------|
| AWS-0104 | Security group allows unrestricted egress to any IP | ec2.tf | No outbound restriction = data exfiltration via any protocol |
| AWS-0029 | EC2 user data contains sensitive AWS keys | ec2.tf | **CONFIRMED** across TFSec + Trivy + GitLeaks — highest confidence finding |
| AWS-0104 | Unrestricted egress in DB security group | db-app.tf | MySQL can call back to attacker C2 |
| AWS-0040 | EKS cluster public access enabled | eks.tf | Kubernetes API accessible from internet |
| AWS-0041 | EKS public access CIDR not restricted | eks.tf | 0.0.0.0/0 — entire internet can reach the K8s API |
| AWS-0346 | IAM policy allows wildcard actions | iam.tf | `ec2:*`, `s3:*`, `lambda:*` on `Resource: *` = privilege escalation |

---

## CRITICAL Findings – Azure (7)

| Trivy ID | Title | File | Analysis |
|----------|-------|------|---------|
| AZU-0041 | AKS API Server Authorized IP Ranges not enabled | aks.tf | K8s API internet-facing — anyone can attempt auth |
| AZU-0013 | Key Vault network ACL not set | key_vault.tf | All secrets, keys accessible with no network boundary |
| AZU-0012 | Storage account network default action not deny | storage.tf | Storage account accessible without restriction |
| AZU-0047 | NSG allows unrestricted ingress | networking.tf | SSH from internet — instant brute force exposure |
| AZU-0047 | NSG allows unrestricted ingress | networking.tf | RDP from internet — primary ransomware vector |
| AZU-0048 | NSG allows RDP (3389) from internet | networking.tf | **CONFIRMED** by TFSec + Trivy — RDP critical finding |
| AZU-0047 | NSG rule allows unrestricted ingress | networking.tf | Multiple open ingress rules |

---

## CRITICAL Findings – GCP (2)

| Trivy ID | Title | File | Analysis |
|----------|-------|------|---------|
| GCP-0046 | BigQuery dataset accessible to all authenticated users | big_data.tf | Any Gmail = read access to your data warehouse |
| GCP-0027 | Firewall allows unrestricted ingress from any IP | networks.tf | GCE instances exposed to internet port scans |

---

## HIGH Findings – AWS (61, key ones)

| Trivy ID | Title | File |
|----------|-------|------|
| AWS-0028 | EC2 IMDS v2 not enforced | ec2.tf |
| AWS-0080 | RDS storage not encrypted | db-app.tf |
| AWS-0131 | EC2 root block device not encrypted | ec2.tf |
| AWS-0180 | RDS publicly accessible | db-app.tf |
| AWS-0345 | IAM policy allows wildcard S3/EC2/Lambda | iam.tf |
| AWS-0132 | ECR image scanning disabled | ecr.tf |
| AWS-0088 | ECR image tag not immutable | ecr.tf |
| AWS-0052 | S3 bucket encryption disabled | s3.tf (data, financials, operations) |
| AWS-0089 | S3 access logging not enabled | s3.tf |
| AWS-0086 | RDS encryption not enabled | db-app.tf |
| AWS-0077 | RDS backup retention insufficient | db-app.tf, rds.tf ×8 |
| AWS-0060 | CloudTrail not enabled | (no cloudtrail resource) |
| AWS-0159 | Neptune cluster not encrypted | neptune.tf |

---

## HIGH Findings – Azure (6)

| Trivy ID | Title | File |
|----------|-------|------|
| AZU-0042 | AKS RBAC disabled | aks.tf |
| AZU-0043 | AKS network policy not configured | aks.tf |
| AZU-0006 | App Service TLS version outdated | app_service.tf |
| AZU-0039 | VM password auth not disabled | instance.tf |
| AZU-0010 | Storage trusted services bypass not enabled | storage.tf |
| AZU-0038 | Managed disk encryption disabled | storage.tf |

---

## HIGH Findings – GCP (11)

| Trivy ID | Title | File |
|----------|-------|------|
| GCP-0015 | Cloud SQL SSL not enforced | big_data.tf |
| GCP-0017 | Cloud SQL publicly exposed (×2) | big_data.tf |
| GCP-0001 | GCS bucket publicly accessible | gcs.tf |
| GCP-0048 | GKE legacy metadata endpoints | gke.tf |
| GCP-0053 | GKE control plane exposed to internet | gke.tf |
| GCP-0043 | GCE instance IP forwarding enabled | instances.tf |
| GCP-0031 | GCE instance has public IP | instances.tf |
| GCP-0047 | GKE pod security policy not enforced | gke.tf |
| GCP-0023 | BigQuery world-readable | big_data.tf |
| GCP-0024 | Cloud SQL backups disabled | big_data.tf |
| GCP-0016 | Cloud SQL log_connections disabled | big_data.tf |

---

## Cross-Tool Confirmation (Highest Confidence Findings)

Findings confirmed by **all three tools** (Checkov + TFSec + Trivy) are highest confidence:

| Finding | Checkov | TFSec | Trivy |
|---------|:-------:|:-----:|:-----:|
| AWS hardcoded credentials in ec2.tf | ✅ CKV_AWS_45 | ✅ AVD-AWS-0029 | ✅ AWS-0029 |
| RDS publicly accessible | ✅ CKV_AWS_17 | ✅ AVD-AWS-0080 | ✅ AWS-0180 |
| RDS no encryption | ✅ CKV_AWS_17 | ✅ AVD-AWS-0086 | ✅ AWS-0080 |
| S3 no encryption | ✅ CKV_AWS_19 | ✅ AVD-AWS-0052 | ✅ AWS-0052 |
| GCS bucket public | ✅ CKV_GCP_28 | ✅ AVD-GCP-0001 | ✅ GCP-0001 |
| BigQuery world-readable | ✅ CKV_GCP_15 | ✅ AVD-GCP-0046 | ✅ GCP-0046 |
| Azure NSG open SSH/RDP | ✅ CKV_AZURE_9 | ✅ AVD-AZU-0047 | ✅ AZU-0047 |
| AKS no authorized IP range | ✅ CKV_AZURE_115 | ✅ AVD-AZU-0041 | ✅ AZU-0041 |
| Key Vault no network ACL | ✅ CKV_AZURE_109 | ✅ AVD-AZU-0013 | ✅ AZU-0013 |

---

## Interview Talking Point

> *"Trivy gave me an independent validation layer. When a finding appears in Checkov, TFSec, AND Trivy — like the hardcoded AWS credentials in ec2.tf — it's a definitive finding with zero false-positive risk. I used Trivy specifically because it's the tool most commonly used in Kubernetes-native CI pipelines (GitHub Actions, Tekton), so the findings I document here directly translate to what a DevSecOps engineer would configure in their pipeline shift-left process."*
