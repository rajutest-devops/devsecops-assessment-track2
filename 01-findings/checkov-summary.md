# Checkov Scan Summary – TerraGoat Multi-Cloud

**Tool:** Checkov (Bridgecrew)  
**Version:** Latest  
**Scan Date:** 2026-07-07  
**Raw Output Files:** `checkov-aws.json` · `checkov-azure.json` · `checkov-gcp.json`

---

## What Is Checkov?

Checkov is an open-source static analysis tool for Infrastructure as Code. It reads Terraform (HCL), CloudFormation, Kubernetes YAML, and other formats, and checks resources against a library of 1000+ built-in policies. Each policy maps to real-world compliance benchmarks: CIS, PCI-DSS, SOC 2, NIST, HIPAA, ISO 27001.

**Why Checkov was chosen:** TerraGoat was built by Bridgecrew, the same team that created Checkov. Checkov is the canonical tool for this repo and its findings map directly to the Bridgecrew cloud dashboard used in enterprise environments. Running Checkov gives findings that align with what a QSA auditor or cloud security team would produce.

---

## Results Overview

| Cloud | Passed Checks | Failed Checks | Pass Rate |
|-------|:---:|:---:|:---:|
| AWS | 115 | 215 | 35% |
| Azure | 68 | 174 | 28% |
| GCP | 17 | 56 | 23% |
| **Total** | **200** | **445** | **31%** |

> ⚠️ **Interpretation:** A 31% pass rate means 69% of security checks are failing. In a production environment, this would fail any security audit or cloud security posture management (CSPM) baseline.

> **Note on Severity:** Checkov in this version reports all findings as `UNKNOWN` severity because the `--bc-api-key` flag (Bridgecrew cloud account) is not set. The actual severity of each finding is known from the check name and cross-referenced with TFSec which provides CRITICAL/HIGH/MEDIUM/LOW ratings.

---

## Top AWS Failures (215 total)

| Check ID | Check Name | Resource | Category |
|----------|-----------|----------|---------|
| CKV_AWS_161 | RDS IAM authentication disabled | aws_db_instance.default | Identity |
| CKV_AWS_293 | RDS deletion protection disabled | aws_db_instance.default | Resilience |
| CKV_AWS_157 | RDS Multi-AZ disabled | aws_db_instance.default | Resilience |
| CKV_AWS_129 | RDS CloudWatch logs not enabled | aws_db_instance.default | Detection |
| CKV_AWS_133 | RDS backup retention = 0 | aws_db_instance.default | Resilience |
| CKV_AWS_226 | RDS minor version auto-upgrade off | aws_db_instance.default | Patching |
| CKV_AWS_17 | RDS publicly accessible | aws_db_instance.default | Network |
| CKV_AWS_118 | RDS enhanced monitoring disabled | aws_db_instance.default | Detection |
| CKV_AWS_45 | Lambda env vars not encrypted | aws_lambda_function.analysis_lambda | Data |
| CKV_AWS_116 | Lambda DLQ not configured | aws_lambda_function.analysis_lambda | Resilience |
| CKV_AWS_50 | Lambda X-Ray tracing disabled | aws_lambda_function.analysis_lambda | Detection |
| CKV_AWS_272 | Lambda URL auth disabled | aws_lambda_function | Identity |
| CKV_AWS_25 | S3 bucket not encrypted | aws_s3_bucket.data | Data |
| CKV_AWS_19 | S3 server-side encryption disabled | aws_s3_bucket (multiple) | Data |
| CKV_AWS_21 | S3 versioning disabled | aws_s3_bucket.data, .financials | Data |
| CKV_AWS_18 | S3 access logging disabled | aws_s3_bucket (multiple) | Detection |
| CKV_AWS_53 | S3 bucket policy allows public access | aws_s3_bucket.data | Network |
| CKV_AWS_7 | KMS key rotation not enabled | aws_kms_key.logs_key | Encryption |
| CKV_AWS_23 | ELB does not use HTTPS listener | aws_elb.weblb | Network |
| CKV_AWS_92 | ELB access logs not enabled | aws_elb.weblb | Detection |
| CKV_AWS_2 | ALB/ELB HTTP redirect missing | aws_elb.weblb | Network |
| CKV_AWS_58 | EKS secrets not encrypted | aws_eks_cluster.eks_cluster | Data |
| CKV_AWS_37 | EKS control plane logging disabled | aws_eks_cluster.eks_cluster | Detection |
| CKV_AWS_38 | EKS control plane auth logging off | aws_eks_cluster.eks_cluster | Detection |
| CKV_AWS_39 | EKS control plane audit logging off | aws_eks_cluster.eks_cluster | Detection |
| CKV_AWS_74 | EKS endpoint public access enabled | aws_eks_cluster.eks_cluster | Network |
| CKV2_AWS_5 | Security group not attached to ENI | aws_security_group | Network |
| CKV_AWS_88 | EC2 public IP auto-assignment | aws_instance.web_host | Network |
| CKV_AWS_79 | EC2 IMDS v1 not disabled | aws_instance.web_host | Identity |
| CKV2_AWS_6 | S3 Block Public Access not set | aws_s3_bucket (multiple) | Network |

---

## Top Azure Failures (174 total)

| Check ID | Check Name | Resource | Category |
|----------|-----------|----------|---------|
| CKV_AZURE_170 | AKS not using Paid SLA SKU | azurerm_kubernetes_cluster | Resilience |
| CKV_AZURE_172 | AKS Secrets Store CSI autorotation off | azurerm_kubernetes_cluster | Identity |
| CKV_AZURE_8 | Kubernetes Dashboard enabled | azurerm_kubernetes_cluster | Network |
| CKV_AZURE_141 | AKS local admin not disabled | azurerm_kubernetes_cluster | Identity |
| CKV_AZURE_115 | AKS private cluster not enabled | azurerm_kubernetes_cluster | Network |
| CKV_AZURE_117 | AKS disk encryption set missing | azurerm_kubernetes_cluster | Data |
| CKV_AZURE_7 | AKS network policy not configured | azurerm_kubernetes_cluster | Network |
| CKV_AZURE_57 | Storage account HTTPS-only not enforced | azurerm_storage_account | Network |
| CKV_AZURE_33 | Storage account queue logging incomplete | azurerm_storage_account | Detection |
| CKV_AZURE_35 | Key Vault soft delete not enabled | azurerm_key_vault | Resilience |
| CKV_AZURE_42 | Key Vault purge protection disabled | azurerm_key_vault | Resilience |
| CKV_AZURE_109 | Key Vault network ACL not default deny | azurerm_key_vault | Network |
| CKV_AZURE_23 | SQL audit log retention < 90 days | azurerm_sql_server | Detection |
| CKV_AZURE_24 | SQL threat detection disabled | azurerm_sql_server | Detection |
| CKV_AZURE_25 | SQL email threat alerts not enabled | azurerm_sql_server | Detection |
| CKV_AZURE_131 | App Service client certificate missing | azurerm_app_service | Identity |
| CKV_AZURE_13 | App Service authentication disabled | azurerm_app_service | Identity |
| CKV_AZURE_15 | App Service HTTPS-only not enabled | azurerm_app_service | Network |
| CKV_AZURE_17 | App Service TLS 1.2+ not enforced | azurerm_app_service | Network |
| CKV_AZURE_80 | App Service Java version outdated | azurerm_app_service | Patching |

---

## Top GCP Failures (56 total)

| Check ID | Check Name | Resource | Category |
|----------|-----------|----------|---------|
| CKV_GCP_52 | Cloud SQL log_connections flag off | google_sql_database_instance | Detection |
| CKV_GCP_108 | Cloud SQL hostname logging off | google_sql_database_instance | Detection |
| CKV_GCP_6 | Cloud SQL SSL not required | google_sql_database_instance | Network |
| CKV_GCP_11 | Cloud SQL open to world | google_sql_database_instance | Network |
| CKV_GCP_79 | Cloud SQL not latest major version | google_sql_database_instance | Patching |
| CKV_GCP_110 | pgAudit not enabled | google_sql_database_instance | Detection |
| CKV_GCP_51 | log_checkpoints flag off | google_sql_database_instance | Detection |
| CKV_GCP_53 | log_disconnections flag off | google_sql_database_instance | Detection |
| CKV_GCP_14 | log_temp_files flag not set | google_sql_database_instance | Detection |
| CKV_GCP_76 | Cloud SQL no point-in-time recovery | google_sql_database_instance | Resilience |
| CKV_GCP_23 | BigQuery dataset not encrypted with CMK | google_bigquery_dataset | Data |
| CKV_GCP_17 | Compute instance OS login disabled | google_compute_instance | Identity |
| CKV_GCP_39 | Compute instance project SSH keys | google_compute_instance | Identity |
| CKV_GCP_32 | Compute instance serial port enabled | google_compute_instance | Network |
| CKV_GCP_38 | GKE legacy ABAC enabled | google_container_cluster | Identity |
| CKV_GCP_25 | GKE master auth networks not configured | google_container_cluster | Network |
| CKV_GCP_67 | GKE legacy metadata endpoints | google_container_cluster | Network |
| CKV_GCP_8 | GKE logging disabled | google_container_cluster | Detection |
| CKV_GCP_9 | GKE monitoring disabled | google_container_cluster | Detection |
| CKV_GCP_69 | GCS bucket not using uniform bucket-level access | google_storage_bucket | Identity |

---

## How to Read Checkov Check IDs

- `CKV_AWS_*` — AWS Terraform checks
- `CKV_AZURE_*` — Azure Terraform checks
- `CKV_GCP_*` — GCP Terraform checks
- `CKV2_AWS_*` — Second generation AWS checks (more specific)
- Number = sequential check ID in the Checkov library

Each failing check has a `guideline` URL in the raw JSON pointing to Bridgecrew docs explaining the fix.

---

## Interview Talking Point

> *"I ran Checkov across all three clouds and got a 31% pass rate — meaning 69% of security checks failed. The important thing about Checkov is it doesn't just tell you something is wrong; it tells you the specific Terraform attribute that needs to change. For example, CKV_AWS_133 fails because backup_retention_period is 0 — Checkov's fixed_definition field in the JSON even shows you the corrected code. This makes it a developer-friendly tool: findings are immediately actionable, not vague."*
