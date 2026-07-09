# Detection & Incident Response

**Module:** 06 – Detection & Incident Response  
**Findings:** FIND-011, FIND-020

---

## Key Issues & Solutions

| Finding | Issue | Solution | Why |
|---------|-------|----------|-----|
| FIND-011 | GKE logging disabled | Enable Cloud Logging | No audit trail = cannot detect attacks |
| FIND-020 | EKS logs not exported | CloudWatch + S3 + alerts | Centralized + long-term retention |

---

## AWS EKS: Enable Control Plane Logs (FIND-020)

**BEFORE:**
```hcl
enabled_cluster_log_types = []  # NO LOGGING
```

**AFTER:**
```hcl
enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
```

**Setup CloudWatch + S3:**
```hcl
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/cluster"
  retention_in_days = 90
}

resource "aws_cloudtrail" "main" {
  s3_bucket_name             = aws_s3_bucket.audit_logs.id
  enable_log_file_validation = true
}

# Archive to Glacier (cheaper storage)
resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.audit_logs.id
  rule { transition { days = 30; storage_class = "GLACIER" } }
}

# Alert on unauthorized API calls
resource "aws_cloudwatch_metric_alarm" "unauthorized" {
  metric_name = "UnauthorizedAPICallsEventCount"
  threshold   = 1
  alarm_actions = [aws_sns_topic.security_alerts.arn]
}
```

---

## Azure AKS: Enable Diagnostic Logs (FIND-020 equivalent)

**BEFORE:**
```hcl
resource "azurerm_kubernetes_cluster" "main" {
  name = "production-aks"
  # No oms_agent configured
}
```

**AFTER:**
```hcl
resource "azurerm_kubernetes_cluster" "main" {
  name = "production-aks"
  oms_agent {
    enabled                    = true
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }
}

resource "azurerm_monitor_diagnostic_setting" "aks" {
  target_resource_id = azurerm_kubernetes_cluster.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  enabled_log { category = "kube-apiserver" }
  enabled_log { category = "kube-audit" }
  enabled_log { category = "kube-controller-manager" }
}

resource "azurerm_monitor_metric_alert" "unauthorized" {
  metric_name = "httpRequestsWithFailureResponse"
  threshold   = 5
  action { action_group_id = azurerm_monitor_action_group.security.id }
}
```

---

## GCP GKE: Enable Cluster Logging (FIND-011)

**BEFORE:**
```hcl
logging_service    = "none"  # LOGGING DISABLED
monitoring_service = "none"
```

**AFTER:**
```hcl
logging_service    = "logging.googleapis.com/kubernetes"
monitoring_service = "monitoring.googleapis.com/kubernetes"

logging_config {
  enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS", "API_SERVER"]
}
```

---

## CSPM Approach

Cloud Security Posture Management is implemented as continuous policy enforcement, not periodic point-in-time scanning.

| Layer | Tooling | Cadence | Action |
|---|---|---|---|
| IaC pre-merge | Checkov/TFSec/Conftest | Every PR | Block or flag by severity policy |
| Runtime cloud config | Native cloud findings + aggregator | Continuous | Alert on drift from baseline |
| Governance reporting | Central dashboard | Daily | Track MTTR, open critical findings, exception aging |

**Operating model:** no critical misconfiguration remains untriaged beyond 24 hours.

## Incident Walkthrough: Compromised CI Service Account

### 1) Detection

- Trigger: abnormal OIDC AssumeRole pattern from CI principal (new geography/time/profile).
- Signals: CloudTrail anomaly, IAM role usage spike, unusual Terraform/API calls.
- SLA: triage starts within 5 minutes of alert.

### 2) Containment

- Disable compromised pipeline identity/provider binding.
- Revoke active sessions/tokens and freeze production deploy workflow.
- Apply deny policy guardrail to sensitive actions (iam:CreateUser, kms:DisableKey, s3:PutBucketPolicy).

### 3) Eradication

- Remove malicious workflow/action references and unapproved role trust statements.
- Rotate affected secrets and reissue trusted workload identity bindings.
- Validate no persistence artifacts remain (backdoor IAM principals, webhook exfil paths).

### 4) Recovery

- Restore trusted pipeline definition from known-good commit.
- Re-enable deploy path with temporary heightened approval requirements.
- Run full post-recovery verification (infra drift check, permission diff, workload smoke tests).

## Communication Plan: Mid-Incident vs Post-Incident

| Timing | Audience | Content |
|---|---|---|
| Mid-incident (first 30-60 min) | ITSO/CISO/operations leads | What happened, current blast radius, containment actions, immediate business impact |
| During containment | Service owners | Operational restrictions (deploy freeze), expected timelines |
| Post-incident (within 24-72 hrs) | Governance panel + stakeholders | Root cause, timeline, eradication evidence, recovery validation, corrective actions |

This separates fast operational communication from complete forensic reporting.

**Export to BigQuery + alerts:**
```hcl
resource "google_logging_project_sink" "gke_audit" {
  name        = "gke-audit"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/audit"
  filter      = "resource.type=k8s_cluster"
}

resource "google_monitoring_alert_policy" "suspicious_exec" {
  display_name = "kubectl exec detected"
  conditions {
    condition_threshold {
      filter = "protoPayload.methodName=v1.pods.exec"
      comparison = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.security_email.id]
}
```

---

## Notable Points

**Q: Why CloudWatch AND S3 (not just one)?**  
> "CloudWatch = real-time alerts. S3 with Object Lock = immutable long-term backup (attacker can't delete). If control plane compromised, S3 is separate account. Forensics needs months of history queryable."

**Q: Why Glacier archive after 30 days?**  
> "Most incidents resolved within 30 days. Glacier costs 10x less than hot storage. If needed later (3-month investigation), data still there."

**Q: What if admin deletes logs?**  
> "CloudTrail signature validation detects tampering. S3 Object Lock prevents deletion (7-year hold). MFA Delete requires physical approval. Logs in separate AWS account = can't access even with root creds."

**Q: How do you detect logging disabled?**  
> "Set alarm on config changes. If logging_service changes from 'enabled' → 'none', alert fires. Monthly audit script checks all clusters."

---

## IR Checklist

| Phase | Action | Timeline |
|-------|--------|----------|
| Detect | Alert fires, on-call paged | 0-5 min |
| Assess | Query logs: who, what, when | 5-15 min |
| Contain | Revoke creds, block IP, verbose logging | 15-60 min |
| Eradicate | Rotate keys, remove backdoors | 1-4 hours |
| Recover | Restore from backup, verify | 4+ hours |

---

## Remediation Status

| Finding | Action | Status |
|---------|--------|--------|
| FIND-011 | GKE → enable Cloud Logging | ✅ Documented |
| FIND-020 | EKS → CloudWatch + S3 + alerts | ✅ Documented |
