# Architecture Narrative — Design Decisions

**Module:** 10 — Architecture  
**Companion to:** hld-diagram.md and lld-diagram.md

---

## Key Security Decisions

### 1. OIDC Federation Instead of Long-Lived Credentials

**Decision:** CI/CD pipeline uses OIDC tokens (1-hour) instead of stored AWS access keys.

**Reasoning:** Any stored credential (GitHub Actions secret, environment variable) is a liability. If the pipeline is compromised, an attacker inherits all stored credentials permanently. With OIDC, the token expires in 1 hour and is scoped to a specific GitHub repo + branch. An attacker compromising the pipeline gets 1-hour access, not permanent access.

**Alternative considered:** Stored IAM user access keys in GitHub Secrets  
**Rejected because:** Keys don't expire. Rotation is manual. One leaked key = permanent account access. The `tj-actions/changed-files` incident (March 2025) demonstrated this exact attack at scale.

---

### 2. SSM Session Manager Instead of SSH

**Decision:** No port 22 open anywhere. All administrative access via AWS Systems Manager Session Manager.

**Reasoning:** SSH requires an open port, key distribution, and key rotation. SSM Session Manager proxies the connection through the AWS control plane — no inbound port needed. Access is controlled by IAM (who can `ssm:StartSession`), logged to CloudTrail, and requires MFA. Accidental SSH is impossible because the port doesn't exist.

**Alternative considered:** SSH bastion host with port 22 restricted to VPN CIDR  
**Rejected because:** Bastion hosts require maintenance (patching, HA). VPN CIDR changes require security group updates. Keys still need managing. SSM eliminates all of these.

---

### 3. Centralised KMS Instead of Per-Service Encryption

**Decision:** Single KMS key per environment (`data-encryption-key`) used across RDS, S3, and Secrets Manager.

**Reasoning:** Simpler to manage, audit, and rotate. One key policy controls who can decrypt data. If a service account is compromised, revoking its KMS access stops data access even if storage is physically accessible.

**Alternative considered:** Per-service keys (one for RDS, one for S3, one for SM)  
**Rejected because:** Key sprawl increases operational complexity. Auditing 10+ keys per environment is harder than auditing one. For this estate, a single CMK per environment with tight IAM policies achieves the same blast-radius goal.

**Note:** For workloads with PCI-DSS scope requiring BYOK, a separate HSM-backed key (CloudHSM or Azure Dedicated HSM) would be warranted. This is documented as a future enhancement.

---

### 4. WAF + CloudFront Before ALB (Not ALB Directly)

**Decision:** Traffic hits CloudFront → WAF before reaching the Application Load Balancer.

**Reasoning:** ALB alone doesn't block DDoS at edge. CloudFront caches static content and absorbs volumetric attacks before they reach EC2. WAF with managed rules (OWASP Top 10) blocks SQL injection, XSS, and bot traffic at the edge — not inside the VPC where it's already consumed resources.

**Alternative considered:** WAF attached directly to ALB  
**Rejected because:** ALB WAF doesn't benefit from CloudFront's distributed PoP network. Volumetric DDoS reaches the ALB before WAF rules apply. Edge protection is significantly more effective.

---

### 5. Private Cluster (GKE) — No Public Master Endpoint

**Decision:** GKE master endpoint is private (`enable_private_endpoint = true`). Only admin CIDR reachable via VPN.

**Reasoning:** FIND-012 showed the master exposed to `0.0.0.0/0`. Any internet host can attempt Kubernetes API calls. Removing the public endpoint reduces the attack surface to zero for unauthenticated access. Authorised admins reach the master via private IP through VPN.

**Alternative considered:** Public endpoint with strong RBAC  
**Rejected because:** Even with strong RBAC, a zero-day in the Kubernetes API server would be exploitable from anywhere. Defense in depth requires both network restriction AND access control — not just one.

---

### 6. Multi-Cloud Logging to Single SIEM (Not Native-Only)

**Decision:** CloudWatch + Azure Monitor + GCP Logging all ship to a centralised log store (Log Analytics or SIEM).

**Reasoning:** Security incidents rarely stay within one cloud. If an attacker uses a compromised GCP service account to pivot to AWS (via a shared API credential), detecting the attack requires correlating logs across both clouds. With three separate native log stores, correlation is manual and slow.

**Alternative considered:** Keep logs in each cloud's native tool (CloudWatch / Azure Monitor / GCP Logging)  
**Rejected because:** No cross-cloud correlation. CSPM tools need access to all three. Incident response requires querying three separate UIs. Centralisation adds complexity but significantly improves detection capability.

---

## What's Out of Scope (and Why)

| Item | Decision | Reason |
|------|----------|--------|
| Cross-cloud failover (AWS → Azure) | Not recommended | Complexity outweighs benefit; each cloud has multi-AZ within itself |
| HSM (CloudHSM) | Not implemented | Warranted only for PCI Tier 1 workloads; adds $80K+/year cost |
| Service mesh (Istio) | Future enhancement | Required for mTLS between pods; not in scope for initial go-live |
| Zero-trust micro-segmentation | Partial | NetworkPolicy covers pod-to-pod; full ZTA requires service mesh |

---

## Summary

The architecture prioritises:
1. **No long-lived credentials** — OIDC everywhere
2. **Network + access control** — Private subnets + MFA + SSM (not SSH)
3. **Encryption at every layer** — KMS at rest + TLS in transit
4. **Centralised visibility** — Single SIEM across all clouds
5. **Automation first** — Checkov/TFSec in pipeline prevents regressions
