# Multi-Cloud Architecture Design

**Module:** 10 – Architecture  
**Scope:** High-Level Design (HLD) + Low-Level Design (LLD) + topology after remediation

---

## High-Level Design (HLD): Three-Cloud Platform

```
┌─────────────────────────────────────────────────────────────────┐
│                     External Users / Applications               │
└────┬────────────────────────────────────────────────────────────┘
     │
     ├─────────────────────────────────────────────────────────────────────┐
     │                                                                       │
     ▼                                                                       ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  INGRESS LAYER (Per Cloud)                                                        │
├──────────────────────────────────────────────────────────────────────────────────┤
│ AWS: CloudFront + ALB + WAF                                                      │
│ Azure: Front Door + Application Gateway + WAF                                   │
│ GCP: Cloud CDN + Cloud Load Balancer + Cloud Armor                              │
└──────┬──────────────────┬──────────────────────────────┬─────────────────────────┘
       │                  │                              │
       ▼                  ▼                              ▼
┌──────────────┐   ┌──────────────┐           ┌──────────────────┐
│ AWS          │   │ AZURE        │           │ GCP              │
│ VPC          │   │ VNet         │           │ VPC              │
├──────────────┤   ├──────────────┤           ├──────────────────┤
│ EKS Cluster  │   │ AKS Cluster  │           │ GKE Cluster      │
│ (logging ON) │   │ (logging ON) │           │ (logging ON)     │
│ (NetPolicies)    │ (NSGs)       │           │ (FirewallRules)  │
│ (Private IPs)    │ (Private IPs)            │ (Private network)
└────┬─────────┘   └────┬────────┘           └────┬──────────────┘
     │                  │                         │
     ├──────────────────┼─────────────────────────┤
     │                  │                         │
     ▼                  ▼                         ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
│ S3 (Encrypted)   │ Storage Acct  │   │ Cloud Storage    │
│ (Private)        │ (Private)     │   │ (Private + CMK)  │
│                  │               │   │                  │
│ RDS Aurora   │   │ SQL DB        │   │ Cloud SQL        │
│ (Encrypted)  │   │ (TDE)         │   │ (Encrypted)      │
│              │   │               │   │                  │
│ KMS Keys     │   │ Key Vault     │   │ Cloud KMS        │
│ (90-day rot) │   │ CMK           │   │ (90-day rot)     │
└──────────────┘   └──────────────┘   └──────────────────┘
       │                  │                         │
       └──────────────────┼─────────────────────────┘
                          │
                          ▼
                   ┌──────────────────┐
                   │ Centralized Logs │
                   ├──────────────────┤
                   │ CloudTrail → S3  │
                   │ Azure Monitor    │
                   │ Cloud Audit Logs │
                   │ BigQuery/Glacier │
                   └──────────────────┘
                          │
                          ▼
                   ┌──────────────────┐
                   │ Security Tools   │
                   ├──────────────────┤
                   │ Checkov          │
                   │ TFSec            │
                   │ GitLeaks         │
                   │ Falco (runtime)  │
                   └──────────────────┘
```

---

## Low-Level Design (LLD): AWS EKS + RDS Example

```
AWS VPC: 10.0.0.0/16
│
├─ Public Subnets (NAT for outbound only)
│  ├─ 10.0.1.0/24 (AZ-a)
│  └─ 10.0.2.0/24 (AZ-b)
│
├─ Private Subnets (EKS nodes)
│  ├─ 10.0.10.0/24 (AZ-a)
│  └─ 10.0.11.0/24 (AZ-b)
│
└─ Database Subnets (RDS private)
   ├─ 10.0.20.0/24 (AZ-a)
   └─ 10.0.21.0/24 (AZ-b)

Security Groups:
├─ ALB-SG: Allow 443 from 0.0.0.0/0 (HTTPS only)
├─ EKS-Node-SG: Allow 443/6443 from ALB-SG (API server access)
├─ EKS-Pod-SG: Allow port 8080 from EKS-Node-SG (app pods)
└─ RDS-SG: Allow 5432 from EKS-Pod-SG (database access)

Network ACLs:
├─ Inbound: Deny SSH (port 22)
├─ Inbound: Deny RDP (port 3389)
├─ Inbound: Allow HTTPS only (port 443)
└─ Outbound: Deny suspicious IPs (DDoS list)

EKS Cluster:
├─ API endpoint: Private (no public access) — FIND-012 fixed
├─ Logging: Enabled (api, audit, authenticator) — FIND-020 fixed
├─ Network Policies: Enabled (deny-all + explicit allow) — FIND-013 fixed
├─ IAM Roles: Least privilege (specific actions only) — FIND-010 fixed
└─ Nodes: Auto-scaling with monitoring

RDS Aurora:
├─ Encryption: TDE + KMS customer-managed key — FIND-018 fixed
├─ Backup: Daily snapshots → S3 (encrypted)
├─ Access: Private endpoint only
├─ Monitoring: CloudWatch logs + Performance Insights
└─ Credentials: Rotated every 90 days (not hardcoded) — FIND-002 fixed
```

---

## Data Flow (Before & After)

### BEFORE (Vulnerable)

```
User Request
     │
     ▼
┌──────────────────────────────────────────────┐
│ ALB (No WAF)                                 │
│ Accepts HTTP + HTTPS                        │
│ No DDoS protection                           │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ EKS Pods                                     │
│ Public master endpoint (FIND-012)            │
│ No NetworkPolicy (FIND-013)                  │
│ Can reach database directly                  │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ RDS Aurora                                   │
│ Unencrypted at rest (FIND-018)              │
│ Hardcoded credentials in env var (FIND-002) │
│ No backup encryption                         │
└──────────────────────────────────────────────┘
```

**Issues:** Attacker can intercept data, bypass EKS network, access database directly

### AFTER (Remediated)

```
User Request
     │
     ▼
┌──────────────────────────────────────────────┐
│ CloudFront + WAF                             │
│ HTTPS only (no HTTP)                         │
│ DDoS protection enabled                      │
│ TLS 1.3                                      │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ ALB (HTTPS Only)                             │
│ SSL/TLS certificate validation               │
│ Request rate limiting                        │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ EKS (Private Master)                         │
│ Private endpoint (FIND-012 fixed)           │
│ NetworkPolicy: Deny-all + allow ingress only │
│ Pod-to-database via service mesh (mTLS)      │
│ IAM roles: Least privilege (FIND-010 fixed)  │
│ Logging: CloudTrail + CloudWatch (FIND-020)  │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ RDS Aurora (Encrypted)                       │
│ Encryption at rest: KMS CMK (FIND-018 fixed) │
│ Encryption in transit: TLS only              │
│ Credentials: IAM database auth (FIND-002)    │
│ Backup: Encrypted → S3 with lifecycle        │
│ Audit logs: CloudTrail + RDS events          │
└──────────────────────────────────────────────┘
```

**Benefits:** Defense in depth, encrypted end-to-end, audit trail, zero-trust network

---

## Multi-Cloud Workload Distribution

| Workload | AWS | Azure | GCP | Reason |
|----------|-----|-------|-----|--------|
| **API Server** | EKS (primary) | AKS (failover) | GKE (standby) | Multi-region HA |
| **Database** | RDS Aurora | Azure SQL | Cloud SQL | Cross-cloud replication |
| **Object Storage** | S3 (primary) | Blob Storage | Cloud Storage | Data residency |
| **Logs/Analytics** | CloudTrail → S3 | Azure Monitor | BigQuery | Cloud-native logging |
| **KMS** | AWS KMS | Key Vault | Cloud KMS | Cloud-native encryption |
| **CI/CD** | GitHub Actions | GitHub Actions | GitHub Actions | Single source of truth |

---

## High Availability & Disaster Recovery

### RTO/RPO Goals

| Scenario | RTO | RPO | Solution |
|----------|-----|-----|----------|
| Single AZ failure | 5 minutes | 0 minutes | Multi-AZ failover (active-active) |
| Single region failure | 30 minutes | 5 minutes | Cross-region read replica |
| Single cloud provider failure | 2 hours | 15 minutes | Cross-cloud backup + restore |
| Data corruption | 24 hours | 1 day | Point-in-time restore + verification |

### Implementation

**AWS RDS:**
```
├─ Multi-AZ: Synchronous replica in AZ-b
├─ Cross-region backup: Automated snapshots → S3 → copy to other region
├─ Backup retention: 35 days (encrypted)
└─ Restore: Terraform can recreate from snapshot
```

**Backup Strategy:**
```
Every 1 hour: Automated snapshots
Every 1 day: Copy to S3 (replicate to other regions)
Every 1 month: Glacier archive (7-year retention for compliance)
Every quarter: Full backup validation + restore test
```

---

## Network Segmentation Layers

| Layer | Scope | Control | Enforcement |
|-------|-------|---------|-------------|
| **Layer 3** | Network | VPC CIDR + subnets | VPC/VNet/VPC routes |
| **Layer 4** | Firewall | Security Groups + NSGs | Stateful firewalls |
| **Layer 7** | API Gateway | Rate limiting + WAF | Application rules |
| **Pod Network** | Kubernetes | NetworkPolicy | eBPF-based enforcement (Calico) |
| **Service Mesh** | microservices | mTLS + AuthorizationPolicy | Istio/Linkerd |

---

## Monitoring & Observability

| Metric | Source | Tool | Alert Threshold |
|--------|--------|------|-----------------|
| **API Errors** | EKS logs | CloudWatch | >5% error rate |
| **Database Latency** | RDS metrics | CloudWatch | >500ms p99 |
| **Unauthorized API Calls** | CloudTrail | EventBridge | Any occurrence |
| **Failed Login Attempts** | Azure AD logs | Azure Monitor | >10 in 5 min |
| **Network Anomalies** | VPC Flow Logs | GuardDuty | Suspicious IPs |
| **Compliance Drift** | Checkov scan | CI/CD pipeline | Failed check blocks merge |

---

## Disaster Recovery Runbook

| Phase | Action | Time | Validation |
|-------|--------|------|-----------|
| **Detection** | Alert fires (RTO clock starts) | 0-5 min | Confirm issue is real |
| **Failover** | Update DNS to backup region | 5-15 min | Verify traffic routing |
| **Verification** | Run smoke tests | 15-30 min | Confirm app is healthy |
| **Monitoring** | Watch metrics/logs | Ongoing | No new errors |
| **Communication** | Notify stakeholders | Ongoing | Status updates |

---

## Notable Points

**Q: Why multi-cloud instead of multi-region in one cloud?**  
> "Multi-region in one cloud still has vendor risk (cloud provider outage). Multi-cloud gives options: if AWS has issue, failover to GCP. Costs more but critical for 99.99% uptime SLAs."

**Q: How do you keep three databases in sync?**  
> "RDS Aurora cross-region read replica (asynchronous). Azure SQL active geo-replication (read-only). GCP Cloud SQL read replicas. They stay ~5 seconds behind. Accept slight staleness for availability."

**Q: What if data corruption happens in all three clouds simultaneously?**  
> "Point-in-time restore from 24 hours ago. That's why we keep backups for 35 days (and Glacier for 7 years). Restore to a separate database, validate data, then point prod to it."

**Q: Should every microservice run in all three clouds?**  
> "No. Cost would be 3x. Strategy: stateless services (API, web) run in all clouds. Stateful services (database, cache) run in primary + replicas only."

---

## Architecture Post-Remediation

✅ Defense in depth (network + app + data layers)  
✅ Encryption end-to-end (in transit + at rest)  
✅ Audit trail across all three clouds  
✅ Multi-cloud HA with RTO/RPO SLAs  
✅ Automated failover + disaster recovery  
✅ Zero-trust network + least-privilege IAM
