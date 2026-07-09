# DevSecOps Assessment — Track 2: Multi-Cloud Platform Security & Compliance

**Candidate Repository:** `rajutest-devops/devsecops-assessment-track2`  
**Reference Repository:** [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) (forked: `rajutest-devops/terragoat`)  
**Date:** 2026-07-09

---

## Executive Summary

A security review of TerraGoat — a deliberately vulnerable multi-cloud Terraform repository spanning AWS, Azure, and GCP — identified **20 exploitable findings** across 46 `.tf` files. Four are Critical severity (CVSS 9.0+), actively exploitable with no prerequisites. The estate has no centralised detection, inconsistent logging, and hardcoded credentials in source code.

**Overall Risk Posture: HIGH**

| Cloud | Critical | High | Tools Used |
|-------|----------|------|------------|
| AWS | 3 | 9 | Checkov, TFSec, Trivy, GitLeaks |
| Azure | 1 | 5 | Checkov, TFSec, Trivy |
| GCP | 0 | 2 | Checkov, TFSec, Trivy |

---

## Repository Choice

**Primary:** `terragoat` (bridgecrewio) — chosen because it spans all three clouds (AWS, Azure, GCP) in one repository with realistic IaC patterns mirroring the assessment scenario. Multi-cloud coverage allows comparing how the same risk manifests differently across providers.

**Reference for target state:** AWS Landing Zone Accelerator (`awslabs/landing-zone-accelerator-on-aws`) — referenced in architecture and compliance modules as the hardened target baseline.

---

## How the Modules Connect

```
Module 01 (Findings)          <- Base input to all downstream modules
  |
  +-> Module 02 (Pipeline)          <- Catches future issues before merge/deploy
  +-> Module 03 (Identity)          <- Fixes FIND-001/002 (hardcoded keys), FIND-010 (wildcard IAM)
  +-> Module 04 (Network)           <- Fixes FIND-008/009/012/013 (open ports, GKE exposure)
  +-> Module 05 (Data Protection)   <- Fixes FIND-004/005/018 (public S3, unencrypted SQL)
  +-> Module 06 (Detection & IR)    <- Fixes FIND-011/020 (disabled logging)
  +-> Module 07 (Remediation)       <- Fix guidance for all 20 findings
      +-> compensating-controls.md  <- COTS constraint handling
      +-> fixed-terraform/          <- Corrected Terraform files

Module 08 (Threat Model)      <- STRIDE + MITRE ATT&CK across all findings
Module 09 (Compliance)        <- CIS / PCI-DSS / NIST CSF / SOC 2 mapping
Module 10 (Architecture)      <- HLD + LLD + narrative (target state post-remediation)
Module 11 (Resilience & DR)   <- RTO/RPO, backup, multi-AZ, failover
Module 12 (Presentation)      <- Executive summary + slides for governance panel
```

---

## Repository Structure

```
devsecops-assessment-track2/
├── README.md
├── 01-findings/
│   ├── findings-register.md          <- 20 prioritised findings (Critical/High)
│   ├── severity-methodology.md       <- Selection from 445+ raw Checkov failures
│   └── [raw scan outputs]            <- checkov, tfsec, trivy, gitleaks JSONs
├── 02-pipeline-supply-chain/
│   ├── pipeline-design.md            <- 5 vulnerabilities + secure pipeline design
│   └── .gitlab-ci-example.yml        <- GitLab CI reference (assessment requirement)
├── 03-identity-governance/
│   └── cross-cloud-iam-design.md     <- IAM roles, Workload Identity, Conditional Access
├── 04-network-zero-trust/
│   └── network-segmentation.md       <- SSH/RDP restriction, GKE private endpoint
├── 05-data-protection/
│   └── encryption-key-mgmt.md        <- S3 lockdown, EBS, Azure SQL TDE, GCP KMS
├── 06-detection-ir/
│   └── monitoring-incident-response.md <- Logging, alerts, IR workflow
├── 07-remediation/
│   ├── remediation-advisory.md       <- All 20 findings, P0-P3 priority timeline
│   ├── compensating-controls.md      <- COTS constraint: 3 compensating controls
│   └── fixed-terraform/              <- Corrected .tf files for critical findings
├── 08-threat-model/
│   └── threat-model.md               <- STRIDE + MITRE ATT&CK + kill chain
├── 09-compliance/
│   └── compliance-mapping.md         <- CIS / PCI-DSS / NIST CSF / SOC 2
├── 10-architecture/
│   ├── hld-diagram.md                <- High-Level Design (Mermaid diagram)
│   ├── lld-diagram.md                <- Low-Level Design (Mermaid diagram)
│   ├── architecture-narrative.md     <- Design decisions + alternatives considered
│   └── architecture-design.md        <- Full architecture document
├── 11-resilience-dr/
│   └── resilience-dr-plan.md         <- Multi-AZ, RTO/RPO, backup, failover
└── 12-presentation/
    ├── executive-summary.md          <- Detailed executive narrative
    └── slides.md                     <- Presentation slides (25-min panel format)
```

---

## Actual Running Pipeline

The GitHub Actions pipeline is in the **terragoat fork**:  
`rajutest-devops/terragoat/.github/workflows/devsecops-pipeline.yml`

**Stages:** terraform-lint → iac-scan (Checkov + TFSec) → secret-scan (GitLeaks) → pr-summary  
All actions pinned to commit SHAs. Secrets block pipeline (`allow_failure: false`).

---

## Commit History

| Commit | Module | Description |
|--------|--------|-------------|
| `3318df9` | 01 | Findings register + severity methodology |
| `f555c32` | 02 | Pipeline design + GitLab CI reference |
| `e86b960` | 03 | Cross-cloud IAM design |
| `8b3ef87` | 04 | Network segmentation |
| `f68891b` | 05 | Data protection + encryption |
| `1e019e5` | 06 | Detection & IR |
| `474ea06` | 07 | Remediation advisory |
| `4ec46cb` | 08 | Threat model (STRIDE + MITRE) |
| `c4a1d8a` | 09 | Compliance mapping |
| `e0b2587` | 10 | Architecture design |
| `18680e5` | 11 | Resilience & DR plan |
| `1760555` | 12 | Executive summary |
