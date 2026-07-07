# Severity Methodology

**Assessment:** DevSecOps Track 2 – Multi-Cloud Platform Security  
**Scope:** AWS · Azure · GCP (TerraGoat repository)

---

## How Findings Were Rated

Each finding was rated on two axes:

**Exploitability** — how easy is it for an attacker to actually use this?  
**Impact** — if exploited, what's the worst realistic outcome?

| Severity | Exploitability | Impact | Example |
|---|---|---|---|
| **Critical** | Low effort, no special access needed | Data breach, credential theft, full account compromise | Hardcoded credentials in code, public bucket with PII |
| **High** | Requires some positioning but still practical | Service compromise, lateral movement within cloud | Open SSH from internet, wildcard IAM policy |
| **Medium** | Needs an existing foothold or additional conditions | Reduced visibility, weakened defence-in-depth | Logging disabled, unencrypted volumes |
| **Low** | Edge case or defence-in-depth gap only | Minimal direct impact | Non-critical best-practice deviations |

This assessment has no Low findings documented — TerraGoat's misconfigs are concentrated at Critical/High/Medium.

---

## Tool Coverage

Findings were identified using four tools run against the full Terraform codebase:

- **Checkov** — IaC static analysis, maps to CIS/PCI/SOC2 benchmarks. Raw output: `checkov-*.json`
- **TFSec** — Terraform scanner with native CRITICAL/HIGH/MEDIUM/LOW ratings. Raw output: `tfsec-*.json`
- **Trivy** — Independent misconfiguration scanner (different rule engine from TFSec/Checkov). Raw output: `trivy-*.json`
- **GitLeaks** — Secret scanning across current files and full git history. Raw output: `gitleaks-*.json`

Where two or more tools flag the same issue, confidence is high. Where only one tool flags it, the finding was manually verified against the source Terraform before inclusion in this register.

---

## What Was Not Included

The raw scans produce hundreds of check failures. Most are not in this register because they fall into:

- **Checklist items with no real exploitability** — e.g., missing resource tags, non-standard naming conventions
- **False positives** — tool flagging a pattern that doesn't apply in this context
- **Duplicates** — the same root cause reported multiple times across different sub-resources

The 20 findings in this register represent distinct, exploitable or impactful issues with clear remediation paths.
