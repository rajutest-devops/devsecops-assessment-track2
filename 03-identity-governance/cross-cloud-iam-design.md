# Cross-Cloud Identity & Governance

**Module:** 03 – Identity & Governance  
**Findings:** FIND-001, FIND-002, FIND-006, FIND-007, FIND-010, FIND-014, FIND-015

---

## Key Issues & Solutions

| Finding | Issue | Solution | Why |
|---------|-------|----------|-----|
| FIND-001/002 | AWS hardcoded keys in code | IAM roles + STS AssumeRole | Temporary creds (expire), auto-rotate, full audit |
| FIND-006 | Azure no MFA for admins | Conditional Access policy | Block risky access (weak device, unknown location) |
| FIND-007 | Azure weak password policy | 14+ chars, symbols, 90-day expiry | Resist brute force & long-term compromise |
| FIND-010 | GCP wildcard IAM `*:*` | Resource + action-specific role | Limit blast radius if service compromised |
| FIND-014 | Azure overpermissioned roles | RBAC scoping per resource | Principle of least privilege |
| FIND-015 | GCP service account key file | Workload Identity + OIDC token | No long-lived keys, per-repo isolation |

---

## AWS: Remove Hardcoded Keys → IAM Roles

**Problem:** Credentials in code never expire, visible in logs/tfstate/git history  
**Solution:** EC2/Lambda gets role → automatic temporary credentials from metadata service

**Key Fix:**
```hcl
# OLD: Hardcoded keys (FIND-001)
export AWS_ACCESS_KEY_ID="AKIA2EXAMPLE1234567"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

# NEW: IAM role (automatic credentials every 15 min)
resource "aws_iam_instance_profile" "ec2_profile" {
  role = aws_iam_role.ec2_s3_role.name
}
resource "aws_instance" "web_server" {
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  # EC2 fetches from 169.254.169.254 → no keys in code
}
```

**Cross-Account (FIND-002):**
```hcl
# Lambda assumes role in different account (with ExternalId protection)
resource "aws_iam_role_policy" "cross_account" {
  policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Resource = "arn:aws:iam::123456789012:role/external-role"
      Condition = { StringEquals = { "sts:ExternalId" = "secret-id" } }
    }]
  })
}
```

---

## Azure: Managed Identities + Conditional Access

**Problem (FIND-006):** Admins can sign in from anywhere, anytime, no MFA  
**Solution:** Conditional Access blocks risky access + Managed Identity removes credential management

**Key Fix:**
```hcl
# Managed Identity (no credentials to manage)
resource "azurerm_user_assigned_identity" "app_identity" {
  name = "app-processor-identity"
}
resource "azurerm_linux_virtual_machine" "app_vm" {
  identity { type = "UserAssigned"; identity_ids = [azurerm_user_assigned_identity.app_identity.id] }
}

# MFA required for admins
resource "azurerm_conditional_access_policy" "require_mfa" {
  state = "enabled"
  conditions {
    users { included_roles = ["62e90394-69f5-4237-9190-012177145e10"] } # Global Admin
  }
  grant_controls { built_in_controls = ["mfa"] }
}

# Strong password (FIND-007)
resource "azuread_directory_password_policy" "strong" {
  min_password_length      = 14
  enforce_complex_password = true
  max_password_age_days    = 90
}
```

---

## GCP: Workload Identity + Least-Privilege IAM

**Problem (FIND-015):** Service account keys never expire, exposed in tfstate  
**Solution:** OIDC federation → 1-hour tokens + per-repo isolation

**Problem (FIND-010):** Wildcard IAM `*:*` means compromised service can delete everything  
**Solution:** Custom role with only needed actions

**Key Fix:**
```hcl
# Workload Identity Pool (OIDC)
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-pool"
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

# GitHub Actions gets 1-hour token (no service account key file)
resource "google_service_account_iam_member" "github_binding" {
  role = "roles/iam.workloadIdentityUser"
  member = "principalSet://iam.googleapis.com/projects/PROJECT/locations/global/workloadIdentityPools/github-pool/attribute.repository/ORG/REPO"
}

# Least-privilege: Only deploy to Cloud Run, read secrets
resource "google_project_iam_custom_role" "deployer" {
  included_permissions = [
    "run.services.update",
    "run.services.get",
    "secretmanager.secrets.get",
    "secretmanager.versions.access"
  ]
}
```

---

## Human Privileged Access (Break-Glass + JIT)

Machine identity controls do not replace human privileged-access governance. This section covers emergency and time-bound admin patterns required by the brief.

### Break-Glass (Emergency Access)

- Two emergency admin accounts are created per cloud tenant/subscription/account.
- Credentials are vaulted, sealed, and access is dual-approved (security lead + platform lead).
- Use only when SSO, federation, or policy engines are unavailable.
- Every use triggers mandatory post-incident review within 24 hours.

### Time-Bound Privileged Access (JIT/PIM)

- Azure: Privileged Identity Management (PIM) eligible roles, activation window 1-4 hours.
- AWS: Privileged role assumption via IAM Identity Center with max session duration and approval workflow.
- GCP: IAM Conditions grant temporary elevation with expiry timestamp.
- Production admin access requires ticket reference, justification, and approver identity.

### Audit and Forensics Controls

- All privilege elevation events are logged to immutable audit stores.
- Minimum retained fields: requester, approver, role, duration, ticket ID, source IP, and command history where possible.
- Control objective: every privileged session is attributable, time-boxed, and reviewable.

### Example Control Policy (Provider-Neutral)

| Control | Requirement |
|---|---|
| Approval | At least one approver outside requester chain |
| Session Length | Max 4 hours (default 1 hour) |
| MFA | Mandatory before elevation |
| Justification | Required ticket/change ID |
| Session Recording | Required for production access |
| Post-Use Review | Security review within 24 hours |

---

## Notable Points

**Q: Why not just use service account keys?**  
> "Keys never expire — one leaked key means permanent access. Temporary credentials (1 hour) + auto-rotation limit blast radius. If a key leaks, it's only valid for 1 hour. We also get full audit trail showing who accessed what when."

**Q: Why Workload Identity for GitHub → GCP?**  
> "OIDC token is tied to a specific GitHub repo + job. Service account keys aren't. If we stored keys in GitHub secrets, one compromised repo = all repos can access GCP. With OIDC, only that specific repo gets access."

**Q: Why force MFA on Azure admins?**  
> "Compromised password isn't enough. Even if attacker has admin password, they still need the phone/authenticator. Conditional Access also blocks logon from unusual locations/old browsers."

**Q: Why specific IAM permissions instead of `*`?**  
> "Blast radius. If a microservice is compromised, it should only do exactly what that service needs. Wildcard means attacker can delete databases, extract secrets, disable monitoring. Least privilege = defense in depth."

---

## Remediation Status

| Finding | Action | Status |
|---------|--------|--------|
| FIND-001 | Remove AWS keys → IAM role | ✅ Documented |
| FIND-002 | Lambda cross-account assume | ✅ Documented |
| FIND-006 | Azure Conditional Access + MFA | ✅ Documented |
| FIND-007 | Azure strong password policy | ✅ Documented |
| FIND-010 | GCP least-privilege IAM | ✅ Documented |
| FIND-014 | Azure RBAC scoping | ✅ Documented |
| FIND-015 | GCP Workload Identity | ✅ Documented |
