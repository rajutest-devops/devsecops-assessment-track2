# GitLeaks Secret Scanning Summary – TerraGoat

**Tool:** GitLeaks  
**Scan Date:** 2026-07-07  
**Raw Output Files:** `gitleaks-secrets.json` · `gitleaks-git-history.json`

---

## What Is GitLeaks?

GitLeaks is an open-source secret scanning tool that detects hardcoded secrets, API keys, tokens, and passwords in:
1. **The current working tree** (all files as they exist now)
2. **Entire git history** (every commit ever made — including deleted lines)

**Why GitLeaks is critical:** Developers often believe that deleting a secret from a file and committing the deletion "removes" the secret. It does not. Git stores every version of every file. Any secret committed to git history is permanently accessible via `git log -p`, `git show <commit-hash>`, or by cloning the repository.

---

## Scan Results

### Scan 1: Current Repository Files

**Total secrets found: 16 detections (4 unique secrets)**

| # | Rule ID | File | Line | Secret Value (Redacted) |
|---|---------|------|------|------------------------|
| 1 | `hashicorp-tf-password` | `terraform/azure/sql.tf` | 15 | `administrator_login_password = "Aa12345678"` |
| 2 | `hashicorp-tf-password` | `terraform/azure/sql.tf` | 83 | `administrator_login_password = "Aa12345678"` |
| 3 | `generic-api-key` | `terraform/aws/ec2.tf` | 16 | `AWS_SECRET_ACCESS_KEY=wJalr***REDACTED***` |
| 4 | `aws-access-token` | `terraform/aws/ec2.tf` | 15 | `AKIA***REDACTED***` |
| 5–16 | `generic-api-key` / `aws-access-token` | `results.sarif` | 1 | Same keys detected in the scan output SARIF file (expected — the SARIF reproduces code snippets containing the keys) |

> **Note:** Detections 5–16 are in `results.sarif` which is a scan output file that contains code snippets of the vulnerable lines. These are not additional secrets — they are the same secrets reproduced in the tool output. The `results.sarif` file should be added to `.gitignore` to prevent committing scan output containing credential snippets.

### Scan 2: Full Git History

**Total secrets found: 5 detections**

| # | Rule ID | File | Line | Commit Context |
|---|---------|------|------|----------------|
| 1 | `hashicorp-tf-password` | `terraform/azure/sql.tf` | 65 | Azure SQL administrator password |
| 2 | `hashicorp-tf-password` | `terraform/azure/postgres.tf` | 11 | Azure PostgreSQL administrator password |
| 3 | `hashicorp-tf-password` | `terraform/azure/sql.tf` | 15 | Azure SQL administrator password |
| 4 | `generic-api-key` | `terraform/ec2.tf` | 17 | AWS Secret Access Key in EC2 user_data (REDACTED) |
| 5 | `aws-access-token` | `terraform/ec2.tf` | 16 | AWS Access Key ID in EC2 user_data (REDACTED) |

---

## Deep Analysis of Each Unique Secret

### Secret 1: AWS Access Key ID
- **Value:** `AKIA***REDACTED***` (full value in raw scan JSON — not reproduced here for security)
- **Location:** `terraform/aws/ec2.tf` line 15, EC2 `user_data` block
- **Type:** AWS IAM Access Key (long-lived, programmatic access)
- **Risk:** This key is in git history permanently. Anyone who has ever cloned this repo has access to it. AWS Access Keys don't expire unless explicitly rotated. The key grants whatever permissions the associated IAM user has.
- **Detection by:** GitLeaks + TFSec `AVD-AWS-0029` + Trivy `AWS-0029`
- **Action Required:** `aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMAAA` — immediately, without waiting

### Secret 2: AWS Secret Access Key
- **Value:** `wJalr***REDACTED***KEY` (in ec2.tf)
- **Location:** `terraform/aws/ec2.tf` line 16
- **Type:** AWS IAM Secret Access Key (pair to Secret 1)
- **Risk:** Together with Secret 1, this forms complete AWS credentials. An attacker can configure `aws configure` with these and access any AWS service the IAM user has permissions to.
- **Additional location:** Also hardcoded in `terraform/aws/lambda.tf` as `secret_key` environment variable

### Secret 3 & 4: Azure SQL Administrator Passwords
- **Value:** `Aa12345678` (hardcoded in both MSSQL and PostgreSQL Terraform resources)
- **Locations:** `terraform/azure/sql.tf` lines 15, 65, 83 · `terraform/azure/postgres.tf` line 11
- **Type:** Database administrator password
- **Risk:** This password grants full admin access (`sa` / admin user) to the SQL Server and PostgreSQL instances. If the RDS is publicly accessible, this is a direct path to the database.
- **Pattern concern:** The same password `Aa12345678` is reused across both MSSQL and PostgreSQL — credential reuse multiplies blast radius.

---

## Why Secrets End Up in Terraform

Understanding this is important for the interview:

1. **Developer convenience:** Writing `password = var.db_password` requires setting a tfvars file. Writing `password = "Aa12345678"` is faster in development.
2. **"I'll change it before production":** Developers intend to clean up but forget, or the code goes to production as-is.
3. **Copy-paste from documentation:** AWS example docs sometimes use placeholder-looking keys like `AKIAIOSFODNN7EXAMPLE` — developers copy these into Terraform assuming they're just examples.
4. **No pre-commit hooks:** Without a `gitleaks` pre-commit hook, there's no gate to stop secrets from entering git.

---

## Correct Patterns (How to Fix)

### AWS credentials: Use IAM Roles, not keys
```hcl
# WRONG — hardcoded key
user_data = "export AWS_ACCESS_KEY_ID=AKIA..."

# RIGHT — IAM instance profile (no key needed)
resource "aws_iam_instance_profile" "web" {
  role = aws_iam_role.web_role.name
}
resource "aws_instance" "web_host" {
  iam_instance_profile = aws_iam_instance_profile.web.name
  # No AWS keys needed — instance inherits role permissions via metadata service
}
```

### Database passwords: Use AWS Secrets Manager
```hcl
# WRONG — hardcoded password
resource "aws_db_instance" "default" {
  password = "Aa12345678"
}

# RIGHT — generate random password, store in Secrets Manager
resource "random_password" "db_password" {
  length  = 32
  special = true
}
resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result
}
resource "aws_db_instance" "default" {
  password = random_password.db_password.result
  # Never hardcoded — never in git — rotatable via Secrets Manager
}
```

### Prevent future secrets: Pre-commit hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```
This runs GitLeaks before every `git commit` — secrets never reach git in the first place.

---

## Git History Cleanup (If Real Credentials)

If these were real credentials (not intentional for training):
```bash
# Install git-filter-repo
pip install git-filter-repo

# Remove all occurrences of the key from history
git filter-repo --replace-text <(echo 'AKIA_YOUR_KEY_HERE==>REDACTED_KEY')

# Force push (coordinate with team — this rewrites all commit hashes)
git push --force-with-lease origin main
```

> ⚠️ **Even after rewriting history, the secret must be considered compromised.** GitHub, GitLab, and Bitbucket may cache old objects. Treat the credential as permanently leaked and rotate immediately.

---

## Interview Talking Point

> *"GitLeaks is unique because it scans git history, not just current files. Developers often think deleting a secret removes it — but git is an append-only log. Every version of every file is stored. I found 5 secrets in the git history of TerraGoat including AWS access keys and Azure database passwords. The correct response to any secret found in git history is: (1) treat it as compromised immediately regardless of whether you think someone saw it, (2) rotate the credential, (3) clean git history with git-filter-repo, (4) add a pre-commit hook so this never happens again."*
