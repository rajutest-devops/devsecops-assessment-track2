# Cross-Cloud Identity & Governance

**Module:** 03 – Identity & Governance  
**Assessment:** DevSecOps Track 2 – Multi-Cloud Platform Security  
**Date:** 2026-07-08

---

## Executive Summary

TerraGoat stores credentials directly in Terraform code and relies on overpermissioned IAM roles. This module addresses 7 findings across AWS, Azure, and GCP through temporary credential issuance, least-privilege RBAC, and managed identities.

| Finding | Issue | Severity | Solution |
|---------|-------|----------|----------|
| FIND-001 | AWS access key in ec2.tf | Critical | → AWS STS AssumeRole with temporary creds |
| FIND-002 | AWS secret key in lambda.tf | Critical | → Lambda IAM role + assume role chain |
| FIND-006 | Azure AD no MFA enforcement | High | → Conditional access policies |
| FIND-007 | Azure default password policy weak | High | → Custom strong policy (12+ chars, symbols) |
| FIND-010 | Wildcard IAM permissions `*:*` | High | → Resource-specific, action-specific policy |
| FIND-014 | Azure role assignments overly broad | High | → RBAC scoping per resource |
| FIND-015 | GCP service account no federation | High | → Workload Identity Pool + OIDC |

---

## AWS: Temporary Credentials via STS AssumeRole

### The Problem

**Current state (vulnerable):**
```hcl
# terragoat/terraform/aws/ec2.tf - Line 5
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  
  # HARDCODED CREDENTIALS - NEVER DO THIS
  user_data = base64encode(<<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID="AKIA2EXAMPLE1234567"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    aws s3 ls
  EOF
  )
}
```

**Risks:**
1. Keys in code repositories are searchable via GitHub, GitLab, commit history
2. Keys don't expire — one compromise = permanent access
3. Keys appear in logs, terraform.tfstate, CI/CD output
4. No audit trail (who used the key, when, which API calls)

---

### The Solution: IAM Roles + AssumeRole

**Fixed code (secure):**

```hcl
# Create an IAM role for the EC2 instance
resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2-s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Policy: S3 read-only for specific bucket (least privilege)
resource "aws_iam_role_policy" "s3_read_only" {
  name = "s3-read-only"
  role = aws_iam_role.ec2_s3_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Resource = [
        "arn:aws:s3:::production-data-bucket",
        "arn:aws:s3:::production-data-bucket/*"
      ]
    }]
  })
}

# Attach role to instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-s3-profile"
  role = aws_iam_role.ec2_s3_role.name
}

resource "aws_instance" "web_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # No credentials in code. Role automatically applied.
  # EC2 metadata service provides temporary credentials (auto-rotate).
  user_data = base64encode(<<-EOF
    #!/bin/bash
    # AWS SDK automatically uses instance role credentials
    aws s3 ls  # Works without env vars
  EOF
  )
}
```

**How it works:**
1. EC2 instance launched with IAM role
2. Instance metadata service (169.254.169.254) provides temporary credentials
3. AWS SDK reads from metadata → no hardcoded keys
4. Credentials auto-rotate every 15 minutes
5. CloudTrail logs all API calls with principal ARN (full audit)

**Key Principles:**
- ✅ Roles expire automatically
- ✅ No credentials in code/logs/tfstate
- ✅ Fine-grained permissions per resource
- ✅ Full audit trail in CloudTrail

---

## AWS Lambda: Cross-Account Assume Role

### Scenario: Microservice needs to access another AWS account

**Problem (FIND-002):**
```hcl
# terragoat/terraform/aws/lambda.tf - Line 15
# Hardcoded credentials in environment variable
resource "aws_lambda_function" "data_processor" {
  filename      = "lambda.zip"
  function_name = "data-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      AWS_ACCESS_KEY_ID     = "AKIA2EXAMPLE1234567"
      AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
      EXTERNAL_ACCOUNT_ID   = "123456789012"
    }
  }
}
```

**Solution:**

```hcl
# Account A: Create Lambda role
resource "aws_iam_role" "lambda_role" {
  name = "lambda-processor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Account A: Allow Lambda to assume role in Account B
resource "aws_iam_role_policy" "lambda_cross_account" {
  name = "lambda-assume-external-role"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Resource = "arn:aws:iam::123456789012:role/external-data-access-role"
      Condition = {
        StringEquals = {
          "sts:ExternalId" = "unique-external-id-12345"
        }
      }
    }]
  })
}

resource "aws_lambda_function" "data_processor" {
  filename      = "lambda.zip"
  function_name = "data-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  environment {
    variables = {
      EXTERNAL_ACCOUNT_ID = "123456789012"
      EXTERNAL_ROLE_NAME  = "external-data-access-role"
      EXTERNAL_ID         = "unique-external-id-12345"
      # NO HARDCODED CREDENTIALS
    }
  }
}
```

**Lambda function code (Python):**

```python
import boto3
import os

sts_client = boto3.client('sts')

def assume_external_role():
    """Use temporary STS credentials, not hardcoded keys."""
    response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{os.environ['EXTERNAL_ACCOUNT_ID']}:role/{os.environ['EXTERNAL_ROLE_NAME']}",
        RoleSessionName="lambda-session",
        ExternalId=os.environ['EXTERNAL_ID'],
        DurationSeconds=3600
    )
    
    return boto3.client(
        's3',
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken']
    )

def handler(event, context):
    s3_client = assume_external_role()
    # Use s3_client for cross-account operations
    return {"statusCode": 200}
```

**Security Benefits:**
- Credentials never hardcoded
- External ID adds extra layer of protection
- Session token expires in 1 hour (or custom duration)
- Full CloudTrail audit trail

---

## Azure: Managed Identities & Conditional Access

### The Problem (FIND-006, FIND-007)

**Current vulnerabilities:**

```hcl
# terragoat/terraform/azure/policies.tf
# No MFA requirement for privileged roles
resource "azurerm_role_assignment" "contributor_role" {
  scope              = azurerm_resource_group.main.id
  role_definition_id = "/subscriptions/.../providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
  principal_id       = azuread_user.admin.id
  # NO CONDITIONAL ACCESS - admin can sign in from any location, any device, any time
}
```

**Issues:**
- No MFA enforcement
- No location restrictions
- Weak password policy (default Azure: 8 chars, no symbols)

---

### The Solution: Managed Identities + Conditional Access

**Step 1: Replace service principals with managed identities**

```hcl
# Create managed identity (no credentials to manage)
resource "azurerm_user_assigned_identity" "app_identity" {
  name                = "app-processor-identity"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
}

# Assign to App Service/VM
resource "azurerm_linux_virtual_machine" "app_vm" {
  name                = "app-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  size                = "Standard_B2s"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app_identity.id]
  }

  # ... other config ...
}

# Grant permissions to the managed identity (not credentials)
resource "azurerm_role_assignment" "app_key_vault_access" {
  scope              = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id       = azurerm_user_assigned_identity.app_identity.principal_id
}
```

**Step 2: Enforce MFA for all administrative access**

```hcl
# Conditional Access Policy: MFA required for privileged roles
resource "azurerm_conditional_access_policy" "require_mfa_for_admin" {
  display_name = "Require MFA for Administrator roles"
  state        = "enabled"

  conditions {
    users {
      included_roles = [
        "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
        "10dae51f-b6af-4016-8d66-8c2a99b929b3"   # Application Administrator
      ]
    }

    applications {
      included_applications = ["All"]
    }

    client_app_types = ["All"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
```

**Step 3: Enforce strong password policy**

```hcl
resource "azuread_directory_password_policy" "strong_pwd" {
  enforce_complex_password = true
  min_password_length      = 14
  max_password_age_days    = 90
}
```

**Benefits:**
- ✅ No credentials to store/rotate manually
- ✅ MFA enforced for all admins
- ✅ Location-based restrictions
- ✅ Device compliance checks
- ✅ Full audit trail in Azure AD

---

## GCP: Service Account Federation & Workload Identity

### The Problem (FIND-015)

**Current vulnerable approach:**
```hcl
# terragoat/terraform/gcp/instances.tf
# Service account key stored as file
resource "google_service_account" "app_sa" {
  account_id = "app-processor"
}

resource "google_service_account_key" "app_key" {
  service_account_id = google_service_account.app_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
}

# Key exposed in tfstate
# Key never rotated
# Key used across multiple environments
```

---

### The Solution: Workload Identity Federation

**Step 1: Create Workload Identity Pool (OIDC)**

```hcl
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-pool"
  location                  = "global"
  display_name              = "GitHub Actions OIDC"
  disabled                  = false

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.aud"        = "assertion.aud"
    "attribute.repository" = "assertion.repository"
  }
}

# Configure GitHub as OIDC provider
resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github"
  location                           = "global"
  display_name                       = "GitHub Provider"
  disabled                           = false

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# Allow GitHub repo to use this identity
resource "google_service_account_iam_member" "github_workload_identity_binding" {
  service_account_id = google_service_account.app_sa.name
  role               = "roles/iam.workloadIdentityUser"

  member = "principalSet://iam.googleapis.com/projects/${data.google_client_config.current.project_id}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/attribute.repository/rajutest-devops/terragoat"
}
```

**Step 2: GitHub Actions uses OIDC token (no service account key)**

```yaml
# .github/workflows/deploy-gcp.yml
name: Deploy to GCP

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: 'read'
      id-token: 'write'

    steps:
      - uses: actions/checkout@v4

      # Get ID token from GitHub Actions
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/PROJECT_ID/locations/global/workloadIdentityPools/github-pool/providers/github'
          service_account_email: 'app-processor@PROJECT_ID.iam.gserviceaccount.com'
          token_format: 'access_token'
          access_token_lifetime: '3600s'

      - uses: google-github-actions/setup-gcloud@v2

      - run: |
          gcloud compute instances list --project=${{ secrets.GCP_PROJECT_ID }}
          # No service account key needed
```

**Benefits:**
- ✅ No long-lived service account keys
- ✅ Tokens valid for 1 hour only
- ✅ Full audit trail (who, when, which repo)
- ✅ Per-repo token isolation
- ✅ Can revoke without regenerating

---

## GCP: Least Privilege IAM (FIND-010)

### The Problem

```hcl
# Wildcard permissions - DANGEROUS
resource "google_project_iam_custom_role" "overpermissioned" {
  role_id     = "custom.allAccess"
  title       = "All Access"
  description = "Can do everything - DON'T USE THIS"

  included_permissions = [
    "compute.*",      # All compute engine operations
    "storage.*",      # All storage operations
    "*"               # EVERYTHING
  ]
}
```

---

### The Solution: Resource & Action Specific

```hcl
# Custom role: Deploy app to Cloud Run (specific only)
resource "google_project_iam_custom_role" "cloud_run_deployer" {
  role_id     = "custom.cloudRunDeployer"
  title       = "Cloud Run Deployer"
  description = "Deploy to production Cloud Run services only"

  included_permissions = [
    # Deploy new revisions
    "run.services.update",
    "run.services.get",
    "run.services.list",
    
    # Push images to Artifact Registry
    "artifactregistry.repositories.get",
    "artifactregistry.files.get",
    "artifactregistry.files.list",
    
    # Read secrets for environment vars
    "secretmanager.secrets.get",
    "secretmanager.versions.access",
    
    # That's it - nothing else
  ]
}

# Assign with resource conditions
resource "google_project_iam_member" "deployer_binding" {
  project = var.project_id
  role    = google_project_iam_custom_role.cloud_run_deployer.id
  member  = "serviceAccount:cicd-deployer@${var.project_id}.iam.gserviceaccount.com"

  condition {
    title       = "Only production environment"
    description = "Can only deploy to production Cloud Run services"
    expression  = "resource.matchTag('env', 'production')"
  }
}
```

---

## Remediation Mapping

| Finding | Module | Action | Status |
|---------|--------|--------|--------|
| FIND-001 | 03 | Remove hardcoded AWS keys → use IAM roles | Documented |
| FIND-002 | 03 | Remove AWS secret from Lambda env → assume role | Documented |
| FIND-006 | 03 | Enforce MFA via Conditional Access | Documented |
| FIND-007 | 03 | Enforce 14-char password policy | Documented |
| FIND-010 | 03 | Replace wildcard IAM → specific permissions | Documented |
| FIND-014 | 03 | Scope Azure roles per resource | Documented |
| FIND-015 | 03 | Replace service account key → Workload Identity | Documented |

---

## Implementation Checklist

- [ ] AWS: Deploy EC2 instance with IAM role (no hardcoded keys)
- [ ] AWS: Lambda cross-account assume role with external ID
- [ ] Azure: Migrate service principals → managed identities
- [ ] Azure: Deploy Conditional Access policy (MFA for admins)
- [ ] Azure: Enforce strong password policy (14+ chars, symbols)
- [ ] GCP: Create Workload Identity Pool (OIDC federation)
- [ ] GCP: Deprecate all service account key files
- [ ] All: Audit CloudTrail / Azure Activity / GCP Audit Logs for verification

---

## Interview Talking Points

**Why no hardcoded credentials?**
> "Credentials in code are permanently valid. If someone gets them, they can access your AWS account indefinitely. Instead, we use IAM roles that provide temporary credentials (valid 1 hour) that auto-rotate. If compromised, the damage window is limited to 1 hour, and we can immediately detect it in CloudTrail."

**Why Workload Identity instead of service account keys?**
> "Service account keys never expire — they're a permanent access mechanism. Workload Identity uses OIDC tokens that are valid for 1 hour and tied to a specific GitHub repo. We get both security (expiration) and auditability (full trace of which repo requested access)."

**Why least-privilege IAM?**
> "If an attacker compromises one service, they should only be able to do exactly what that service needs. A wildcard `*:*` permission means a compromised service can delete production databases, export all data, disable monitoring, etc. With least-privilege, they can only perform the specific actions that service is designed to do."

---

## References

- [AWS IAM Roles for EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html)
- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [Azure Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)
- [Azure Conditional Access](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/)
- [GCP Workload Identity Federation](https://cloud.google.com/docs/authentication/workload-identity-federation)
- [GCP Least Privilege IAM](https://cloud.google.com/docs/authentication#least_privilege)
