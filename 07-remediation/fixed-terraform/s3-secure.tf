# Fix for FIND-004/005: S3 public access + no encryption
# Original: terragoat/terraform/aws/s3.tf
# Change: Block all public access + KMS encryption + enforce SSL-only

# -----------------------------------------------------------
# S3 bucket — no public access
# -----------------------------------------------------------
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name

  tags = {
    Environment      = "production"
    DataClassification = "sensitive"
  }
}

# Block ALL public access (4 flags required)
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning for accidental deletion recovery
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

# KMS encryption at rest
resource "aws_kms_key" "s3_key" {
  description             = "S3 data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Rotate annually

  tags = { Name = "s3-data-key" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true  # Reduce KMS API calls cost
  }
}

# Enforce HTTPS-only (FIND-005)
resource "aws_s3_bucket_policy" "enforce_ssl" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyHTTP"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        aws_s3_bucket.data.arn,
        "${aws_s3_bucket.data.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

# Lifecycle: archive to Glacier after 90 days
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "archive-old-data"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}
