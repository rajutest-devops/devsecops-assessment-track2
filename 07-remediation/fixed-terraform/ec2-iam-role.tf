# Fix for FIND-001: Remove hardcoded AWS access key from EC2
# Original: terragoat/terraform/aws/ec2.tf
# Change: Replace hardcoded credentials with IAM instance profile

# -----------------------------------------------------------
# Create IAM role for EC2 (no hardcoded keys)
# -----------------------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "ec2-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Least-privilege: S3 read-only to specific bucket
resource "aws_iam_role_policy" "ec2_s3_access" {
  name = "ec2-s3-read"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::${var.data_bucket_name}",
        "arn:aws:s3:::${var.data_bucket_name}/*"
      ]
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-app-profile"
  role = aws_iam_role.ec2_role.name
}

# -----------------------------------------------------------
# EC2 instance: uses role, no credentials in user_data
# -----------------------------------------------------------
resource "aws_instance" "web_server" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"  # t2.micro EOL, use t3
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.web.id]

  # AWS SDK automatically reads credentials from metadata service
  # No AWS_ACCESS_KEY_ID, no AWS_SECRET_ACCESS_KEY
  user_data = base64encode(<<-EOF
    #!/bin/bash
    aws s3 ls s3://${var.data_bucket_name}/  # Works via IAM role
  EOF
  )

  metadata_options {
    http_tokens   = "required"   # IMDSv2 only (prevents SSRF attacks)
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted = true  # Encrypt root volume
  }

  tags = { Name = "web-server" }
}
