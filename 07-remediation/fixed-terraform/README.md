# Fixed Terraform — Critical & High Findings

This directory contains corrected Terraform for the most critical findings from Module 01.
Each file shows the minimal change needed to remediate the finding.

| File | Finding | Change |
|------|---------|--------|
| `ec2-iam-role.tf` | FIND-001 | Remove hardcoded AWS key → IAM instance profile |
| `lambda-role.tf` | FIND-002 | Remove hardcoded secret → Lambda execution role |
| `s3-secure.tf` | FIND-004/005 | Block public access + KMS encryption + SSL-only |
| `eks-logging.tf` | FIND-020 | Enable EKS control plane logs → CloudWatch |
| `gke-secure.tf` | FIND-011/012/013 | Enable logging + private master + NetworkPolicy |
