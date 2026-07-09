# Low-Level Design (LLD) — AWS Production Slice

**Module:** 10 — Architecture  
**View:** Implementation detail — engineer-facing, one representative slice  
**Slice:** AWS ingress → App → RDS + the CI/CD path that provisions it

---

## LLD Diagram: AWS Production Path

```mermaid
graph TB
    %% External
    Internet["🌐 Internet\n(Public Users)"]
    Dev["👤 Developer\n(Corp VPN: 203.0.113.0/24)"]
    GH["GitHub Actions\nCI/CD Runner"]

    %% AWS Account boundary
    subgraph PROD["AWS Account: production-123456789012"]

        %% Edge
        subgraph EDGE["Edge / DMZ Tier — public subnets 10.0.0.0/24, 10.0.1.0/24"]
            WAF["AWS WAF\nRules: OWASP top 10\nRate limit: 1000 req/min"]
            CF["CloudFront\nOrigin: ALB\nSSL: TLS 1.2+"]
            ALB["Application Load Balancer\nHTTPS only (port 443)\nHTTP → HTTPS redirect"]
        end

        %% App Tier
        subgraph APP["App Tier — private subnets 10.0.10.0/24, 10.0.11.0/24"]
            EC2a["EC2: app-01\nAMI: ami-hardened\nIMDSv2 required\nIAM role: app-role"]
            EC2b["EC2: app-02\nAMI: ami-hardened\nIMDSv2 required\nIAM role: app-role"]
            IAMRole["IAM Role: app-role\nPermissions:\n- rds:Connect\n- s3:GetObject\n- secretsmanager:GetSecret\nNO wildcard actions"]
        end

        %% Data Tier
        subgraph DATA["Data Tier — isolated subnets 10.0.20.0/24, 10.0.21.0/24"]
            RDS["RDS Aurora PostgreSQL\nMulti-AZ: enabled\nEncrypted: KMS key\nPublicly accessible: false\nPort 5432 from app-sg only"]
            S3["S3: production-data\nPublic access: blocked\nEncryption: SSE-KMS\nVersioning: enabled\nSSL-only policy"]
        end

        %% Security & Key Management
        subgraph SEC["Security Services"]
            KMS["AWS KMS\nKey: data-encryption-key\nRotation: annual\nAdmins: security-team only"]
            SM["Secrets Manager\nDB credentials (auto-rotate 90d)\nAPI keys\nNo hardcoded values in code"]
            CW["CloudWatch Logs\nRetention: 90 days\nLog groups:\n/aws/ec2/app\n/aws/rds/prod\n/aws/waf/prod"]
            CT["CloudTrail\nS3 bucket: audit-logs\nLog file validation: true\nObject Lock: 7 years"]
            SG_WEB["Security Group: web-sg\nIngress: 443 from 0.0.0.0/0\nEgress: 5432 to db-sg"]
            SG_DB["Security Group: db-sg\nIngress: 5432 from web-sg ONLY\nEgress: none"]
        end

        %% Bastion / Admin
        subgraph ADMIN["Management — mgmt subnet 10.0.30.0/24"]
            SSM["AWS Systems Manager\nSession Manager\n(No SSH, no port 22)"]
        end
    end

    %% CI/CD Path
    subgraph CICD["CI/CD Pipeline (GitHub Actions)"]
        Checkout["actions/checkout\nSHA pinned"]
        Scan["iac-scan\nCheckov + TFSec"]
        SecretScan["secret-scan\nGitLeaks"]
        TFPlan["terraform plan\n(preview only)"]
        Approve["Manual approval\nRequired for prod"]
        TFApply["terraform apply\n(OIDC token — no keys)"]
    end

    %% OIDC
    OIDC["OIDC Provider\ngithub.com/actions\n→ AWS STS AssumeRole\n(1-hour token)"]

    %% Flows — user traffic
    Internet -->|"HTTPS"| CF
    CF -->|"HTTPS"| WAF
    WAF -->|"Filtered"| ALB
    ALB -->|"HTTP 8080"| EC2a
    ALB -->|"HTTP 8080"| EC2b

    EC2a -->|"Port 5432\n(SSL required)"| RDS
    EC2b -->|"Port 5432\n(SSL required)"| RDS
    EC2a -->|"HTTPS\n(SSL-only)"| S3
    EC2a -->|"GetSecret"| SM
    SM -->|"Decrypt via"| KMS
    RDS -->|"Encrypted with"| KMS

    %% Admin access — no direct SSH
    Dev -->|"VPN → SSM\n(no SSH)"| SSM
    SSM -->|"SSM Agent"| EC2a

    %% Logging
    EC2a -->|"App logs"| CW
    RDS -->|"DB logs"| CW
    WAF -->|"WAF logs"| CW
    ALB -->|"Access logs"| CW
    CW -->|"Archive"| CT

    %% CI/CD flow
    Dev -->|"git push"| GH
    GH --> Checkout --> Scan --> SecretScan --> TFPlan --> Approve --> TFApply
    TFApply -->|"OIDC token"| OIDC
    OIDC -->|"1-hour temp creds"| PROD

    %% IAM
    EC2a -.->|"assumes"| IAMRole
    EC2b -.->|"assumes"| IAMRole

    %% Security groups
    SG_WEB -.->|"attached to"| EC2a
    SG_WEB -.->|"attached to"| EC2b
    SG_DB -.->|"attached to"| RDS

    %% Styling
    classDef edge fill:#ffe0cc,stroke:#cc6600,color:#111111,stroke-width:2px
    classDef app fill:#ccffcc,stroke:#006600,color:#111111,stroke-width:2px
    classDef data fill:#cce0ff,stroke:#0000cc,color:#111111,stroke-width:2px
    classDef sec fill:#ffccff,stroke:#660066,color:#111111,stroke-width:2px
    classDef cicd fill:#ffffcc,stroke:#666600,color:#111111,stroke-width:2px
    class WAF,CF,ALB edge
    class EC2a,EC2b,IAMRole app
    class RDS,S3 data
    class KMS,SM,CW,CT,SG_WEB,SG_DB sec
    class Checkout,Scan,SecretScan,TFPlan,Approve,TFApply cicd
```

---

## Port/Protocol Detail

| Source | Destination | Port | Protocol | Notes |
|--------|-------------|------|----------|-------|
| Internet | CloudFront | 443 | HTTPS/TLS 1.2+ | HTTP → 301 redirect |
| CloudFront | ALB | 443 | HTTPS | Origin shield enabled |
| ALB | EC2 | 8080 | HTTP | Internal only, private subnet |
| EC2 | RDS | 5432 | PostgreSQL/SSL | `rds.force_ssl=1` |
| EC2 | S3 | 443 | HTTPS | SSL-only bucket policy |
| EC2 | Secrets Manager | 443 | HTTPS | VPC endpoint |
| EC2 | KMS | 443 | HTTPS | VPC endpoint |
| Admin | EC2 | (none) | SSM Session | No port 22, no SSH key |
| CI/CD | AWS | 443 | HTTPS | OIDC STS token exchange |

---

## IAM: Specific Permissions per Component

| Component | Role | Permissions | NOT granted |
|-----------|------|-------------|-------------|
| EC2 (app) | `app-role` | `rds:Connect`, `s3:GetObject`, `secretsmanager:GetSecret` | `s3:DeleteObject`, `iam:*`, `ec2:*` |
| CI/CD | `cicd-deploy-role` | `ec2:DescribeInstances`, `s3:PutObject` (deploy bucket) | `iam:CreateUser`, `rds:DeleteDBInstance` |
| RDS | N/A (managed) | Internal only | No public IAM role needed |
| CloudTrail | `cloudtrail-role` | `s3:PutObject` (audit bucket) | Read access to audit bucket |

---

## Encryption at Every Layer

| Layer | At Rest | In Transit | Key Location |
|-------|---------|------------|-------------|
| EC2 root volume | KMS CMK | N/A | AWS KMS |
| RDS data | KMS CMK | TLS (force_ssl=1) | AWS KMS |
| S3 objects | SSE-KMS | SSL-only policy | AWS KMS |
| Secrets Manager | KMS CMK | HTTPS | AWS KMS |
| CloudTrail logs | SSE-S3 | HTTPS | AWS managed |

---

## Where Pipeline + Detection Sit

| Component | Physical Location | Integration |
|-----------|------------------|-------------|
| CI/CD (GitHub Actions) | GitHub-hosted runner | Deploys via OIDC → no credentials stored |
| Checkov/TFSec | CI/CD runner | Runs on PR — blocks merge if CRITICAL |
| GitLeaks | CI/CD runner | Blocks push if secrets found |
| CloudWatch | AWS managed | Receives logs from EC2, RDS, WAF, ALB |
| CloudTrail | AWS managed | Immutable audit trail in S3 (Object Lock) |
| SSM Session Manager | AWS managed | Admin access (no SSH port open) |
