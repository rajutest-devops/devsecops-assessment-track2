# High-Level Design (HLD) — Target State Secure Architecture

**Module:** 10 — Architecture  
**View:** System context — major building blocks, trust boundaries, data flow  
**Audience:** Governance panel / non-technical stakeholders

---

## HLD Diagram

```mermaid
graph TB
    %% External actors
    Dev["👤 Developer\n(VPN required)"]
    User["👥 End Users\n(Public Internet)"]
    Panel["🏛️ Governance Panel\n(ITSO / CISO)"]

    %% Source Control & Pipeline
    subgraph SC["Source Control & CI/CD — Trust Boundary: External"]
        GitHub["GitHub / GitLab\nSource Control"]
        Pipeline["CI/CD Pipeline\n[lint → iac-scan → secret-scan]"]
    end

    %% Identity Provider
    subgraph IDP["Identity Layer — Trust Boundary: Corporate"]
        EntraID["Azure Entra ID\nIdentity Provider"]
        OIDC["OIDC Federation\n(GitHub → AWS/Azure/GCP)"]
    end

    %% Cloud Landing Zones
    subgraph AWS["AWS Landing Zone — Trust Boundary: Production"]
        AWSWAF["WAF / CloudFront\nEdge Protection"]
        AWSALB["Application Load Balancer"]
        AWSAPP["App Tier\n[Private Subnet]"]
        AWSDB["RDS / Aurora\n[Encrypted]"]
        AWSS3["S3 Buckets\n[Private + KMS]"]
        AWSKMS["AWS KMS\nKey Management"]
    end

    subgraph AZURE["Azure Landing Zone — Trust Boundary: Production"]
        AzureWAF["Azure WAF\n+ Front Door"]
        AzureApp["App Service\n[Private Endpoint]"]
        AzureSQL["Azure SQL\n[TDE + CMK]"]
        AzureKV["Key Vault\nKey Management"]
    end

    subgraph GCP["GCP Landing Zone — Trust Boundary: Production"]
        CloudArmor["Cloud Armor\nDDoS Protection"]
        GKE["GKE Cluster\n[Private + NetworkPolicy]"]
        CloudSQL["Cloud SQL\n[Encrypted]"]
        GCPKMS["Cloud KMS\nKey Management"]
    end

    %% Centralised Security
    subgraph SEC["Security Platform — Trust Boundary: Security Team Only"]
        CSPM["CSPM\n[Checkov + TFSec continuous]"]
        SIEM["SIEM / Log Analytics\n[CloudWatch + Azure Monitor + GCP Logging]"]
        Alerts["Alert Manager\n[PagerDuty / Opsgenie]"]
        SecretsM["Secrets Manager\n[AWS SM / Azure KV / GCP SM]"]
    end

    %% Flows
    Dev -->|"HTTPS + MFA"| GitHub
    GitHub --> Pipeline
    Pipeline -->|"OIDC token\n(no keys)"| OIDC
    OIDC --> AWS
    OIDC --> AZURE
    OIDC --> GCP

    User -->|"HTTPS"| AWSWAF
    User -->|"HTTPS"| AzureWAF
    User -->|"HTTPS"| CloudArmor

    AWSWAF --> AWSALB --> AWSAPP --> AWSDB
    AWSAPP --> AWSS3
    AWSAPP --> AWSKMS
    AWSDB --> AWSKMS

    AzureWAF --> AzureApp --> AzureSQL
    AzureSQL --> AzureKV

    CloudArmor --> GKE --> CloudSQL
    GKE --> GCPKMS

    AWS -->|"Logs"| SIEM
    AZURE -->|"Logs"| SIEM
    GCP -->|"Logs"| SIEM
    SIEM --> Alerts
    CSPM --> SIEM

    EntraID -->|"SSO / RBAC"| AWS
    EntraID -->|"SSO / RBAC"| AZURE
    EntraID -->|"SSO / RBAC"| GCP

    Panel -->|"Risk decisions"| SEC

    %% Styling
    classDef external fill:#ffcccc,stroke:#cc0000,color:#111111,stroke-width:2px
    classDef identity fill:#ffe0cc,stroke:#cc6600,color:#111111,stroke-width:2px
    classDef cloud fill:#ccffcc,stroke:#006600,color:#111111,stroke-width:2px
    classDef security fill:#cce0ff,stroke:#0000cc,color:#111111,stroke-width:2px
    class Dev,User,Panel external
    class EntraID,OIDC identity
    class AWSWAF,AWSALB,AWSAPP,AWSDB,AWSS3,AWSKMS cloud
    class AzureWAF,AzureApp,AzureSQL,AzureKV cloud
    class CloudArmor,GKE,CloudSQL,GCPKMS cloud
    class CSPM,SIEM,Alerts,SecretsM security
```

---

## Trust Boundaries

| Boundary | What It Protects | Mechanism |
|----------|-----------------|-----------|
| **External → SC** | Prevent unauthorised code push | MFA + branch protection + required reviewers |
| **SC → Cloud** | Prevent credential theft | OIDC tokens (1-hour, no long-lived keys) |
| **Public → Edge** | DDoS, injection, bot attacks | WAF + Cloud Armor + rate limiting |
| **Edge → App** | Direct database access | Private subnets, no public IPs on DB |
| **App → Security** | Log tampering | Immutable log archive (separate account) |
| **Human → Cloud** | Unauthorised admin access | MFA + Conditional Access + JIT |

---

## Data Flow (Non-Technical Description)

1. **Developer** pushes code → Pipeline scans for secrets + misconfigs before merge
2. **Pipeline** deploys to cloud using short-lived token (no password stored)
3. **User** hits WAF edge → request routed to private app tier
4. **App** reads encrypted database → decryption key fetched from KMS (never stored in code)
5. **Every action** logs to centralised SIEM → alerts fire on anomalies
6. **ITSO** reviews risk dashboard → approves exceptions via governance workflow

---

## What Changed vs Current State

| Current State | Target State |
|---------------|--------------|
| Hardcoded credentials in code | OIDC + IAM roles (no credentials) |
| No CSPM | Checkov + TFSec continuous scanning |
| Inconsistent logging | Centralised SIEM (all 3 clouds) |
| No MFA enforcement | Conditional Access (all admins) |
| Public S3 buckets | Private + KMS encrypted |
| No secrets management | AWS SM / Azure KV / GCP SM |
