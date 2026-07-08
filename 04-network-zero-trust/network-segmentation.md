# Network Segmentation & Zero Trust

**Module:** 04 – Network & Zero Trust  
**Findings:** FIND-008, FIND-009, FIND-012, FIND-013

---

## Key Issues & Solutions

| Finding | Issue | Solution | Why |
|---------|-------|----------|-----|
| FIND-008 | AWS port 22 (SSH) open to 0.0.0.0/0 | Restrict to specific IPs/VPC | Prevents brute force, exploit attempts from internet |
| FIND-009 | AWS port 3389 (RDP) open to 0.0.0.0/0 | Remove or restrict to bastion host | No direct RDP from internet (lateral movement vector) |
| FIND-012 | GKE master endpoint public | Authorized networks only | Only admin IPs can reach Kubernetes API |
| FIND-013 | GKE no NetworkPolicies | Add ingress/egress rules | Prevent pod-to-pod lateral movement |

---

## AWS: Restrict SSH/RDP Access

**Problem:** Port 22 & 3389 open to world = anyone can attack  
**Solution:** Restrict to specific IPs or use Systems Manager Session Manager (no SSH needed)

**Key Fix:**
```hcl
# OLD: SSH open to 0.0.0.0/0 (FIND-008)
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # DANGER
  }
}

# NEW: SSH only from corporate VPN/office IP
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/32"]  # Your office IP only
  }
}

# BETTER: Use Systems Manager (no SSH port exposed)
resource "aws_iam_role_policy" "ssm_access" {
  policy = jsonencode({
    Statement = [{
      Action = [
        "ssm:StartSession",
        "ec2messages:GetMessages",
        "ssmmessages:CreateControlChannel"
      ]
      Resource = "*"
    }]
  })
}
# Connect via: aws ssm start-session --target i-12345678
```

**RDP Restriction (FIND-009):**
```hcl
# OLD: RDP open (FIND-009)
resource "aws_security_group" "windows" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # DANGER
  }
}

# NEW: RDP only through bastion host
resource "aws_security_group" "windows" {
  ingress {
    from_port       = 3389
    to_port         = 3389
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]  # Bastion only
  }
}

resource "aws_security_group" "bastion" {
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/32"]  # Admin IP only
  }
}
```

---

## Azure: Network Security Groups (NSG) + Deny by Default

**Problem:** Open SSH/RDP on any Azure resource  
**Solution:** NSG rules: deny all inbound, allow specific ports from known IPs only

**Key Fix:**
```hcl
# Deny all inbound by default
resource "azurerm_network_security_group" "app_nsg" {
  name = "app-nsg"

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Allow SSH only from VPN
  security_rule {
    name                       = "allow-ssh-vpn-only"
    priority                   = 200
    direction                  = "Inbound"
    access                      = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"  # VPN subnet
    destination_address_prefix = "*"
  }
}
```

---

## GCP: Authorized Networks + Pod Network Policies

**Problem (FIND-012):** GKE master public, anyone can access Kubernetes API  
**Solution:** Authorized networks whitelist + private master option

**Problem (FIND-013):** Pods can reach any other pod (no Network Policies)  
**Solution:** Deny-all NetworkPolicy, then allow only needed communication

**Key Fix:**
```hcl
# Restrict GKE master access to specific IPs (FIND-012)
resource "google_container_cluster" "main" {
  name = "prod-gke"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "203.0.113.0/32"
      display_name = "Admin IP"
    }
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false  # Still accessible from authorized IPs
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }
}

# Default deny-all NetworkPolicy (FIND-013)
resource "kubernetes_network_policy" "deny_all" {
  metadata {
    name = "deny-all"
    namespace = "production"
  }
  spec {
    pod_selector {}  # Apply to all pods
    policy_types = ["Ingress", "Egress"]
    # No rules = deny all
  }
}

# Explicit allow: frontend → backend only
resource "kubernetes_network_policy" "allow_frontend_to_backend" {
  metadata {
    name      = "allow-frontend-backend"
    namespace = "production"
  }
  spec {
    pod_selector {
      match_labels = {
        tier = "backend"
      }
    }
    ingress {
      from {
        pod_selector {
          match_labels = {
            tier = "frontend"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
  }
}
```

---

## Notable Points

**Q: Why not just change firewall rules without code?**  
> "Manual firewall rules get forgotten, reverted, or missed during scaling. Infrastructure-as-code means rules are documented, version-controlled, and automatically applied to new resources. Auditors can see exactly who changed what and when."

**Q: Why deny-all NetworkPolicies first?**  
> "Default-deny is Zero Trust principle. Every connection must be explicitly approved. If someone misconfigures a pod, it's blocked by default — they have to think about what traffic it needs."

**Q: What's the difference between bastion host and Systems Manager?**  
> "Bastion is a public-facing jump server (still needs hardening). Systems Manager uses AWS's managed service (no SSH port, encryption in-transit, CloudTrail logging). Systems Manager is simpler for AWS environments."

**Q: Why private GKE master?**  
> "Kubernetes API contains secrets, can trigger deployments, drain nodes. Public master = anyone can poke the API. Private master + authorized networks = only admins from specific IPs."

---

## Remediation Status

| Finding | Action | Status |
|---------|--------|--------|
| FIND-008 | AWS SSH → restrict to corp IP or SSM | ✅ Documented |
| FIND-009 | AWS RDP → bastion host + NSG | ✅ Documented |
| FIND-012 | GKE master → authorized networks | ✅ Documented |
| FIND-013 | GKE → deny-all NetworkPolicy + explicit allow | ✅ Documented |
