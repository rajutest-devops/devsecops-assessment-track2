# Fix for FIND-011/012/013: GKE logging disabled, public master, no NetworkPolicy
# Original: terragoat/terraform/gcp/gke.tf
# Changes: Enable logging + private master endpoint + NetworkPolicy

resource "google_container_cluster" "primary" {
  name     = "production-gke"
  location = var.region

  # Remove default node pool; create separate managed one
  remove_default_node_pool = true
  initial_node_count       = 1

  # FIND-011: Enable Cloud Logging + Monitoring
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  logging_config {
    enable_components = [
      "SYSTEM_COMPONENTS",
      "WORKLOADS",
      "API_SERVER",
      "CONTROLLER_MANAGER",
      "SCHEDULER"
    ]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  # FIND-012: Restrict master endpoint to known admin IPs only
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = var.admin_cidr_block  # e.g. "203.0.113.0/24"
      display_name = "Admin VPN"
    }
  }

  # FIND-012: Private cluster — nodes have no public IPs
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true  # Master also private
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # FIND-013: Enable NetworkPolicy (Calico)
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  # Workload Identity (removes need for service account keys)
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Enable shielded nodes
  enable_shielded_nodes = true

  # Disable legacy auth
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "primary-node-pool"
  cluster    = google_container_cluster.primary.name
  location   = var.region
  node_count = 3

  node_config {
    machine_type = "e2-standard-4"
    disk_type    = "pd-ssd"
    disk_size_gb = 100

    # Workload Identity on nodes
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}

# FIND-013: Default-deny NetworkPolicy (apply after cluster created)
# Applied via kubectl — Terraform data source or null_resource
# Equivalent YAML:
# apiVersion: networking.k8s.io/v1
# kind: NetworkPolicy
# metadata:
#   name: deny-all
#   namespace: default
# spec:
#   podSelector: {}
#   policyTypes: [Ingress, Egress]
