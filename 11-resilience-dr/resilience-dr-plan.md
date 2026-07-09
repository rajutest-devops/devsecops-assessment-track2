# Resilience & Disaster Recovery

**Module:** 11 – Resilience & Disaster Recovery  
**Scope:** Backup strategy, RTO/RPO, multi-AZ, failover, and recovery procedures

---

## Current State: Single Point of Failure

| Component | Current | Risk | Impact |
|-----------|---------|------|--------|
| **EKS Nodes** | Single AZ | AZ outage | 100% downtime |
| **RDS Database** | Single AZ, no replicas | DB failure | Data loss + 4+ hours restore |
| **S3 Buckets** | Single region | Region outage | Inaccessible for hours |
| **KMS Keys** | Single region | Key unavailable | Cannot decrypt data |
| **Backups** | Not encrypted | Breach risk | Confidential data exposed |

**RPAS (Recovery Point Age Sensitivity):** 24 hours

---

## Target State: Multi-AZ + Cross-Region Resilience

| Component | Solution | RTO | RPO | Cost Increase |
|-----------|----------|-----|-----|-----------------|
| **EKS** | Multi-AZ + auto-scaling | 5 min | 0 min | +30% |
| **RDS** | Multi-AZ + cross-region replica | 5 min | 5 min | +50% |
| **S3** | Multi-region replication | 30 min | 15 min | +20% |
| **Backups** | Versioning + cross-region copy | 24 hr | 1 hr | +10% |

**Total Cost Impact:** +35% infrastructure cost for 99.95% uptime SLA

---

## AWS: Multi-AZ Deployment Pattern

### EKS High Availability

**BEFORE:**
```hcl
resource "aws_eks_cluster" "single_az" {
  # Nodes only in us-east-1a
  node_groups {
    subnet_ids = [aws_subnet.az_a.id]
  }
}
```

**AFTER:**
```hcl
resource "aws_eks_cluster" "multi_az" {
  # Nodes spread across AZ-a + AZ-b
  node_groups {
    subnet_ids = [
      aws_subnet.az_a.id,
      aws_subnet.az_b.id
    ]
    desired_size       = 6
    min_size           = 4
    max_size           = 12
  }
}

resource "aws_autoscaling_policy" "scale_out" {
  # Auto-scale when CPU > 70%
  metric_aggregation_type = "Average"
  policy_type             = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70
  }
}
```

### RDS Multi-AZ + Cross-Region

**BEFORE:**
```hcl
resource "aws_db_instance" "single_az" {
  multi_az = false  # Single AZ only
  backup_retention_period = 7
}
```

**AFTER:**
```hcl
# Primary (us-east-1)
resource "aws_db_instance" "primary" {
  multi_az                   = true  # Synchronous standby in AZ-b
  backup_retention_period    = 35
  copy_tags_to_snapshot      = true
  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
}

# Cross-region replica (us-west-2)
resource "aws_db_instance" "replica" {
  replicate_source_db = aws_db_instance.primary.id
  skip_final_snapshot = false
}

# Backup to S3
resource "aws_backup_vault" "primary" {
  name = "rds-backup-vault"
}

resource "aws_backup_plan" "rds" {
  name = "rds-backup-plan"
  rule {
    rule_name       = "daily_backup"
    target_backup_vault_name = aws_backup_vault.primary.name
    schedule        = "cron(0 5 ? * * *)"  # 5 AM UTC daily
    start_window    = 60
    completion_window = 120
    lifecycle {
      delete_after = 35  # Keep 35 days
      cold_storage_after = 7  # Move to Glacier after 7 days
    }
  }
}

# Cross-region backup copy
resource "aws_backup_vault" "replica_region" {
  provider = aws.us-west-2
  name     = "rds-backup-vault-replica"
}

resource "aws_backup_plan" "cross_region_copy" {
  name = "cross-region-backup"
  rule {
    copy_action {
      destination_vault_arn = aws_backup_vault.replica_region.arn
      lifecycle {
        cold_storage_after = 7
        delete_after = 35
      }
    }
  }
}
```

---

## Azure: Zone-Redundant Deployment

**BEFORE:**
```hcl
resource "azurerm_kubernetes_cluster" "single_zone" {
  default_node_pool {
    availability_zones = ["1"]  # Single zone
  }
}
```

**AFTER:**
```hcl
resource "azurerm_kubernetes_cluster" "zone_redundant" {
  default_node_pool {
    availability_zones = ["1", "2", "3"]  # All 3 zones
    enable_auto_scaling = true
    min_count           = 6
    max_count           = 12
  }
}

resource "azurerm_mssql_server" "zone_redundant" {
  # Enable geo-replication (secondary region)
}

resource "azurerm_mssql_database" "primary" {
  # Active geo-replication
  create_mode = "Default"
}

resource "azurerm_mssql_database" "secondary" {
  # Read-only replica in secondary region
  create_mode = "OnlineSecondary"
  creation_source_database_id = azurerm_mssql_database.primary.id
}

# Automatic failover group
resource "azurerm_mssql_failover_group" "db_failover" {
  server_id           = azurerm_mssql_server.primary.id
  databases           = [azurerm_mssql_database.primary.id]
  partner_server_id   = azurerm_mssql_server.secondary.id
  
  read_write_endpoint_failover_policy {
    mode          = "Automatic"
    grace_minutes = 60
  }
}

# Backup to Storage with lifecycle
resource "azurerm_storage_account" "backup" {
  name = "backupstorageaccount"
  account_replication_type = "GRS"  # Geo-redundant
  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "Archive"
    }
    expiration {
      days = 365
    }
  }
}
```

---

## GCP: Regional + Cross-Region Backup

**BEFORE:**
```hcl
resource "google_sql_database_instance" "single_zone" {
  location                 = "us-central1-a"
  availability_type        = "ZONAL"
}
```

**AFTER:**
```hcl
# Primary (us-central1) - High Availability
resource "google_sql_database_instance" "primary" {
  region           = "us-central1"
  availability_type = "REGIONAL"  # Multi-zone HA
  backup_configuration {
    enabled                        = true
    binary_log_enabled             = true
    backup_retention_settings {
      retained_backups = 30
      retention_unit   = "COUNT"
    }
    point_in_time_recovery_enabled = true
    transaction_log_retention_days = 7
  }
}

# Replica (us-east1) - Read-only cross-region
resource "google_sql_database_instance" "replica" {
  master_instance_name = google_sql_database_instance.primary.name
  region               = "us-east1"
  database_version     = "MYSQL_8_0"
}

# Backup to Cloud Storage
resource "google_sql_backup_run" "manual" {
  instance = google_sql_database_instance.primary.name
}

# GCS backup export (daily)
resource "google_cloud_scheduler_job" "backup_export" {
  name             = "daily-sql-backup"
  schedule         = "0 2 * * *"  # 2 AM UTC daily
  time_zone        = "UTC"
  attempt_deadline = "600s"
  
  http_target {
    http_method = "POST"
    uri = "https://www.googleapis.com/sql/v1beta4/projects/${var.project_id}/instances/${google_sql_database_instance.primary.name}/export"
  }
}
```

---

## Backup Strategy Matrix

| Component | Frequency | Retention | Location | Encryption |
|-----------|-----------|-----------|----------|------------|
| **EKS etcd** | Hourly | 7 days | S3 + Glacier | KMS CMK |
| **RDS snapshots** | Daily | 35 days | S3 + replica region | KMS CMK |
| **S3 versioning** | Continuous | 90 days | S3 + cross-region replication | KMS CMK |
| **Application code** | Per commit | Unlimited | Git (GitHub) | GitHub encryption |
| **Logs/audit** | Continuous (streamed) | 7 years | Glacier + immutable | KMS CMK |

---

## Disaster Recovery Procedures

### RTO: 5 Minutes (Single AZ Failure)

```
Incident: EKS nodes in AZ-a become unavailable

0 min:   Monitoring detects pod failures
         → Alerts fire (Slack + PagerDuty)
         
2 min:   Auto-scaling group launches new nodes in AZ-b
         → Kubernetes scheduler places pods on healthy nodes
         
5 min:   All pods healthy again
         → Monitoring confirms (no errors)
         → Incident resolved
```

### RTO: 30 Minutes (Database Failure)

```
Incident: RDS primary in AZ-a fails

0 min:   CloudWatch detects RDS unavailable
         → RDS Multi-AZ automatic failover triggers
         
2 min:   Standby replica in AZ-b becomes new primary
         → Connection string automatically updates
         → Application reconnects
         
5 min:   All queries succeeding
         → Monitoring confirms health
         
30 min:  (Optional) Promote cross-region replica to primary
         → If entire region is down
```

### RTO: 2 Hours (Entire Region Failure)

```
Incident: AWS us-east-1 region completely down

0-10 min:  Monitoring detects outage
           → Team activates disaster recovery playbook
           
10-30 min: Update DNS to point to us-west-2 (replica region)
           → Update environment variables in Terraform
           → Promote read-only replica to primary
           
30-60 min: Run smoke tests in replica region
           → Verify data integrity + application health
           
60-120 min: Full failover complete
            → Users transparently using us-west-2
            → SLA maintained (5 minute detection + 2 hour failover)
```

---

## Backup Validation & Restore Testing

| Task | Frequency | Procedure | Success Criteria |
|------|-----------|-----------|-----------------|
| **Snapshot integrity check** | Daily | Verify checksums | SHA256 match |
| **Restore test (staging)** | Weekly | Restore snapshot to test DB | Data consistency check |
| **Cross-region replication** | Daily | Verify bytes replicated | Replication lag < 15 min |
| **Backup encryption** | Daily | Verify KMS key used | Key audit logs show access |
| **Full DR drill** | Quarterly | Failover to replica region | All services healthy in <30 min |

---

## Failover Checklist

- [ ] Identify failure (AZ/zone/region/data center)
- [ ] Activate war room (Slack channel + conference call)
- [ ] Notify stakeholders (board, customers)
- [ ] Trigger auto-failover (if supported by platform)
- [ ] Monitor promotion status (watch logs)
- [ ] Run smoke tests (health checks + queries)
- [ ] Update DNS / routing (if manual)
- [ ] Verify no data loss (query verification)
- [ ] Scale infrastructure in new region (if needed)
- [ ] Document incident (timeline + root cause)
- [ ] Post-mortem within 24 hours

---

## Notable Points

**Q: Why keep 35 days of backups instead of 7?**  
> "Most data corruption goes undetected for 2-3 weeks. By then, 7-day backups are gone. With 35 days, you can restore to before corruption. After 30 days, move to Glacier (cold storage) for cost."

**Q: What if attacker corrupts all three cloud backups simultaneously?**  
> "Keep immutable backup in separate account/organization. Attacker can't access it even with admin creds. We use S3 Object Lock (7-year hold). Even AWS support can't delete."

**Q: Can we do zero-downtime failover?**  
> "Yes, with multi-region active-active setup. But costs 2-3x. Multi-AZ (same region) is active-active. Cross-region is usually active-passive (5-30 min failover)."

**Q: How do you practice DR without breaking production?**  
> "Use staging environment. Restore backup from yesterday → run full test → delete staging. Or, use chaos engineering tools (intentionally kill pods) to verify auto-recovery."

---

## RTO/RPO Targets (Post-Remediation)

| Scenario | RTO | RPO | Method |
|----------|-----|-----|--------|
| Single pod failure | 30 sec | 0 sec | Kubernetes auto-restart |
| Single node failure | 2 min | 0 sec | Pod migration to healthy node |
| Single AZ failure | 5 min | 0 sec | Multi-AZ failover + auto-scaling |
| Database failover | 5 min | 5 min | RDS multi-AZ + sync replication |
| Region failure | 30 min | 15 min | Cross-region replica promotion |
| Total data center loss | 2 hours | 1 hour | Full cross-region failover |

---

## Summary

✅ Multi-AZ deployment across all components  
✅ 35-day encrypted backup retention  
✅ Cross-region replication for critical data  
✅ 5-30 minute RTO targets achievable  
✅ Quarterly DR drill schedule  
✅ Immutable S3 backups with Object Lock  
✅ Zero-knowledge about backup encryption keys (fully customer-managed)
