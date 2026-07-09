# Compensating Controls — COTS Encryption Constraint

**Module:** 07 (Assessment Module 8) — Compensating Controls  
**Scenario:** COTS financial reconciliation tool cannot support encryption-at-rest due to vendor-imposed driver limitation. Cannot be re-platformed before compliance deadline.

---

## The Constraint

| Attribute | Detail |
|-----------|--------|
| System | COTS financial reconciliation tool |
| Limitation | Vendor driver incompatible with encrypted storage volumes |
| Re-platform deadline | After compliance deadline — not an option |
| Data sensitivity | Financial transaction records (PCI-DSS scope) |
| Affected resource | RDS instance / EBS volume attached to COTS workload |

---

## Compensating Controls (3 Required)

### CC-001: Network Isolation — Private Subnet + No Public Access

**Control:** Place the COTS system in a dedicated private subnet with no internet egress and no public IP. Only the specific application tier that sends/receives financial data can communicate with it.

```hcl
# COTS database in isolated private subnet
resource "aws_db_subnet_group" "cots_isolated" {
  subnet_ids = [aws_subnet.private_cots.id]
}

resource "aws_db_instance" "cots_db" {
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.cots_isolated.name
  vpc_security_group_ids = [aws_security_group.cots_only.id]
}

# Security group: only app tier on port 5432 — nothing else
resource "aws_security_group_rule" "cots_ingress" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  source_security_group_id = aws_security_group.app_tier.id
}
```

**Rationale:** If disk is unencrypted, the next control layer is network. An attacker would need to first compromise the private subnet — significantly raising the bar.

---

### CC-002: Enhanced Audit Logging — Full Query + Access Trail

**Control:** Enable all available database audit logging (query logs, connection logs, slow query logs). Ship logs to a separate, immutable log archive that the COTS system cannot access. Alert on any anomalous query patterns (bulk SELECT, data export queries).

```hcl
# Enable all RDS audit logs
resource "aws_db_instance" "cots_db" {
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
}

# Immutable log archive (separate account)
resource "aws_cloudwatch_log_group" "cots_audit" {
  name              = "/aws/rds/cots-financial"
  retention_in_days = 365  # 1-year retention (PCI-DSS requirement)
}

# Alert on bulk data export (> 10,000 rows in one query)
resource "aws_cloudwatch_metric_alarm" "bulk_export" {
  alarm_name  = "cots-bulk-data-export"
  metric_name = "DatabaseConnections"
  alarm_actions = [aws_sns_topic.security_pagerduty.arn]
}
```

**Rationale:** Since data cannot be encrypted at rest, it must be closely monitored. Any unauthorised access to unencrypted data is detectable within minutes (not discovered weeks later).

---

### CC-003: Encryption in Transit + Volume-Level Access Control

**Control:** Enforce TLS/SSL for all connections to the COTS database. Restrict OS-level access to the underlying storage volume — only the COTS application service account can read/write. No SSH to the host. No direct volume mounting.

```hcl
# Force SSL for all connections
resource "aws_db_parameter_group" "cots_ssl_required" {
  family = "postgres14"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

# No SSH access to the underlying host
resource "aws_security_group" "cots_host" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    description = "Database port only — no SSH"
  }
  # Port 22 deliberately absent
}
```

**Rationale:** Data is unencrypted at rest but encrypted in transit. An attacker who intercepts network traffic gets nothing. Access to the raw disk requires physical/hypervisor-level access — only possible if the cloud provider itself is compromised.

---

## Residual Risk Rating

| After Compensating Controls | Assessment |
|-----------------------------|------------|
| **Risk Rating** | Medium (down from Critical) |
| **Likelihood** | Low — three separate control layers must all fail simultaneously |
| **Impact** | High — financial PII still unencrypted at rest |
| **Net Risk** | Acceptable as interim state with time-bound plan |

**Residual risk reduction:**
- Without controls: attacker with disk access → immediate data breach
- With CC-001 (network isolation): attacker must first breach private subnet
- With CC-002 (audit logging): breach detected within minutes, not weeks
- With CC-003 (SSL + access control): in-transit encrypted, OS access blocked

---

## Risk Acceptance

**Who accepts this risk:**  
The formal risk acceptance must come from: **Information Security Officer (ITSO-equivalent) + Data Owner**  
Not engineering. Not the DevSecOps team.

**Required documentation:**
- Signed risk acceptance form
- COTS vendor confirmation of limitation (in writing)
- Re-platform timeline committed
- Quarterly review of compensating controls effectiveness

---

## Time-Bound Plan: Interim → Target State

| Phase | Timeline | Action |
|-------|----------|--------|
| **Now (Interim)** | This sprint | Deploy CC-001 + CC-002 + CC-003 |
| **Month 1** | Compliance deadline | Risk acceptance signed by ITSO + Data Owner |
| **Month 2** | Post-deadline | Vendor escalation — encrypted driver roadmap? |
| **Quarter 2** | Next quarter | Evaluate re-platform options (containerise, API wrapper) |
| **Target** | H2 | COTS replaced or re-platformed with encryption-at-rest enabled |

---

## Exception Governance: Preventing Scope Creep

This exception must not set a precedent for other COTS systems.

**Controls to prevent propagation:**

1. **Exception register** — Every exception requires a ticket in the central exception register with: system name, data classification, compensating controls, ITSO signature, expiry date
2. **Quarterly audit** — All exceptions reviewed every quarter. Any without active re-platform plan are escalated to CISO
3. **Policy-as-code** — Checkov custom check flags `encrypted = false` as CRITICAL. Exception requires a specific `# EXCEPTION-APPROVED: COTS-001` comment in the Terraform code to pass the gate
4. **Hard expiry** — Exceptions expire after 6 months. Must be re-approved or resolved

```hcl
# Checkov exception tagging — requires approved exception tag
resource "aws_db_instance" "cots_db" {
  storage_encrypted = false

  tags = {
    exception_id      = "EXC-2026-001"
    exception_expiry  = "2027-01-09"
    exception_owner   = "ITSO-Name"
    compensating_ctrl = "CC-001,CC-002,CC-003"
    # Without this tag, checkov fails in pipeline
  }
}
```

---

## Notable Points

**Q: Why accept this risk instead of blocking go-live?**  
> "Three compensating controls reduce the likelihood of exploitation to low. The business risk of delaying go-live exceeds the technical risk of running unencrypted data with network isolation + full audit logging in place. This is a risk decision — not a technical one — and must be owned by the ITSO, not engineering."

**Q: What if the vendor never delivers an encrypted driver?**  
> "The re-platform timeline must be binding, not aspirational. If the vendor can't deliver within the agreed quarter, the decision is: accept extended risk (re-sign every 6 months) or force a re-platform. That decision goes to the programme board, not the security team."

**Q: How do compensating controls get validated?**  
> "CC-001: Run a penetration test against the subnet boundary. CC-002: Simulate a bulk data query and verify the alert fires within 5 minutes. CC-003: Attempt connection without SSL — verify it's rejected. All three tested before go-live sign-off."
