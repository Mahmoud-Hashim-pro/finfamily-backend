# FinFamily Disaster Recovery & Backup Restoration Runbook

## 1. Objectives & Metrics
- **RTO (Recovery Time Objective)**: `< 30 minutes` from disaster declaration to restored service.
- **RPO (Recovery Point Objective)**: `< 15 minutes` maximum tolerable data loss (backed by continuous WAL archiving / automated daily snapshots with point-in-time recovery on Neon PostgreSQL).

---

## 2. Backup Strategy
1. **Automated Daily Snapshots**: Taken at 02:00 UTC, encrypted at rest with AES-256.
2. **Write-Ahead Logging (WAL)**: Streamed continuously to resilient cloud object storage with 7-day retention.
3. **Backup Checksums**: Every export computes a SHA-256 fingerprint verified before storage.

---

## 3. Restoration Rehearsal Procedure

### Step 1: Download & Verify Backup Integrity
Verify the archive SHA-256 checksum against metadata:
```bash
sha256sum finfamily_backup_20261023.dump
```

### Step 2: Restore to Isolated Test Database
```bash
createdb -h localhost -p 5432 -U postgres finfamily_recovery_test
pg_restore -h localhost -p 5432 -U postgres -d finfamily_recovery_test -v finfamily_backup_20261023.dump
```

### Step 3: Run Integrity & Reconciliation Audit
Execute the automated integrity verification tool:
```bash
python ops/restore_backup_verification.py
```

The script audits:
- **No Negative Balances**: Asserts `Wallet.balance >= 0` across all accounts.
- **No Orphaned Records**: Checks that every wallet references an existing user.
- **Ledger Consistency**: Verifies transaction integrity and idempotency records.

---

## 4. Incident Response & Escalation
- **Level 1**: Transient connection outage -> Managed pool retries (up to 3 attempts).
- **Level 2**: Unrecoverable corruption / Host failure -> Trigger Point-In-Time Recovery (PITR) to latest healthy WAL timestamp.
- **Level 3**: Full region outage -> Provision replica in secondary cloud zone, apply latest snapshot, repoint `DATABASE_URL` via secret manager, verify startup readiness.
