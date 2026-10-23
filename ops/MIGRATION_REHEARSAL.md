# FinFamily Database Migration Rehearsal & Safety Runbook

## 1. Principles & Safeguards
- **Zero Production Downtime**: Schema modifications must avoid locking tables for extended periods.
- **Strict Backward Compatibility**: Adding columns must use nullable fields or safe database defaults.
- **Fail-Closed Verification**: Every deployment runs `verify_database_readiness` at startup before serving traffic.
- **Isolation First**: No migration is ever run on the live production database (`DATABASE_URL`) without prior rehearsal on an isolated staging snapshot.

---

## 2. Pre-Deployment Migration Rehearsal Procedure

### Step 1: Export Staging / Test Environment
Set the isolated staging database URL:
```bash
export TEST_DATABASE_URL="postgresql://test_user:test_pass@staging-db.finfamily.internal:5432/staging_rehearsal"
```

### Step 2: Run Automated Rehearsal Tool
Execute the automated rehearsal script:
```bash
python ops/rehearse_migrations.py "$TEST_DATABASE_URL" --allow-isolated-rehearsal
```

### Step 3: Validate Output Criteria
The script verifies:
1. All Alembic migrations apply cleanly from baseline to `head`.
2. Execution time for each migration step is measured (< 5.0 seconds).
3. `verify_database_readiness` passes with 100% compliance:
   - Primary keys on all tables.
   - Exact `Numeric(12, 2)` types for all financial columns (`balance`, `amount`, `daily_limit`).
   - Single-column unique constraints on `users.email` and `idempotency_records.key`.
   - Idempotency and audit ledger tables present.

---

## 3. Rollback Procedure
If a migration fails or encounters an unresolvable lock during rehearsal:
1. Revert to previous revision:
   ```bash
   alembic downgrade -1
   ```
2. Verify application connectivity against the previous revision.
3. Abort the deployment pipeline and investigate lock contention or constraint violations.
