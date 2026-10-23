"""
test_migration_and_backup_rehearsal.py
======================================
Automated test suite verifying:
1. Programmatic Alembic migration rehearsal chain (base -> head) across all 4 revisions.
2. Production safety guardrails (rejection of cloud domains, production credentials, and missing flags).
3. Disaster recovery restore drill execution, ledger parity audit, and JSON evidence generation (RTO < 30m, RPO < 15m).
"""

import os
import json
import tempfile
import pytest
from ops.rehearse_migrations import (
    run_migration_rehearsal,
    validate_safety_boundary,
)
from ops.restore_backup_verification import run_isolated_restore_drill


def test_programmatic_alembic_migration_rehearsal_success():
    """Verify that programmatic Alembic rehearsal executes all revisions and passes verification."""
    fd, temp_db = tempfile.mkstemp(suffix="_rehearsal_test.db")
    os.close(fd)
    target_url = f"sqlite:///{temp_db}"

    try:
        report = run_migration_rehearsal(
            target_db_url=target_url,
            allow_isolated_rehearsal=True,
            clean_sqlite=False,
        )
        assert report["status"] == "success"
        assert report["target_type"] == "sqlite"
        assert len(report["revisions_applied"]) == 4

        rev_names = [r["revision"] for r in report["revisions_applied"]]
        assert rev_names == [
            "0000_baseline_schema",
            "0001_numeric_and_isolation",
            "0002_idemp_mfa_atomic",
            "0003_mission_proof",
        ]

        assert report["readiness_verification"]["status"] == "passed"
        assert report["table_inspection"]["status"] == "passed"
        assert "wallets" in report["table_inspection"]["verified_tables"]
        assert "transactions" in report["table_inspection"]["verified_tables"]
        assert "idempotency_records" in report["table_inspection"]["verified_tables"]
    finally:
        try:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        except OSError:
            pass


def test_rehearsal_safety_boundary_rejects_cloud_and_production_urls():
    """Verify that validate_safety_boundary strictly rejects prohibited targets."""
    # 1. Prohibited cloud domains
    with pytest.raises(RuntimeError, match="belongs to prohibited cloud provider domain"):
        validate_safety_boundary("postgresql://user:pass@ep-calm-bar.aws.neon.tech/neondb")

    with pytest.raises(RuntimeError, match="belongs to prohibited cloud provider domain"):
        validate_safety_boundary("postgresql://user:pass@mydb.supabase.co:5432/postgres")

    with pytest.raises(RuntimeError, match="belongs to prohibited cloud provider domain"):
        validate_safety_boundary("postgresql://user:pass@rds-instance.aws.com:5432/test")

    # 2. Production keywords in non-local db name
    with pytest.raises(RuntimeError, match="contains forbidden production keyword"):
        validate_safety_boundary("postgresql://user:pass@staging-server.internal:5432/finfamily_prod")

    # 3. Missing confirmation flag
    with pytest.raises(RuntimeError, match="--allow-isolated-rehearsal"):
        validate_safety_boundary("sqlite:///test.db", allow_isolated_rehearsal=False)

    # 4. Valid isolated test targets pass
    validate_safety_boundary("sqlite:///migration_rehearsal.tmp.db", allow_isolated_rehearsal=True)
    validate_safety_boundary("postgresql://postgres:pass@127.0.0.1:5432/finfamily_test", allow_isolated_rehearsal=True)


def test_disaster_recovery_restore_drill_and_evidence():
    """Verify isolated restore drill produces compliant RTO/RPO metrics and ledger parity."""
    fd, temp_db = tempfile.mkstemp(suffix="_dr_drill.db")
    os.close(fd)
    evidence_fd, evidence_path = tempfile.mkstemp(suffix="_evidence.json")
    os.close(evidence_fd)
    target_url = f"sqlite:///{temp_db}"

    try:
        report = run_isolated_restore_drill(
            target_db_url=target_url,
            evidence_file_path=evidence_path,
        )

        assert report["overall_status"] == "passed"
        assert report["rto_compliance"]["compliant"] is True
        assert report["rto_compliance"]["status"] == "COMPLIANT"
        assert report["rpo_compliance"]["compliant"] is True
        assert report["rpo_compliance"]["status"] == "COMPLIANT"

        # Check ledger balance reconciliation
        ledger_audit = report["ledger_balance_reconciliation_audit"]
        assert ledger_audit["status"] == "passed"

        # No negative balances
        neg_check = next(c for c in ledger_audit["checks"] if c["check"] == "negative_balances")
        assert neg_check["violations_count"] == 0

        # No orphaned records
        orph_wallets = next(c for c in ledger_audit["checks"] if c["check"] == "orphaned_wallets")
        assert orph_wallets["orphaned_count"] == 0

        # Ledger sums match
        sums_check = next(c for c in ledger_audit["checks"] if c["check"] == "transaction_ledger_sums")
        assert sums_check["net_ledger_volume"] == "254.75"

        # Evidence file exists and parses as valid JSON
        assert os.path.exists(evidence_path)
        with open(evidence_path, "r", encoding="utf-8") as f:
            evidence_data = json.load(f)
        assert evidence_data["overall_status"] == "passed"
        assert evidence_data["drill_type"] == "isolated_disaster_recovery_restore_verification"

    finally:
        for path in (temp_db, evidence_path):
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
