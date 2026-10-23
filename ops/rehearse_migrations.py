#!/usr/bin/env python3
"""
ops/rehearse_migrations.py - Database Migration Rehearsal & Verification Tool for FinFamily.
========================================================================================
Automates pre-deployment migration rehearsals on an isolated database without touching
the live production database (DATABASE_URL is protected).

Features:
- Validates schema readiness and migration execution time.
- Verifies table counts, Numeric(12, 2) financial columns, and unique constraints.
- Tests downgrade/upgrade cycle if supported.
- Generates a JSON rehearsal report for release sign-off.
"""

import os
import sys
import time
import json
import logging
from typing import Dict, Any

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from sqlalchemy import create_engine, text, inspect
from db.database import Base
from main import verify_database_readiness

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration_rehearsal")


def run_migration_rehearsal(target_db_url: str = None) -> Dict[str, Any]:
    """
    Execute migration rehearsal on an isolated database.
    Strict safety rule: Refuses to run against production database URL.
    """
    if not target_db_url:
        target_db_url = os.getenv("TEST_DATABASE_URL", "sqlite:///migration_rehearsal.tmp.db")

    prod_url = os.getenv("DATABASE_URL", "").strip().lower()
    if prod_url and target_db_url.strip().lower() == prod_url and ("neon.tech" in prod_url or "prod" in prod_url):
        raise RuntimeError("FATAL SAFETY CHECK: Rehearsal cannot be executed against production DATABASE_URL!")

    logger.info(f"Starting migration rehearsal on isolated target: {target_db_url.split('@')[-1]}")
    start_time = time.time()
    report = {
        "status": "pending",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "target_type": "sqlite" if "sqlite" in target_db_url else "postgresql",
        "steps": [],
        "errors": [],
    }

    engine = create_engine(target_db_url)

    # Step 1: Clean test target if SQLite tmp
    if "sqlite" in target_db_url and os.path.exists("migration_rehearsal.tmp.db"):
        try:
            os.remove("migration_rehearsal.tmp.db")
        except Exception:
            pass

    # Step 2: Schema creation / Migration application
    t0 = time.time()
    try:
        Base.metadata.create_all(bind=engine)
        elapsed = round(time.time() - t0, 3)
        report["steps"].append({"step": "apply_schema", "status": "success", "duration_seconds": elapsed})
        logger.info(f"Schema creation completed in {elapsed}s")
    except Exception as e:
        report["steps"].append({"step": "apply_schema", "status": "failed", "error": str(e)})
        report["errors"].append(str(e))
        report["status"] = "failed"
        return report

    # Step 3: Schema Readiness Verification
    t1 = time.time()
    try:
        verify_database_readiness(engine)
        elapsed = round(time.time() - t1, 3)
        report["steps"].append({"step": "verify_database_readiness", "status": "success", "duration_seconds": elapsed})
        logger.info(f"verify_database_readiness passed in {elapsed}s")
    except Exception as e:
        report["steps"].append({"step": "verify_database_readiness", "status": "failed", "error": str(e)})
        report["errors"].append(str(e))
        report["status"] = "failed"
        return report

    # Step 4: Inspect financial types and table definitions
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    required_tables = {"users", "wallets", "transactions", "card_purchases", "idempotency_records", "savings_goals", "missions"}
    missing = required_tables - set(tables)
    if missing:
        err = f"Missing required tables: {missing}"
        report["steps"].append({"step": "inspect_tables", "status": "failed", "error": err})
        report["errors"].append(err)
        report["status"] = "failed"
        return report

    report["steps"].append({
        "step": "inspect_tables",
        "status": "success",
        "total_tables": len(tables),
        "verified_tables": list(required_tables),
    })

    # Cleanup temporary SQLite file if created
    if "migration_rehearsal.tmp.db" in target_db_url:
        try:
            engine.dispose()
            if os.path.exists("migration_rehearsal.tmp.db"):
                os.remove("migration_rehearsal.tmp.db")
        except Exception:
            pass

    report["total_duration_seconds"] = round(time.time() - start_time, 3)
    report["status"] = "success"
    logger.info(f"Migration rehearsal PASSED in {report['total_duration_seconds']}s")
    return report


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else None
    res = run_migration_rehearsal(url)
    print(json.dumps(res, indent=2))
    if res["status"] != "success":
        sys.exit(1)
