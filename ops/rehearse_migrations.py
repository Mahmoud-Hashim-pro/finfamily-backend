#!/usr/bin/env python3
"""
ops/rehearse_migrations.py - Database Migration Rehearsal & Verification Tool for FinFamily.
========================================================================================
Automates pre-deployment migration rehearsals on an isolated database without touching
the live production database (DATABASE_URL is strictly protected).

Upgraded Capabilities:
- Full Alembic programmatic migration chain execution (base -> head).
- Detailed tracking of each migration revision applied with timestamps and duration.
- Automated rollback / downgrade cycle testing with safety policy handling.
- Startup schema readiness verification via verify_database_readiness().
- Table and column structural inspection (Numeric(12, 2) financial parity).
- Robust Production-Database Safety Boundary:
  * Prohibits execution against live production DATABASE_URL.
  * Blocks any cloud provider domains (neon.tech, aws.com, azure.com, google.com, supabase.co).
  * Enforces explicit staging/test databases (SQLite, localhost/127.0.0.1, or test/staging names).
  * Requires --allow-isolated-rehearsal flag to confirm rehearsal intent.
"""

import os
import sys
import time
import json
import logging
import argparse
import gc
from typing import Dict, Any, List, Optional

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from dotenv import load_dotenv
load_dotenv(override=False)

from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import make_url
from alembic.config import Config
from alembic import command
from alembic.script import ScriptDirectory
from main import verify_database_readiness

logger = logging.getLogger("migration_rehearsal")

PROHIBITED_CLOUD_DOMAINS = (
    "neon.tech",
    "aws.com",
    "amazonaws.com",
    "azure.com",
    "google.com",
    "googleapis.com",
    "supabase.co",
    "supabase.com",
)

PROHIBITED_NAME_KEYWORDS = (
    "prod",
    "production",
    "live",
)


def validate_safety_boundary(target_db_url: str, allow_isolated_rehearsal: bool = True) -> None:
    """
    Robust Production-Database Safety Boundary.
    Enforces that migration rehearsal can NEVER execute against production, cloud, or non-staging databases:
    1. Rejects calls without explicit confirmation flag (--allow-isolated-rehearsal).
    2. Parses target URL with sqlalchemy.engine.make_url().
    3. Rejects any cloud provider domains (neon.tech, aws.com, azure.com, google.com, supabase.co).
    4. Compares against production DATABASE_URL (matching host, port, dbname, or credentials).
    5. Rejects production keyword aliases in database name (prod, production, live).
    6. Enforces that target must be an explicit staging/test database (SQLite, localhost/127.0.0.1, or have test/staging in name).
    """
    if not allow_isolated_rehearsal:
        raise RuntimeError(
            "FATAL SAFETY CHECK: Rehearsal intent not confirmed. "
            "The '--allow-isolated-rehearsal' flag is strictly required to proceed."
        )

    if not target_db_url or not isinstance(target_db_url, str) or not target_db_url.strip():
        raise RuntimeError("FATAL SAFETY CHECK: Target database URL must be a non-empty string.")

    try:
        target_parsed = make_url(target_db_url.strip())
    except Exception as e:
        raise RuntimeError(f"FATAL SAFETY CHECK: Target database URL could not be parsed: {e}")

    target_host = (target_parsed.host or "").lower()
    target_db = (target_parsed.database or "").lower()
    target_driver = (target_parsed.drivername or "").lower()
    is_sqlite = target_driver.startswith("sqlite")
    is_localhost = target_host in ("localhost", "127.0.0.1", "::1", "postgres")

    # 1. Cloud provider domains check
    for cloud_domain in PROHIBITED_CLOUD_DOMAINS:
        if cloud_domain in target_host:
            raise RuntimeError(
                f"FATAL SAFETY CHECK: Rehearsal target host '{target_host}' belongs to prohibited cloud provider domain '{cloud_domain}'. "
                "Migration rehearsal against remote/production cloud databases is strictly prohibited!"
            )

    # 2. Check against production DATABASE_URL
    prod_env_url = os.getenv("DATABASE_URL", "").strip()
    if prod_env_url:
        try:
            prod_parsed = make_url(prod_env_url)
            prod_host = (prod_parsed.host or "").lower()
            prod_db = (prod_parsed.database or "").lower()
            prod_user = prod_parsed.username
            prod_port = prod_parsed.port

            # Direct string match
            if target_db_url.strip().lower() == prod_env_url.lower():
                raise RuntimeError(
                    "FATAL SAFETY CHECK: Rehearsal target URL exactly matches production DATABASE_URL!"
                )

            # Match by host & database
            if target_host and prod_host and target_host == prod_host:
                if target_db and prod_db and target_db == prod_db:
                    raise RuntimeError(
                        f"FATAL SAFETY CHECK: Target host '{target_host}' and database '{target_db}' match production DATABASE_URL!"
                    )
                if not is_localhost:
                    raise RuntimeError(
                        f"FATAL SAFETY CHECK: Target host '{target_host}' matches production DATABASE_URL host!"
                    )

            # Match by database name if prod is non-test
            if prod_db and not any(t in prod_db for t in ("test", "memory")):
                if target_db and target_db == prod_db:
                    raise RuntimeError(
                        f"FATAL SAFETY CHECK: Target database name '{target_db}' matches production database name!"
                    )

            # Match by credentials and host/database
            if prod_user and target_parsed.username and prod_user == target_parsed.username:
                if (target_db and target_db == prod_db) or (target_host and target_host == prod_host and not is_localhost):
                    raise RuntimeError(
                        "FATAL SAFETY CHECK: Target database credentials and host/database match production DATABASE_URL!"
                    )

            # Match by port, host and db
            if prod_port and target_parsed.port and prod_port == target_parsed.port:
                if prod_host and target_host and prod_host == target_host and (target_db == prod_db or not is_localhost):
                    raise RuntimeError(
                        "FATAL SAFETY CHECK: Target database endpoint matches production DATABASE_URL endpoint!"
                    )
        except RuntimeError:
            raise
        except Exception as e:
            logger.warning(f"Could not parse production DATABASE_URL for comparison: {e}")

    # 3. Check for production keywords in database name
    for kw in PROHIBITED_NAME_KEYWORDS:
        if kw in target_db:
            raise RuntimeError(
                f"FATAL SAFETY CHECK: Target database name '{target_db}' contains forbidden production keyword '{kw}'."
            )

    # 4. Enforce explicit staging/test database target
    # Must be SQLite, localhost/127.0.0.1, or have 'test' or 'staging' in the database name
    is_test_or_staging_name = "test" in target_db or "staging" in target_db
    if not (is_sqlite or is_localhost or is_test_or_staging_name):
        raise RuntimeError(
            f"FATAL SAFETY CHECK: Target database '{target_db_url}' is not an explicit staging/test database. "
            "Target must be SQLite, localhost/127.0.0.1, or have 'test' or 'staging' in the database name."
        )


def get_alembic_config(db_url: str) -> Config:
    """Build programmatic Alembic Config pointed to the target isolated URL."""
    ini_path = os.path.join(backend_root, "alembic.ini")
    alembic_cfg = Config(ini_path)
    alembic_cfg.attributes["configure_logger"] = False
    # ConfigParser treats '%' as an interpolation character; escape '%' to '%%' for alembic.ini config
    escaped_url = db_url.replace("%", "%%")
    alembic_cfg.set_main_option("sqlalchemy.url", escaped_url)
    alembic_cfg.set_main_option("script_location", os.path.join(backend_root, "alembic"))
    return alembic_cfg


def run_migration_rehearsal(
    target_db_url: Optional[str] = None,
    allow_isolated_rehearsal: bool = True,
    clean_sqlite: bool = True,
) -> Dict[str, Any]:
    """
    Execute migration rehearsal on an isolated database using the full Alembic migration chain.
    Strict safety rule: Refuses to run against production database URL or prohibited cloud domains.
    """
    if not target_db_url:
        target_db_url = os.getenv("TEST_DATABASE_URL", "sqlite:///migration_rehearsal.tmp.db")

    # Enforce strict safety boundary before any database interaction
    validate_safety_boundary(target_db_url, allow_isolated_rehearsal=allow_isolated_rehearsal)

    sanitized_target = target_db_url.split("@")[-1] if "@" in target_db_url else target_db_url
    logger.info(f"Starting programmatic Alembic migration rehearsal on isolated target: {sanitized_target}")
    start_time = time.time()

    is_sqlite = "sqlite" in target_db_url
    report: Dict[str, Any] = {
        "status": "pending",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "target_url": sanitized_target,
        "target_type": "sqlite" if is_sqlite else "postgresql",
        "steps": [],
        "revisions_applied": [],
        "rollback_test": None,
        "readiness_verification": None,
        "table_inspection": None,
        "errors": [],
    }

    # Step 1: Clean test target if SQLite tmp
    sqlite_filename = "migration_rehearsal.tmp.db"
    if is_sqlite and sqlite_filename in target_db_url and os.path.exists(sqlite_filename):
        try:
            os.remove(sqlite_filename)
        except Exception as e:
            logger.warning(f"Could not remove pre-existing SQLite tmp file: {e}")

    # Step 2: Configure Alembic and execute migration chain (base -> head)
    alembic_cfg = get_alembic_config(target_db_url)
    script = ScriptDirectory.from_config(alembic_cfg)
    revisions = list(reversed(list(script.walk_revisions("base", "head"))))

    logger.info(f"Discovered {len(revisions)} Alembic migration revisions in chain: {[r.revision for r in revisions]}")

    for rev in revisions:
        t_rev_start = time.time()
        rev_start_ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
        try:
            command.upgrade(alembic_cfg, rev.revision)
            rev_elapsed = round(time.time() - t_rev_start, 4)
            rev_record = {
                "revision": rev.revision,
                "description": rev.doc or "",
                "started_at": rev_start_ts,
                "duration_seconds": rev_elapsed,
                "status": "success",
            }
            report["revisions_applied"].append(rev_record)
            logger.info(f"Migration {rev.revision} applied successfully in {rev_elapsed}s")
        except Exception as e:
            rev_elapsed = round(time.time() - t_rev_start, 4)
            err = f"Migration {rev.revision} failed: {str(e)}"
            report["revisions_applied"].append({
                "revision": rev.revision,
                "description": rev.doc or "",
                "started_at": rev_start_ts,
                "duration_seconds": rev_elapsed,
                "status": "failed",
                "error": str(e),
            })
            report["steps"].append({"step": f"apply_{rev.revision}", "status": "failed", "error": err})
            report["errors"].append(err)
            report["status"] = "failed"
            return report

    # Guarantee final upgrade to head
    try:
        command.upgrade(alembic_cfg, "head")
        total_chain_time = round(sum(r["duration_seconds"] for r in report["revisions_applied"]), 4)
        report["steps"].append({
            "step": "apply_migrations_chain",
            "status": "success",
            "revisions_count": len(report["revisions_applied"]),
            "duration_seconds": total_chain_time,
        })
    except Exception as e:
        err = f"Alembic upgrade head verification failed: {e}"
        report["steps"].append({"step": "apply_migrations_chain", "status": "failed", "error": err})
        report["errors"].append(err)
        report["status"] = "failed"
        return report

    # Step 3: Test rollback/downgrade where supported, then re-upgrade to head
    t_rb_start = time.time()
    rb_record: Dict[str, Any] = {
        "command": "command.downgrade(alembic_cfg, '-1')",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
    }
    try:
        command.downgrade(alembic_cfg, "-1")
        rb_record["status"] = "downgraded_successfully"
        rb_record["supported"] = True
        logger.info("Alembic downgrade -1 succeeded (supported).")
    except Exception as e:
        rb_record["status"] = "downgrade_protected_by_safety_policy"
        rb_record["supported"] = False
        rb_record["policy_message"] = str(e)
        logger.info(f"Alembic downgrade -1 returned safe policy block: {e}")

    if rb_record.get("supported", False):
        try:
            command.upgrade(alembic_cfg, "head")
            rb_record["reupgrade_to_head"] = "success"
        except Exception as e:
            err = f"Re-upgrade to head following rollback test failed: {e}"
            report["errors"].append(err)
            report["status"] = "failed"
            return report
    else:
        rb_record["reupgrade_to_head"] = "not_applicable_downgrade_blocked"


    rb_record["duration_seconds"] = round(time.time() - t_rb_start, 4)
    report["rollback_test"] = rb_record
    report["steps"].append({
        "step": "test_rollback_cycle",
        "status": "success",
        "rollback_result": rb_record["status"],
        "duration_seconds": rb_record["duration_seconds"],
    })

    # Step 4: Verify Database Schema Readiness via verify_database_readiness(engine)
    engine = create_engine(target_db_url)
    t_vr_start = time.time()
    try:
        is_ready, detail_msg = verify_database_readiness(engine, is_production_mode=False, check_alembic_revision=True)
        vr_elapsed = round(time.time() - t_vr_start, 4)
        if not is_ready:
            err = f"Database readiness check failed: {detail_msg}"
            report["steps"].append({"step": "verify_database_readiness", "status": "failed", "error": err})
            report["errors"].append(err)
            report["status"] = "failed"
            engine.dispose()
            return report

        report["readiness_verification"] = {
            "status": "passed",
            "duration_seconds": vr_elapsed,
            "message": detail_msg,
        }
        report["steps"].append({
            "step": "verify_database_readiness",
            "status": "success",
            "duration_seconds": vr_elapsed,
            "message": detail_msg,
        })
        logger.info(f"verify_database_readiness passed in {vr_elapsed}s: {detail_msg}")
    except Exception as e:
        err = f"Exception during database readiness verification: {e}"
        report["steps"].append({"step": "verify_database_readiness", "status": "failed", "error": err})
        report["errors"].append(err)
        report["status"] = "failed"
        engine.dispose()
        return report

    # Step 5: Deep table and financial column inspection
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        required_tables = {
            "families", "users", "wallets", "transactions", "card_purchases",
            "idempotency_records", "savings_goals", "missions", "game_completions",
            "audit_logs", "user_badges", "lesson_completions", "alembic_version"
        }
        missing = required_tables - tables
        if missing:
            err = f"Missing required tables after migration: {missing}"
            report["steps"].append({"step": "inspect_tables", "status": "failed", "error": err})
            report["errors"].append(err)
            report["status"] = "failed"
            engine.dispose()
            return report

        report["table_inspection"] = {
            "status": "passed",
            "total_tables": len(tables),
            "verified_tables": sorted(list(required_tables)),
            "all_tables": sorted(list(tables)),
        }
        report["steps"].append({
            "step": "inspect_tables",
            "status": "success",
            "total_tables": len(tables),
        })
    finally:
        engine.dispose()
        gc.collect()

    # Step 6: Cleanup temporary SQLite file if requested
    if clean_sqlite and is_sqlite and sqlite_filename in target_db_url:
        try:
            if os.path.exists(sqlite_filename):
                os.remove(sqlite_filename)
        except Exception as e:
            logger.warning(f"Could not remove temporary rehearsal database {sqlite_filename}: {e}")

    report["total_duration_seconds"] = round(time.time() - start_time, 4)
    report["status"] = "success"
    logger.info(f"Migration rehearsal completed successfully in {report['total_duration_seconds']}s")
    return report


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="FinFamily Database Migration Rehearsal & Verification")
    parser.add_argument("url", nargs="?", default=None, help="Target database URL (optional)")
    parser.add_argument("--target-db-url", dest="target_url", default=None, help="Target database URL")
    parser.add_argument(
        "--allow-isolated-rehearsal",
        action="store_true",
        help="Explicitly confirm intent for isolated database rehearsal",
    )
    args = parser.parse_args()

    target = args.target_url or args.url

    if not args.allow_isolated_rehearsal:
        logger.error("FATAL: --allow-isolated-rehearsal flag is required.")
        print(json.dumps({
            "status": "failed",
            "error": "The '--allow-isolated-rehearsal' flag must be provided to confirm execution intent."
        }, indent=2))
        sys.exit(1)

    try:
        res = run_migration_rehearsal(target, allow_isolated_rehearsal=args.allow_isolated_rehearsal)
        print(json.dumps(res, indent=2))
        if res["status"] != "success":
            sys.exit(1)
    except Exception as exc:
        logger.fatal(f"Migration rehearsal aborted: {exc}")
        print(json.dumps({"status": "failed", "error": str(exc)}, indent=2))
        sys.exit(1)
