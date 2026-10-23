# FinFamily Backend API 💳👨‍👩‍👧‍👦

High-performance, production-hardened **FastAPI** backend powering the FinFamily ecosystem. Built for financial integrity, high concurrency, strict multi-family data isolation, and safe AI coaching.

---

## 🏗️ Architecture & Stack

- **Framework**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL (with SQLAlchemy 2.0 & Alembic migrations)
- **Financial Math**: `Decimal` / `Numeric(12, 2)` throughout (no floats for balances or ledger records)
- **Concurrency & Ledger**: Row-level locking (`with_for_update()`), atomic balance mutations, idempotent replay (`IdempotencyRecord`)
- **Authentication**: JWT with token versions, session invalidation (`/auth/logout`), Google OAuth verification, TOTP MFA with replay protection & single-use recovery codes
- **Authorization**: Role-based (Admin, Parent, Child) + Multi-tenant Family Isolation Policies
- **Rate Limiting**: Slowapi with Vercel/Cloudflare edge proxy anti-spoofing and in-memory fallback circuit breaker
- **AI Coach**: Abstracted Multi-Provider architecture (`OpenAIProvider`, `DeepSeekProvider`, `MockAIProvider`), circuit-breaker quota store with SQLite/memory failover, strict bilingual PII redaction (Eastern Arabic & ASCII digits), and child safety guardrails

---

## 🔒 Security & Access Model

- **Mandatory 2FA**: Mandatory for Administrator accounts (`ADMIN_EMAILS`); optional and supported for Parents.
- **Family Isolation**: All entity lookups (`wallets`, `missions`, `purchases`, `goals`, `children`) strictly verify family tenancy. Cross-family queries return HTTP 404/403.
- **Card State Machine**: Block changing status of permanently deactivated cards; block unfreezing cards that were frozen by administrators.
- **Brute Force Lockout**: 15-minute temporary lockout after 5 consecutive failed parent login attempts (tracked via `AuditLog` across distributed workers).
- **Session Revocation**: `POST /api/auth/logout` increments `token_version`, immediately invalidating all active JWTs for that account.

---

## 📊 Financial Operations

- **Allowance Transfers**: Instant one-tap disbursements ("Disburse Now") with idempotency checks. Scheduled/cron disbursements planned for future roadmap.
- **Meeza Cards**: Simulated closed-loop cards with daily, weekly, and monthly limits evaluated relative to Africa/Cairo local midnight.
- **Missions & Chores**: Chores award pocket money upon parent review; redemptions request cash-out/offline rewards and debit wallet balance upon approval.
- **Savings Goals**: Idempotent deposits and withdrawals with non-negative check constraints.
- **Gamified Learning**: 6 curriculum modules and 10 interactive mini-games awarding XP and coins once per day per game.

---

## 🧪 Testing & Verification

The backend includes a comprehensive automated test suite covering 30 test files and 745+ tests:

```bash
# Run the full test suite
pytest -q

# Run financial concurrency and PostgreSQL parity tests
pytest test_financial_concurrency_extended.py -v

# Run multi-family isolation and Google auth tests
pytest test_cross_family_isolation_and_google_auth.py -v

# Run Alembic migration and backup rehearsal verification
pytest test_migration_and_backup_rehearsal.py -v
```
