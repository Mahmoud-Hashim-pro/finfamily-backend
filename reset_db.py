"""
سكريبت مساعد وقت التطوير بس — بيمسح كل الجداول ويعيد إنشاءها من جديد
بناءً على الشكل الحالي لـ models.py.

استخدمه أي وقت تغيّر فيه db/models.py وعندك جداول قديمة في Postgres
متطابقاش مع الشكل الجديد.

تحذير: ده بيمسح كل البيانات الموجودة في الجداول دي. متستخدموش على
داتابيز فيها بيانات حقيقية عايز تحتفظ بيها — للتطوير بس.

الاستخدام (من جوه backend/, والـ venv مفعّل):
    python reset_db.py
"""

import os
import sys
from dotenv import load_dotenv

load_dotenv()

# حماية من المسح العرضي: التحقق من بيئة التشغيل
env = os.getenv("ENVIRONMENT", os.getenv("ENV", os.getenv("APP_ENV", "development"))).strip().lower()
if env in ("production", "prod"):
    print("Error: Database reset is strictly prohibited in production environment.")
    sys.exit(1)

# حماية إضافية: التحقق من أن رابط الداتابيز لا يشير إلى سيرفر إنتاج خارجي
db_url = os.getenv("DATABASE_URL", "").lower()
if any(prod_host in db_url for prod_host in ["neon.tech", "rds.amazonaws.com", "prod."]):
    print("Error: Database reset aborted! DATABASE_URL points to a production or remote host.")
    sys.exit(1)

# حماية من المسح العرضي: اشتراط متغير البيئة ALLOW_RESET_DB=true (أو ALLOW_DB_RESET=true)
allow_reset = os.getenv("ALLOW_RESET_DB", os.getenv("ALLOW_DB_RESET", "")).strip().lower()
if allow_reset != "true":
    print("Error: Database reset is blocked. ALLOW_RESET_DB=true environment variable must be set to allow resetting the database.")
    sys.exit(1)

from db.database import engine, Base
from db import models  # noqa: F401  (لازم يتعمله import عشان الـ models تتسجل في Base.metadata)

# التحقق من وضع التشغيل (interactive vs automated)
is_forced = ("--yes" in sys.argv) or ("--force" in sys.argv) or (os.getenv("FORCE_RESET_DB", "").lower() == "true")

if not is_forced:
    if not sys.stdin.isatty():
        print("Error: Non-interactive database reset requires --yes flag or FORCE_RESET_DB=true.")
        sys.exit(1)
    confirm = input(
        "ده هيمسح كل الجداول (users, families) وكل البيانات اللي فيها. متأكد؟ (yes/no): "
    )
    if confirm.strip().lower() != "yes":
        print("اتلغى، مفيش حاجة اتمسحت.")
        sys.exit(0)

print("بنمسح الجداول القديمة...")
Base.metadata.drop_all(bind=engine)
print("بننشئ الجداول من جديد بالشكل الحالي...")
Base.metadata.create_all(bind=engine)
print("خلصنا. الجداول دلوقتي متطابقة مع db/models.py.")