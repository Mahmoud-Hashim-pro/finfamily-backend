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

from db.database import engine, Base
from db import models  # noqa: F401  (لازم يتعمله import عشان الـ models تتسجل في Base.metadata)

confirm = input(
    "ده هيمسح كل الجداول (users, families) وكل البيانات اللي فيها. متأكد؟ (yes/no): "
)

if confirm.strip().lower() != "yes":
    print("اتلغى، مفيش حاجة اتمسحت.")
else:
    print("بنمسح الجداول القديمة...")
    Base.metadata.drop_all(bind=engine)
    print("بننشئ الجداول من جديد بالشكل الحالي...")
    Base.metadata.create_all(bind=engine)
    print("خلصنا. الجداول دلوقتي متطابقة مع db/models.py.")