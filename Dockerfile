FROM python:3.10-slim

# متغيرات بايثون قياسية عشان اللوجز تظهر فورًا (مفيدة وقت الـ debugging على Azure)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# مكتبات نظام لازمة لبناء psycopg2-binary وbcrypt/cryptography وقت الـ pip install
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# بنسخ requirements لوحدها الأول عشان Docker يعمل cache للطبقة دي — لو الكود
# اتغيّر بس requirements.txt لأ، مش هيعيد تثبيت كل المكتبات تاني من الصفر
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
