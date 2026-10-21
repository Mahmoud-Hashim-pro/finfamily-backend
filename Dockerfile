# Stage 1: Build stage with compilation tools (Python 3.12 LTS - FF-43)
FROM python:3.12-slim AS builder

WORKDIR /app

# Install system dependencies required for building wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Hardened runtime stage (no gcc or compilers)
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install only the runtime PostgreSQL shared library
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-installed Python packages from builder stage
COPY --from=builder /install /usr/local

# Create unprivileged system user and group (non-root)
RUN useradd -m -r -u 1001 -s /sbin/nologin appuser

COPY . /app

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
