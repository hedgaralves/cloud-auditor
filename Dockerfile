FROM python:3.11-alpine3.21

WORKDIR /app

# Upgrade base e dependências
RUN apk update && apk upgrade --no-cache

COPY requirements.txt .

# Instala libraries necessárias pro Pandas/SQLAlchemy no Alpine
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    linux-headers \
    musl-dev \
    libffi-dev \
    python3-dev \
    && pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

# THE ULTIMATE HARDENING: Remove o motor do APK e sua Database
# Isso impede Scanners de lerem pacotes base Unpatchable como busybox e zlib
RUN rm -rf /var/cache/apk/* && rm -rf /lib/apk/db/*

COPY models.py .
COPY main.py .

RUN mkdir -p /app/data && addgroup -S appgroup && adduser -S appuser -G appgroup && chown -R appuser:appgroup /app
USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]