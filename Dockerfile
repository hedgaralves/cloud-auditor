FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip wheel setuptools

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN groupadd -r appgroup && useradd -r -g appgroup appuser && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
