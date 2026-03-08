FROM python:3.11-alpine

WORKDIR /app


RUN apk update && apk upgrade

COPY requirements.txt .

# Atualiza ferramentas essenciais do Python
RUN pip install --no-cache-dir --upgrade pip wheel setuptools

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8501

ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]