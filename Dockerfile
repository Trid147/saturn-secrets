FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/trid147/saturn-secrets"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "main.py"]