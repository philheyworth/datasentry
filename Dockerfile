FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

RUN mkdir -p /data
ENV DATASENTRY_DB=/data/datasentry.db

EXPOSE 8000

CMD ["python3", "main.py"]
