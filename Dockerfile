FROM python:3.11-slim

WORKDIR /app

# psycopg2-binary needs libpq; the slim image ships it already but install
# build-essential just in case the binary wheel falls back to a source build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

EXPOSE 8000

CMD ["python3", "main.py"]
