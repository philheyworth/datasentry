# DataSentry — Build & Deployment Guide

## Project Structure

```
datasentry/
├── scanner/
│   ├── scanner.py          # Cross-platform scanner agent
│   └── requirements.txt
├── backend/
│   ├── main.py             # FastAPI backend
│   └── requirements.txt
├── dashboard/
│   └── index.html          # Web dashboard (single file)
└── packaging/
    └── BUILD.md            # This file
```

---

## 1. Backend Deployment

### Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Configure environment
```bash
export DATASENTRY_MASTER_KEY="your-strong-master-key-here"
export DATASENTRY_DB="/data/datasentry.db"          # persistent path
export DATASENTRY_CORS_ORIGINS="https://your-dashboard.com"
```

### Run locally
```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
On first run, a default API key is printed to the console. **Save it — it is only shown once.**

### Deploy to cloud

**Fly.io (recommended — free tier available)**
```bash
fly launch --name datasentry-api
fly secrets set DATASENTRY_MASTER_KEY="your-key"
fly volumes create datasentry_data --size 1
fly deploy
```

**Railway**
```bash
railway init
railway add
railway deploy
```
Set environment variables in the Railway dashboard.

**Docker**
```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/main.py .
ENV DATASENTRY_DB=/data/datasentry.db
VOLUME ["/data"]
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```
```bash
docker build -t datasentry-api .
docker run -d -p 8000:8000 -v datasentry_data:/data datasentry-api
```

### Create API keys for scanner agents
```bash
curl -X POST https://your-api.example.com/api/keys \
  -H "X-Master-Key: your-master-key" \
  -H "Content-Type: application/json" \
  -d '{"label": "Client Acme Corp"}'
```

---

## 2. Scanner Agent — Install Dependencies

```bash
cd scanner
pip install -r requirements.txt
```

For full content scanning (recommended):
- `.docx` files: `python-docx` ✓ (in requirements.txt)
- `.xlsx` files: `openpyxl` ✓ (in requirements.txt)
- `.pdf` files: `pdfminer.six` ✓ (in requirements.txt)

---

## 3. Package as Windows .exe

### Install PyInstaller
```bash
pip install pyinstaller
```

### Build (run on a Windows machine for best results)
```bash
cd scanner
pyinstaller --onefile --windowed \
  --name "DataSentry" \
  --icon datasentry.ico \
  scanner.py
```
The output is at `dist/DataSentry.exe`.

### Pre-configure API settings (for IT-deployed builds)
Edit `scanner.py` before packaging to hard-code your API URL and key
so end users just double-click without entering anything:

```python
# Near the bottom of scanner.py, change main() to:
def main():
    run_gui(
        api_url="https://your-api.example.com",
        api_key="dsk_your_key_here"
    )
```

Or pass them via environment variables at deployment time.

### Silent / CLI mode
```bash
DataSentry.exe --cli --api-url https://your-api.example.com --api-key dsk_xxx
```

### Distribute via Group Policy / MDM
Create a GPO that runs:
```
\\domain\NETLOGON\DataSentry.exe --cli --api-url https://your-api.example.com --api-key dsk_xxx
```
Or use Intune to deploy as a Win32 app with the above command line.

---

## 4. Package as macOS .app

### Build on macOS
```bash
cd scanner
pyinstaller --onefile --windowed \
  --name "DataSentry" \
  scanner.py
```

### Sign and notarise (required for distribution)
```bash
codesign --sign "Developer ID Application: Your Name (TEAMID)" dist/DataSentry.app
xcrun altool --notarize-app --primary-bundle-id com.yourcompany.datasentry \
  --username you@example.com --password @keychain:AC_PASSWORD \
  --file DataSentry.app.zip
```

### Deploy via MDM (Jamf / Kandji)
Upload the signed .pkg to your MDM and deploy with the script:
```bash
DATASENTRY_API_URL="https://your-api.example.com" \
DATASENTRY_API_KEY="dsk_your_key" \
/Applications/DataSentry.app/Contents/MacOS/DataSentry --cli
```

---

## 5. Dashboard Deployment

The dashboard is a single `index.html` file. Options:

**Option A — Host on a CDN / static host**
Upload `dashboard/index.html` to any static host:
- Netlify: drag-and-drop the file
- GitHub Pages: commit to a repo
- Azure Static Web Apps / AWS S3 + CloudFront

**Option B — Serve from the backend**
Add to `main.py`:
```python
from fastapi.staticfiles import StaticFiles
app.mount("/", StaticFiles(directory="dashboard", html=True), name="static")
```

**Option C — Open locally**
Just open `dashboard/index.html` in a browser. Enter your API URL and key
in the Settings panel to connect to live data.

---

## 6. Connecting the Dashboard to Live Data

In the dashboard, click **Settings → API / Config** and enter:
- **Backend API URL**: `https://your-api.example.com`
- **API Key**: any key created via the `/api/keys` endpoint

The dashboard fetches from:
- `GET /api/summary` — fleet totals
- `GET /api/machines` — machine list
- `GET /api/machines/{id}` — machine detail
- `GET /api/pii-hotspots` — risk ranking

---

## 7. Recommended Production Stack

| Component | Recommended | Free tier |
|-----------|-------------|-----------|
| Backend   | Fly.io      | Yes (shared CPU) |
| Database  | SQLite on a Fly volume | Yes (1 GB) |
| Dashboard | Netlify     | Yes |
| Scanner   | .exe via Intune / GPO | — |

For larger deployments (1,000+ machines), swap SQLite for PostgreSQL
(Railway or Supabase free tier). The FastAPI backend only needs the
connection string changing — the SQL is standard.
