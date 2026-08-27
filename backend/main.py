"""
DataSentry Backend API  v2.0
FastAPI + SQLite, with JWT user auth and customer portal.

Environment variables:
    DATASENTRY_DB           Path to the SQLite database (default: datasentry.db)
    DATASENTRY_JWT_SECRET   Secret for signing JWTs  (auto-generated on first run if unset)
    DATASENTRY_MASTER_KEY   Legacy master key for direct API-key management
    DATASENTRY_CORS_ORIGINS Comma-separated CORS origins (default: *)
    PORT                    HTTP port (Railway sets this automatically)
"""

import os
import io
import json
import sqlite3
import hashlib
import secrets
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

try:
    from jose import JWTError, jwt
    HAS_AUTH = True
except ImportError:
    HAS_AUTH = False
    print("WARNING: python-jose not installed. JWT auth disabled.")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DATABASE_PATH  = os.environ.get("DATASENTRY_DB", "datasentry.db")
# Ensure the DB directory exists (important when Railway volume is mounted at /data)
Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
MASTER_API_KEY = os.environ.get("DATASENTRY_MASTER_KEY", "changeme-set-in-env")
ALLOWED_ORIGINS = os.environ.get("DATASENTRY_CORS_ORIGINS", "*").split(",")
JWT_ALGORITHM  = "HS256"
JWT_EXPIRE_HRS = 8

# JWT secret: from env (required in production), or auto-generated for dev.
_jwt_secret_file = Path(DATABASE_PATH).parent / ".jwt_secret"
if os.environ.get("DATASENTRY_JWT_SECRET"):
    JWT_SECRET = os.environ["DATASENTRY_JWT_SECRET"]
elif _jwt_secret_file.exists():
    JWT_SECRET = _jwt_secret_file.read_text().strip()
else:
    JWT_SECRET = secrets.token_hex(32)
    _jwt_secret_file.write_text(JWT_SECRET)

import hashlib as _hashlib
import hmac as _hmac

def _hash_password(plain: str) -> str:
    """PBKDF2-HMAC-SHA256 password hash. No external dependencies."""
    salt = secrets.token_hex(16)
    dk   = _hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260000)
    return f"pbkdf2:sha256:260000:{salt}:{dk.hex()}"

def _verify_password(plain: str, stored: str) -> bool:
    try:
        _, algo, iters, salt, dk_hex = stored.split(":")
        dk = _hashlib.pbkdf2_hmac(algo, plain.encode(), salt.encode(), int(iters))
        return _hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash    TEXT UNIQUE NOT NULL,
            label       TEXT NOT NULL,
            customer_id TEXT DEFAULT '',
            created_at  TEXT NOT NULL,
            active      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            name          TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            customer_id   TEXT,        -- NULL = global admin (sees all customers)
            customer_name TEXT DEFAULT '',
            role          TEXT DEFAULT 'admin',  -- 'admin' | 'viewer'
            created_at    TEXT DEFAULT (datetime('now')),
            active        INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scans (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id       TEXT NOT NULL,
            hostname         TEXT,
            username         TEXT,
            os               TEXT,
            os_version       TEXT,
            architecture     TEXT,
            customer_id      TEXT DEFAULT '',
            customer_name    TEXT DEFAULT '',
            scan_json        TEXT NOT NULL,
            total_files      INTEGER,
            total_size_bytes INTEGER,
            total_pii_files  INTEGER,
            location_count   INTEGER,
            scanned_at       TEXT NOT NULL,
            received_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_locations (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER NOT NULL REFERENCES scans(id),
            machine_id       TEXT NOT NULL,
            label            TEXT,
            location_type    TEXT,
            path             TEXT,
            total_files      INTEGER,
            total_size_bytes INTEGER,
            pii_file_count   INTEGER,
            pii_summary      TEXT,
            top_extensions   TEXT,
            top_pii_files    TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_machine   ON scans(machine_id);
        CREATE INDEX IF NOT EXISTS idx_scans_received  ON scans(received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_customer  ON scans(customer_id);
        CREATE INDEX IF NOT EXISTS idx_locs_scan       ON scan_locations(scan_id);
        CREATE INDEX IF NOT EXISTS idx_locs_machine    ON scan_locations(machine_id);

        -- ── File inventory: one row per discovered file ─────────────────────────
        CREATE TABLE IF NOT EXISTS file_inventory (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id    TEXT NOT NULL,
            machine_id     TEXT NOT NULL,
            hostname       TEXT,
            file_path      TEXT NOT NULL,
            file_name      TEXT NOT NULL,
            file_ext       TEXT DEFAULT '',
            file_size      INTEGER DEFAULT 0,
            file_modified  TEXT,
            location_type  TEXT NOT NULL DEFAULT 'local',
            location_label TEXT,
            is_local       INTEGER DEFAULT 1,
            pii_status     TEXT DEFAULT 'pending',
            pii_findings   TEXT DEFAULT '{}',
            pii_count      INTEGER DEFAULT 0,
            pii_scanned_at TEXT,
            last_seen      TEXT DEFAULT (datetime('now')),
            created_at     TEXT DEFAULT (datetime('now')),
            UNIQUE(machine_id, file_path)
        );

        -- ── On-demand scan jobs: dashboard → scanner command channel ────────────
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id    TEXT NOT NULL,
            machine_id     TEXT NOT NULL,
            target_path    TEXT NOT NULL,
            location_type  TEXT,
            location_label TEXT,
            status         TEXT DEFAULT 'pending',
            created_by     INTEGER REFERENCES users(id),
            created_at     TEXT DEFAULT (datetime('now')),
            started_at     TEXT,
            completed_at   TEXT,
            files_scanned  INTEGER DEFAULT 0,
            pii_found      INTEGER DEFAULT 0,
            error          TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_inv_customer  ON file_inventory(customer_id);
        CREATE INDEX IF NOT EXISTS idx_inv_machine   ON file_inventory(machine_id);
        CREATE INDEX IF NOT EXISTS idx_inv_loc_type  ON file_inventory(location_type, is_local);
        CREATE INDEX IF NOT EXISTS idx_inv_pii       ON file_inventory(pii_status);
        CREATE INDEX IF NOT EXISTS idx_jobs_pending  ON scan_jobs(machine_id, status);
        CREATE INDEX IF NOT EXISTS idx_jobs_customer ON scan_jobs(customer_id);
    """)
    conn.commit()

    # ── First-run: create API key ──────────────────────────────────────────────
    if conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == 0:
        raw_key = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        conn.execute(
            "INSERT INTO api_keys (key_hash, label, created_at) VALUES (?, ?, ?)",
            (key_hash, "Default Scanner Key", datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
        print(f"\n{'='*62}")
        print(f"  DataSentry — First Run Setup")
        print(f"  Scanner API key : {raw_key}")
        print(f"  (shown once — used by scanner agents to submit reports)")
        print(f"{'='*62}")

    # ── Admin user: create on first run, or enforce password from env var ────────
    env_password = os.environ.get("DATASENTRY_ADMIN_PASSWORD", "")
    if conn.execute("SELECT COUNT(*) FROM users WHERE email='admin@datasentry.local'").fetchone()[0] == 0:
        admin_password = env_password or secrets.token_urlsafe(10)
        admin_hash     = _hash_password(admin_password)
        conn.execute(
            "INSERT INTO users (email, name, password_hash, customer_id, role) VALUES (?,?,?,NULL,'admin')",
            ("admin@datasentry.local", "Admin", admin_hash)
        )
        conn.commit()
        print(f"\n  Dashboard login   : admin@datasentry.local")
        print(f"  Dashboard password: {admin_password}")
        print(f"  (set DATASENTRY_ADMIN_PASSWORD env var to lock this in)")
        print(f"{'='*62}\n")
    elif env_password:
        # If env var is set, always keep the admin password in sync with it
        conn.execute(
            "UPDATE users SET password_hash=? WHERE email='admin@datasentry.local'",
            (_hash_password(env_password),)
        )
        conn.commit()
        print("  Admin password synced from DATASENTRY_ADMIN_PASSWORD env var.")

    # ── Seed customer from env vars (survives redeploys without a volume) ────────
    # Set these in Railway environment variables once and the customer is
    # recreated automatically every time the container restarts.
    #
    #   DATASENTRY_SEED_CUSTOMER_ID       e.g.  my-company
    #   DATASENTRY_SEED_CUSTOMER_NAME     e.g.  My Company Ltd
    #   DATASENTRY_SEED_CUSTOMER_EMAIL    e.g.  admin@mycompany.com
    #   DATASENTRY_SEED_CUSTOMER_PASSWORD e.g.  a-strong-password
    #   DATASENTRY_SEED_SCANNER_KEY       e.g.  dsk_abc123  (optional, auto-generated if unset)
    seed_cid   = os.environ.get("DATASENTRY_SEED_CUSTOMER_ID", "").strip()
    seed_cname = os.environ.get("DATASENTRY_SEED_CUSTOMER_NAME", "").strip()
    seed_email = os.environ.get("DATASENTRY_SEED_CUSTOMER_EMAIL", "").strip()
    seed_pass  = os.environ.get("DATASENTRY_SEED_CUSTOMER_PASSWORD", "").strip()
    seed_key   = os.environ.get("DATASENTRY_SEED_SCANNER_KEY", "").strip()

    if seed_cid and seed_cname and seed_email and seed_pass:
        # Upsert the customer row
        conn.execute(
            "INSERT OR IGNORE INTO customers (customer_id, customer_name) VALUES (?,?)",
            (seed_cid, seed_cname)
        )
        conn.execute(
            "UPDATE customers SET customer_name=? WHERE customer_id=?",
            (seed_cname, seed_cid)
        )

        # Upsert the customer portal user
        existing_user = conn.execute(
            "SELECT id FROM users WHERE email=?", (seed_email,)
        ).fetchone()
        pw_hash = _hash_password(seed_pass)
        if existing_user:
            conn.execute(
                "UPDATE users SET password_hash=?, customer_id=?, customer_name=?, role='viewer' WHERE email=?",
                (pw_hash, seed_cid, seed_cname, seed_email)
            )
        else:
            conn.execute(
                "INSERT INTO users (email, name, password_hash, customer_id, customer_name, role) VALUES (?,?,?,?,?,'viewer')",
                (seed_email, seed_cname, pw_hash, seed_cid, seed_cname)
            )

        # Upsert the scanner API key
        if seed_key:
            key_hash = hashlib.sha256(seed_key.encode()).hexdigest()
            existing_key = conn.execute(
                "SELECT id FROM api_keys WHERE key_hash=?", (key_hash,)
            ).fetchone()
            if not existing_key:
                conn.execute(
                    "INSERT INTO api_keys (key_hash, label, customer_id, created_at, active) VALUES (?,?,?,?,1)",
                    (key_hash, f"Seed key — {seed_cname}", seed_cid, datetime.utcnow().isoformat())
                )
        else:
            # Auto-generate a stable key derived from the customer_id (deterministic)
            import hmac as _hmac_mod
            seed_key = "dsk_" + _hmac_mod.new(
                JWT_SECRET.encode(), seed_cid.encode(), "sha256"
            ).hexdigest()[:32]
            key_hash = hashlib.sha256(seed_key.encode()).hexdigest()
            conn.execute(
                "INSERT OR IGNORE INTO api_keys (key_hash, label, customer_id, created_at, active) VALUES (?,?,?,?,1)",
                (key_hash, f"Auto-seed key — {seed_cname}", seed_cid, datetime.utcnow().isoformat())
            )

        conn.commit()
        print(f"[DataSentry] Seed customer '{seed_cid}' ({seed_cname}) ensured in DB.")
        print(f"[DataSentry] Seed scanner key: {seed_key}")

    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# JWT / AUTH HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def make_token(user_id: int, email: str, customer_id: Optional[str], role: str) -> str:
    payload = {
        "sub":         str(user_id),
        "email":       email,
        "customer_id": customer_id,
        "role":        role,
        "exp":         datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HRS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def _bearer(authorization: str = Header(None)) -> Optional[dict]:
    """Extract + decode a Bearer JWT. Returns the payload dict or None."""
    if not HAS_AUTH or not authorization:
        return None
    if not authorization.startswith("Bearer "):
        return None
    try:
        return decode_token(authorization[7:])
    except (JWTError, Exception):
        return None


def require_user(payload: Optional[dict] = Depends(_bearer)):
    if not payload:
        raise HTTPException(status_code=401, detail="Login required")
    return payload


def require_admin(payload: dict = Depends(require_user)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload


def require_api_key(x_api_key: str = Header(...), db: sqlite3.Connection = Depends(get_db)):
    if x_api_key == MASTER_API_KEY and MASTER_API_KEY != "changeme-set-in-env":
        return {"customer_id": None, "customer_name": None}
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    row = db.execute(
        "SELECT id, customer_id FROM api_keys WHERE key_hash = ? AND active = 1", (key_hash,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    cust_id = row["customer_id"] or ""
    # look up customer_name from users table
    urow = db.execute(
        "SELECT customer_name FROM users WHERE customer_id = ? LIMIT 1", (cust_id,)
    ).fetchone()
    return {"customer_id": cust_id, "customer_name": urow["customer_name"] if urow else ""}


def _customer_filter(payload: Optional[dict]) -> Optional[str]:
    """Return customer_id to filter by, or None if admin (sees all)."""
    if not payload:
        return None
    if payload.get("role") == "admin" and payload.get("customer_id") is None:
        return None  # global admin
    return payload.get("customer_id")


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="DataSentry API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class CreateUserRequest(BaseModel):
    email:         str
    name:          str
    password:      str
    customer_id:   Optional[str] = None
    customer_name: Optional[str] = None
    role:          str = "admin"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


@app.post("/auth/login")
def login(body: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    if not HAS_AUTH:
        raise HTTPException(status_code=503, detail="Auth libraries not installed")
    row = db.execute(
        "SELECT id, email, name, password_hash, customer_id, customer_name, role, active FROM users WHERE email = ?",
        (body.email,)
    ).fetchone()
    if not row or not row["active"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not _verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = make_token(row["id"], row["email"], row["customer_id"], row["role"])
    return {
        "access_token":  token,
        "token_type":    "bearer",
        "expires_in":    JWT_EXPIRE_HRS * 3600,
        "user": {
            "id":            row["id"],
            "email":         row["email"],
            "name":          row["name"],
            "customer_id":   row["customer_id"],
            "customer_name": row["customer_name"],
            "role":          row["role"],
        }
    }


@app.get("/auth/me")
def me(payload: dict = Depends(require_user), db: sqlite3.Connection = Depends(get_db)):
    row = db.execute(
        "SELECT id, email, name, customer_id, customer_name, role FROM users WHERE id = ?",
        (int(payload["sub"]),)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


@app.post("/auth/users", status_code=201)
def create_user(body: CreateUserRequest, payload: dict = Depends(require_admin),
                db: sqlite3.Connection = Depends(get_db)):
    """Admin creates a new portal user (for a customer or another admin)."""
    pw_hash = _hash_password(body.password)
    try:
        db.execute(
            """INSERT INTO users (email, name, password_hash, customer_id, customer_name, role)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (body.email, body.name, pw_hash, body.customer_id, body.customer_name or "", body.role)
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email already exists")

    # If creating a customer user, also generate a scanner API key for them
    scanner_key = None
    if body.customer_id:
        raw_key  = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        label    = f"{body.customer_name or body.customer_id} Scanner Key"
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (?, ?, ?, ?)",
            (key_hash, label, body.customer_id, datetime.utcnow().isoformat() + "Z")
        )
        db.commit()
        scanner_key = raw_key

    return {
        "email":       body.email,
        "customer_id": body.customer_id,
        "role":        body.role,
        "scanner_api_key": scanner_key,
        "note": "scanner_api_key is shown once — store it securely" if scanner_key else None,
    }


@app.get("/auth/users")
def list_users(payload: dict = Depends(require_admin), db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute(
        "SELECT id, email, name, customer_id, customer_name, role, created_at, active FROM users"
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/auth/change-password")
def change_password(body: ChangePasswordRequest, payload: dict = Depends(require_user),
                    db: sqlite3.Connection = Depends(get_db)):
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (int(payload["sub"]),)).fetchone()
    if not row or not _verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password incorrect")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (_hash_password(body.new_password), int(payload["sub"])))
    db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER SUBMISSION  (X-API-Key auth, unchanged)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/scans", status_code=201)
async def receive_scan(request: Request,
                       key_info: dict = Depends(require_api_key),
                       db: sqlite3.Connection = Depends(get_db)):
    try:
        report = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    machine       = report.get("machine", {})
    customer      = report.get("customer", {})
    summary       = report.get("summary", {})
    locations     = report.get("locations", [])
    machine_id    = machine.get("machine_id") or machine.get("hostname", "unknown")
    # API key is authoritative for customer identity; body values are fallback only
    customer_id   = key_info.get("customer_id") or customer.get("id", "")
    customer_name = key_info.get("customer_name") or customer.get("name", "")
    scanned_at    = report.get("scan_started_at", datetime.utcnow().isoformat() + "Z")
    received_at   = datetime.utcnow().isoformat() + "Z"

    cursor = db.execute("""
        INSERT INTO scans
            (machine_id, hostname, username, os, os_version, architecture,
             customer_id, customer_name, scan_json,
             total_files, total_size_bytes, total_pii_files,
             location_count, scanned_at, received_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        machine_id, machine.get("hostname"), machine.get("username"),
        machine.get("os"), machine.get("os_version"), machine.get("architecture"),
        customer_id, customer_name, json.dumps(report),
        summary.get("total_files", 0), summary.get("total_size_bytes", 0),
        summary.get("total_pii_files", 0), len(locations),
        scanned_at, received_at,
    ))
    scan_id = cursor.lastrowid

    for loc in locations:
        db.execute("""
            INSERT INTO scan_locations
                (scan_id, machine_id, label, location_type, path,
                 total_files, total_size_bytes, pii_file_count,
                 pii_summary, top_extensions, top_pii_files)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id, machine_id, loc.get("label"), loc.get("type"), loc.get("path"),
            loc.get("total_files", 0), loc.get("total_size_bytes", 0),
            loc.get("pii_file_count", 0),
            json.dumps(loc.get("pii_summary", {})),
            json.dumps(loc.get("top_extensions", [])),
            json.dumps(loc.get("top_pii_files", [])),
        ))

    db.commit()
    return {"scan_id": scan_id, "machine_id": machine_id, "received_at": received_at}


# ─────────────────────────────────────────────────────────────────────────────
# DASHBOARD DATA  (JWT auth — customer-scoped)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/customers")
def list_customers(payload: dict = Depends(require_user), db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    where  = "WHERE s.customer_id = ?" if cust_filter else ""
    params = (cust_filter,) if cust_filter else ()
    rows = db.execute(f"""
        SELECT s.customer_id, s.customer_name,
               COUNT(DISTINCT s.machine_id)  AS machine_count,
               SUM(s.total_files)            AS total_files,
               SUM(s.total_size_bytes)       AS total_size_bytes,
               SUM(s.total_pii_files)        AS total_pii_files,
               MAX(s.scanned_at)             AS last_scanned_at
        FROM scans s
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) l ON s.machine_id = l.machine_id AND s.received_at = l.latest
        {where}
        GROUP BY s.customer_id, s.customer_name
        ORDER BY machine_count DESC
    """, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/customers/{customer_id}/machines")
def list_customer_machines(customer_id: str, payload: dict = Depends(require_user),
                           db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    if cust_filter and cust_filter != customer_id:
        raise HTTPException(status_code=403, detail="Access denied")
    rows = db.execute("""
        SELECT s.machine_id, s.hostname, s.username, s.os, s.os_version,
               s.customer_id, s.customer_name,
               s.total_files, s.total_size_bytes, s.total_pii_files,
               s.location_count, s.scanned_at
        FROM scans s
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) l ON s.machine_id = l.machine_id AND s.received_at = l.latest
        WHERE s.customer_id = ?
        ORDER BY s.total_pii_files DESC
    """, (customer_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/machines")
def list_machines(customer_id: Optional[str] = None, payload: dict = Depends(require_user),
                  db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    effective   = cust_filter or customer_id
    where  = "WHERE s.customer_id = ?" if effective else ""
    params = (effective,) if effective else ()
    rows = db.execute(f"""
        SELECT s.machine_id, s.hostname, s.username, s.os,
               s.customer_id, s.customer_name,
               s.total_files, s.total_size_bytes, s.total_pii_files,
               s.location_count, s.scanned_at,
               COUNT(*) OVER (PARTITION BY s.machine_id) AS scan_count
        FROM scans s
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest
            FROM scans GROUP BY machine_id
        ) latest ON s.machine_id = latest.machine_id AND s.received_at = latest.latest
        {where}
        ORDER BY s.received_at DESC
    """, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/machines/{machine_id}")
def get_machine(machine_id: str, payload: dict = Depends(require_user),
                db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    row = db.execute("""
        SELECT scan_json, customer_id FROM scans
        WHERE machine_id = ?
        ORDER BY received_at DESC LIMIT 1
    """, (machine_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Machine not found")
    if cust_filter and row["customer_id"] != cust_filter:
        raise HTTPException(status_code=403, detail="Access denied")
    return json.loads(row["scan_json"])


@app.get("/api/machines/{machine_id}/history")
def get_machine_history(machine_id: str, payload: dict = Depends(require_user),
                        db: sqlite3.Connection = Depends(get_db)):
    rows = db.execute("""
        SELECT id, total_files, total_size_bytes, total_pii_files,
               location_count, scanned_at, received_at
        FROM scans WHERE machine_id = ?
        ORDER BY received_at DESC LIMIT 20
    """, (machine_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/summary")
def global_summary(customer_id: Optional[str] = None, payload: dict = Depends(require_user),
                   db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    effective   = cust_filter or customer_id
    where  = "WHERE s.customer_id = ?" if effective else ""
    params = (effective,) if effective else ()
    totals = db.execute(f"""
        SELECT COUNT(DISTINCT machine_id) AS total_machines,
               SUM(total_files)           AS total_files,
               SUM(total_size_bytes)      AS total_size_bytes,
               SUM(total_pii_files)       AS total_pii_files
        FROM (
            SELECT s.machine_id, s.total_files, s.total_size_bytes, s.total_pii_files
            FROM scans s
            INNER JOIN (
                SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
            ) l ON s.machine_id = l.machine_id AND s.received_at = l.latest
            {where}
        )
    """, params).fetchone()

    loc_types = db.execute("""
        SELECT sl.location_type,
               COUNT(DISTINCT sl.machine_id) AS machine_count,
               SUM(sl.total_files)           AS total_files,
               SUM(sl.total_size_bytes)      AS total_size_bytes,
               SUM(sl.pii_file_count)        AS pii_file_count
        FROM scan_locations sl
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) l ON sl.machine_id = l.machine_id
        INNER JOIN scans s ON s.machine_id = l.machine_id AND s.received_at = l.latest
                          AND sl.scan_id = s.id
        GROUP BY sl.location_type
        ORDER BY total_files DESC
    """).fetchall()

    pii_rows = db.execute("""
        SELECT pii_summary FROM scan_locations sl
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) l ON sl.machine_id = l.machine_id
        INNER JOIN scans s ON s.machine_id = l.machine_id AND s.received_at = l.latest
                          AND sl.scan_id = s.id
    """).fetchall()
    pii_totals: dict = {}
    for row in pii_rows:
        try:
            for k, v in json.loads(row["pii_summary"]).items():
                pii_totals[k] = pii_totals.get(k, 0) + v
        except Exception:
            pass

    return {
        "totals":         dict(totals) if totals else {},
        "location_types": [dict(r) for r in loc_types],
        "pii_totals":     pii_totals,
    }


@app.get("/api/pii-hotspots")
def pii_hotspots(limit: int = 20, payload: dict = Depends(require_user),
                 db: sqlite3.Connection = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    where  = "WHERE s.customer_id = ?" if cust_filter else ""
    params = (cust_filter, limit) if cust_filter else (limit,)
    rows = db.execute(f"""
        SELECT s.machine_id, s.hostname, s.username, s.os,
               s.customer_id, s.customer_name,
               s.total_pii_files, s.total_files, s.scanned_at
        FROM scans s
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) l ON s.machine_id = l.machine_id AND s.received_at = l.latest
        {where}
        ORDER BY s.total_pii_files DESC LIMIT ?
    """, params).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMER MANAGEMENT  (admin only)
# ─────────────────────────────────────────────────────────────────────────────

class NewCustomerRequest(BaseModel):
    customer_id:   str        # e.g. "acme-corp"
    customer_name: str        # e.g. "Acme Corporation"
    admin_email:   str        # portal login for their admin
    admin_name:    str
    admin_password: str


@app.post("/api/customers/create", status_code=201)
def create_customer(body: NewCustomerRequest, payload: dict = Depends(require_admin),
                    db: sqlite3.Connection = Depends(get_db)):
    """Admin creates a new customer — portal user + scanner API key in one step."""
    # Create portal user
    pw_hash = _hash_password(body.admin_password)
    try:
        db.execute(
            """INSERT INTO users (email, name, password_hash, customer_id, customer_name, role)
               VALUES (?, ?, ?, ?, ?, 'admin')""",
            (body.admin_email, body.admin_name, pw_hash, body.customer_id, body.customer_name)
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email already in use")

    # Create scanner API key for this customer
    raw_key  = "dsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (?, ?, ?, ?)",
        (key_hash, f"{body.customer_name} Scanner Key", body.customer_id,
         datetime.utcnow().isoformat() + "Z")
    )
    db.commit()

    return {
        "customer_id":     body.customer_id,
        "customer_name":   body.customer_name,
        "portal_email":    body.admin_email,
        "scanner_api_key": raw_key,
        "note": "Store scanner_api_key securely — shown once only",
    }


# ─────────────────────────────────────────────────────────────────────────────
# AGENT DOWNLOAD  (JWT auth — generates pre-configured installer)
# ─────────────────────────────────────────────────────────────────────────────

_EXE_CACHE: dict = {"bytes": None, "fetched_at": None}
_BASE_EXE_URL = "https://github.com/philheyworth/datasentry/releases/latest/download/DataSentry.exe"
_EXE_CACHE_TTL_HOURS = 6

def _fetch_base_exe() -> bytes | None:
    """
    Fetch the pre-built DataSentry.exe from GitHub Releases.
    Caches in memory for 6 hours so every download doesn't hit GitHub.
    Returns None if unavailable (build not yet published).
    """
    import urllib.request
    from datetime import timezone

    now = datetime.now(timezone.utc)
    cached = _EXE_CACHE.get("bytes")
    fetched_at = _EXE_CACHE.get("fetched_at")

    if cached and fetched_at:
        age_hours = (now - fetched_at).total_seconds() / 3600
        if age_hours < _EXE_CACHE_TTL_HOURS:
            return cached

    try:
        print(f"[DataSentry] Fetching base EXE from GitHub Releases...", flush=True)
        req = urllib.request.Request(
            _BASE_EXE_URL,
            headers={"User-Agent": "DataSentry-Backend/2.0"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        _EXE_CACHE["bytes"] = data
        _EXE_CACHE["fetched_at"] = now
        print(f"[DataSentry] EXE fetched: {len(data):,} bytes", flush=True)
        return data
    except Exception as e:
        print(f"[DataSentry] WARNING: Could not fetch base EXE: {e}", flush=True)
        return None

@app.get("/api/download/config")
def download_config(request: Request, payload: dict = Depends(require_user),
                    db: sqlite3.Connection = Depends(get_db)):
    """Return a pre-configured datasentry.cfg for the logged-in customer."""
    cust_id   = payload.get("customer_id") or ""
    cust_name = ""
    api_key   = ""

    if cust_id:
        user_row = db.execute(
            "SELECT customer_name FROM users WHERE customer_id = ? LIMIT 1", (cust_id,)
        ).fetchone()
        cust_name = user_row["customer_name"] if user_row else cust_id

        key_row = db.execute(
            "SELECT key_hash FROM api_keys WHERE customer_id = ? AND active = 1 LIMIT 1",
            (cust_id,)
        ).fetchone()
        # We can't un-hash, so we generate a fresh key and return it
        raw_key  = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (?, ?, ?, ?)",
            (key_hash, f"{cust_name} Download Key", cust_id,
             datetime.utcnow().isoformat() + "Z")
        )
        db.commit()
        api_key = raw_key

    # Determine the base URL from the request
    host    = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    scheme  = request.headers.get("x-forwarded-proto", "https" if "railway" in host else "http")
    api_url = f"{scheme}://{host}"

    cfg_content = f"""[datasentry]
; DataSentry Agent Configuration
; Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
; Customer:  {cust_name or 'Global Admin'}

api_url       = {api_url}
api_key       = {api_key}
customer_id   = {cust_id}
customer_name = {cust_name}
"""

    return Response(
        content=cfg_content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="datasentry.cfg"'},
    )


@app.get("/api/download/installer")
def download_installer(request: Request, payload: dict = Depends(require_user),
                       db: sqlite3.Connection = Depends(get_db)):
    """Return a ZIP containing a pre-configured BAT installer + config file."""
    cust_id   = payload.get("customer_id") or ""
    cust_name = ""
    api_key   = ""

    if cust_id:
        user_row  = db.execute(
            "SELECT customer_name FROM users WHERE customer_id = ? LIMIT 1", (cust_id,)
        ).fetchone()
        cust_name = user_row["customer_name"] if user_row else cust_id
        raw_key   = "dsk_" + secrets.token_urlsafe(32)
        key_hash  = hashlib.sha256(raw_key.encode()).hexdigest()
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (?, ?, ?, ?)",
            (key_hash, f"{cust_name} Installer Key", cust_id,
             datetime.utcnow().isoformat() + "Z")
        )
        db.commit()
        api_key = raw_key

    host    = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    scheme  = request.headers.get("x-forwarded-proto", "https" if "railway" in host else "http")
    api_url = f"{scheme}://{host}"

    cfg = f"""[datasentry]
api_url       = {api_url}
api_key       = {api_key}
customer_id   = {cust_id}
customer_name = {cust_name}
"""

    slug = (cust_id or "datasentry").replace(" ", "-").lower()

    # ── Fetch the pre-built EXE from GitHub Releases ──────────────────────────
    exe_bytes = _fetch_base_exe()

    # ── Build ZIP in memory ───────────────────────────────────────────────────
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Pre-configured agent EXE (reads datasentry.cfg from its own folder)
        if exe_bytes:
            zf.writestr(f"DataSentry.exe", exe_bytes)

        # Customer-specific config — EXE reads this automatically on launch
        zf.writestr("datasentry.cfg", cfg)

        # Scheduled-task helper (optional, for IT deployment)
        bat = f"""@echo off
REM DataSentry — Install & Schedule  ({cust_name or slug})
REM Run as Administrator on each endpoint.
setlocal
set HERE=%~dp0
set INSTALL_DIR=%ProgramFiles%\\DataSentry\\{slug}
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /y "%HERE%DataSentry.exe" "%INSTALL_DIR%\\DataSentry.exe" >nul
copy /y "%HERE%datasentry.cfg" "%INSTALL_DIR%\\datasentry.cfg" >nul
schtasks /create /tn "DataSentry - {cust_name or slug}" ^
    /tr "\"%INSTALL_DIR%\\DataSentry.exe\" --cli" ^
    /sc WEEKLY /d MON /st 07:00 /ru SYSTEM /f >nul 2>&1
echo Installed. Running first scan now...
"%INSTALL_DIR%\\DataSentry.exe" --cli
echo Done.
pause
"""
        zf.writestr("install.bat", bat)
        zf.writestr("README.txt", f"""DataSentry Agent — {cust_name or slug}
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

QUICK START (single machine)
=============================
1. Unzip this folder somewhere (e.g. Desktop).
2. Double-click DataSentry.exe — it will scan and upload results automatically.
   No setup required; it is pre-configured for your organisation.

DEPLOY TO MULTIPLE MACHINES (IT admin)
=======================================
1. Run install.bat as Administrator on each endpoint  (or deploy via
   Group Policy / Intune / SCCM as a startup script).
   It copies the files to Program Files and schedules a weekly scan.

{'NOTE: DataSentry.exe could not be bundled (build not yet available).' + chr(10) + 'Download it from: https://github.com/philheyworth/datasentry/releases/latest' if not exe_bytes else ''}
""")
    buf.seek(0)

    filename = f"DataSentry-{slug}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# API KEY MANAGEMENT  (legacy — master key)
# ─────────────────────────────────────────────────────────────────────────────

class NewKeyRequest(BaseModel):
    label: str

@app.post("/api/keys", status_code=201)
def create_api_key(body: NewKeyRequest, x_master_key: str = Header(...),
                   db: sqlite3.Connection = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    raw_key  = "dsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_keys (key_hash, label, created_at) VALUES (?, ?, ?)",
        (key_hash, body.label, datetime.utcnow().isoformat() + "Z")
    )
    db.commit()
    return {"key": raw_key, "label": body.label,
            "note": "Store this key securely — it will not be shown again"}


@app.get("/api/keys")
def list_keys(x_master_key: str = Header(...), db: sqlite3.Connection = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    rows = db.execute(
        "SELECT id, label, customer_id, created_at, active FROM api_keys"
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/keys/{key_id}")
def revoke_key(key_id: int, x_master_key: str = Header(...),
               db: sqlite3.Connection = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    db.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,))
    db.commit()
    return {"revoked": key_id}


# ─────────────────────────────────────────────────────────────────────────────
# FILE INVENTORY  (scanner submits; dashboard reads)
# ─────────────────────────────────────────────────────────────────────────────

class InventoryRecord(BaseModel):
    file_path:      str
    file_name:      str
    file_ext:       str = ""
    file_size:      int = 0
    file_modified:  Optional[str] = None
    location_type:  str = "local"
    location_label: Optional[str] = None
    is_local:       bool = True
    pii_status:     str = "pending"   # pending | clean | findings | skipped
    pii_findings:   dict = {}
    pii_count:      int = 0
    pii_scanned_at: Optional[str] = None


class InventoryBatch(BaseModel):
    machine_id:   str
    hostname:     Optional[str] = None
    records:      list[InventoryRecord]


@app.post("/api/inventory", status_code=200)
async def receive_inventory(body: InventoryBatch,
                            key_info: dict = Depends(require_api_key),
                            db: sqlite3.Connection = Depends(get_db)):
    """
    Scanner posts a batch of file inventory records.
    Uses INSERT OR REPLACE so re-scans update existing rows cleanly.
    Accepts up to 2000 records per call; scanner should batch large directories.
    """
    if len(body.records) > 2000:
        raise HTTPException(status_code=400, detail="Max 2000 records per batch")

    customer_id = key_info.get("customer_id") or ""
    now = datetime.utcnow().isoformat() + "Z"

    rows = [
        (
            customer_id,
            body.machine_id,
            body.hostname,
            r.file_path,
            r.file_name,
            r.file_ext,
            r.file_size,
            r.file_modified,
            r.location_type,
            r.location_label,
            1 if r.is_local else 0,
            r.pii_status,
            json.dumps(r.pii_findings),
            r.pii_count,
            r.pii_scanned_at,
            now,   # last_seen
        )
        for r in body.records
    ]

    db.executemany("""
        INSERT INTO file_inventory
            (customer_id, machine_id, hostname, file_path, file_name, file_ext,
             file_size, file_modified, location_type, location_label, is_local,
             pii_status, pii_findings, pii_count, pii_scanned_at, last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(machine_id, file_path) DO UPDATE SET
            file_size      = excluded.file_size,
            file_modified  = excluded.file_modified,
            location_type  = excluded.location_type,
            location_label = excluded.location_label,
            is_local       = excluded.is_local,
            pii_status     = CASE WHEN excluded.pii_status != 'pending'
                                  THEN excluded.pii_status
                                  ELSE file_inventory.pii_status END,
            pii_findings   = CASE WHEN excluded.pii_status != 'pending'
                                  THEN excluded.pii_findings
                                  ELSE file_inventory.pii_findings END,
            pii_count      = CASE WHEN excluded.pii_status != 'pending'
                                  THEN excluded.pii_count
                                  ELSE file_inventory.pii_count END,
            pii_scanned_at = CASE WHEN excluded.pii_scanned_at IS NOT NULL
                                  THEN excluded.pii_scanned_at
                                  ELSE file_inventory.pii_scanned_at END,
            last_seen      = excluded.last_seen
    """, rows)
    db.commit()
    return {"accepted": len(rows)}


@app.get("/api/inventory/summary")
def inventory_summary(payload: dict = Depends(require_user),
                      db: sqlite3.Connection = Depends(get_db)):
    """
    Returns per-machine, per-location-type aggregates for the Data Map view.
    """
    cust_filter = _customer_filter(payload)
    where  = "WHERE customer_id = ?" if cust_filter else ""
    params = (cust_filter,) if cust_filter else ()

    # Machine-level summary
    machines = db.execute(f"""
        SELECT machine_id, hostname,
               COUNT(*)                                        AS total_files,
               SUM(file_size)                                  AS total_bytes,
               SUM(CASE WHEN is_local = 0 THEN 1 ELSE 0 END)  AS cloud_files,
               SUM(CASE WHEN is_local = 1 THEN 1 ELSE 0 END)  AS local_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files,
               SUM(CASE WHEN pii_status = 'pending'  THEN 1 ELSE 0 END) AS unscanned_files,
               MAX(last_seen)                                  AS last_seen
        FROM file_inventory
        {where}
        GROUP BY machine_id, hostname
        ORDER BY total_files DESC
    """, params).fetchall()

    # Location-type breakdown
    loc_types = db.execute(f"""
        SELECT location_type,
               COUNT(*)                                        AS total_files,
               SUM(file_size)                                  AS total_bytes,
               SUM(CASE WHEN is_local = 0 THEN 1 ELSE 0 END)  AS cloud_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files
        FROM file_inventory
        {where}
        GROUP BY location_type
        ORDER BY total_files DESC
    """, params).fetchall()

    # Per-machine per-location breakdown (for folder tree)
    machine_locs = db.execute(f"""
        SELECT machine_id, hostname, location_type, location_label,
               COUNT(*)                                        AS total_files,
               SUM(file_size)                                  AS total_bytes,
               SUM(CASE WHEN is_local = 0 THEN 1 ELSE 0 END)  AS cloud_files,
               SUM(CASE WHEN is_local = 1 THEN 1 ELSE 0 END)  AS local_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files,
               SUM(CASE WHEN pii_status = 'pending' AND is_local = 0
                        THEN 1 ELSE 0 END)                     AS pending_cloud,
               SUM(pii_count)                                  AS total_pii_hits,
               MIN(last_seen)                                  AS last_seen
        FROM file_inventory
        {where}
        GROUP BY machine_id, hostname, location_type, location_label
        ORDER BY machine_id, total_files DESC
    """, params).fetchall()

    return {
        "machines":      [dict(r) for r in machines],
        "location_types": [dict(r) for r in loc_types],
        "machine_locations": [dict(r) for r in machine_locs],
    }


@app.get("/api/inventory")
def list_inventory(machine_id: Optional[str] = None,
                   location_type: Optional[str] = None,
                   pii_status: Optional[str] = None,
                   is_local: Optional[int] = None,
                   limit: int = 500,
                   offset: int = 0,
                   payload: dict = Depends(require_user),
                   db: sqlite3.Connection = Depends(get_db)):
    """Paginated file inventory with optional filters."""
    cust_filter = _customer_filter(payload)
    conditions = []
    params: list = []
    if cust_filter:
        conditions.append("customer_id = ?"); params.append(cust_filter)
    if machine_id:
        conditions.append("machine_id = ?");   params.append(machine_id)
    if location_type:
        conditions.append("location_type = ?"); params.append(location_type)
    if pii_status:
        conditions.append("pii_status = ?");    params.append(pii_status)
    if is_local is not None:
        conditions.append("is_local = ?");      params.append(is_local)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    limit = min(limit, 1000)
    params += [limit, offset]

    rows = db.execute(f"""
        SELECT id, machine_id, hostname, file_path, file_name, file_ext,
               file_size, file_modified, location_type, location_label,
               is_local, pii_status, pii_findings, pii_count,
               pii_scanned_at, last_seen
        FROM file_inventory {where}
        ORDER BY pii_count DESC, file_size DESC
        LIMIT ? OFFSET ?
    """, params).fetchall()

    total = db.execute(f"SELECT COUNT(*) FROM file_inventory {where}",
                       params[:-2]).fetchone()[0]

    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [dict(r) for r in rows],
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCAN JOBS  (dashboard creates; scanner polls and executes)
# ─────────────────────────────────────────────────────────────────────────────

class CreateScanJobRequest(BaseModel):
    machine_id:     str
    target_path:    str
    location_type:  Optional[str] = None
    location_label: Optional[str] = None


class UpdateScanJobRequest(BaseModel):
    status:        Optional[str] = None   # running | completed | failed
    files_scanned: Optional[int] = None
    pii_found:     Optional[int] = None
    error:         Optional[str] = None


@app.post("/api/scan-jobs", status_code=201)
def create_scan_job(body: CreateScanJobRequest,
                    payload: dict = Depends(require_user),
                    db: sqlite3.Connection = Depends(get_db)):
    """
    Dashboard creates an on-demand PII scan job for a specific path on a machine.
    The scanner picks this up on its next poll.
    """
    cust_filter = _customer_filter(payload)

    # Validate machine belongs to this customer
    owner = db.execute(
        "SELECT customer_id FROM file_inventory WHERE machine_id = ? LIMIT 1",
        (body.machine_id,)
    ).fetchone()
    if owner and cust_filter and owner["customer_id"] != cust_filter:
        raise HTTPException(status_code=403, detail="Access denied")

    # Prevent duplicate pending jobs for the same path
    existing = db.execute("""
        SELECT id FROM scan_jobs
        WHERE machine_id = ? AND target_path = ? AND status = 'pending'
    """, (body.machine_id, body.target_path)).fetchone()
    if existing:
        return {"job_id": existing["id"], "status": "pending", "note": "job already queued"}

    customer_id = cust_filter or (owner["customer_id"] if owner else "")
    cursor = db.execute("""
        INSERT INTO scan_jobs
            (customer_id, machine_id, target_path, location_type, location_label, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (customer_id, body.machine_id, body.target_path,
          body.location_type, body.location_label, int(payload["sub"])))
    db.commit()
    return {"job_id": cursor.lastrowid, "status": "pending"}


@app.get("/api/scan-jobs/pending")
def get_pending_jobs(machine_id: str,
                     key_info: dict = Depends(require_api_key),
                     db: sqlite3.Connection = Depends(get_db)):
    """
    Scanner polls this endpoint after each scan to pick up on-demand jobs.
    Returns pending jobs for this machine (scoped to API key's customer).
    """
    customer_id = key_info.get("customer_id") or ""
    where_cust  = "AND customer_id = ?" if customer_id else ""
    params      = [machine_id, machine_id] + ([customer_id] * 2 if customer_id else [])
    # Use a subquery to mark as 'running' atomically isn't possible in SQLite
    # without WAL; instead we return pending and let scanner PATCH immediately.
    rows = db.execute(f"""
        SELECT id, target_path, location_type, location_label, created_at
        FROM scan_jobs
        WHERE machine_id = ? AND status = 'pending' {where_cust}
        ORDER BY created_at
        LIMIT 5
    """, [machine_id] + ([customer_id] if customer_id else [])).fetchall()
    return [dict(r) for r in rows]


@app.patch("/api/scan-jobs/{job_id}")
def update_scan_job(job_id: int, body: UpdateScanJobRequest,
                    key_info: dict = Depends(require_api_key),
                    db: sqlite3.Connection = Depends(get_db)):
    """Scanner updates a job's status and result counts."""
    row = db.execute("SELECT id, status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    updates: list[str] = []
    params: list = []

    if body.status:
        updates.append("status = ?");       params.append(body.status)
        if body.status == "running":
            updates.append("started_at = ?");   params.append(datetime.utcnow().isoformat() + "Z")
        elif body.status in ("completed", "failed"):
            updates.append("completed_at = ?"); params.append(datetime.utcnow().isoformat() + "Z")
    if body.files_scanned is not None:
        updates.append("files_scanned = ?"); params.append(body.files_scanned)
    if body.pii_found is not None:
        updates.append("pii_found = ?");     params.append(body.pii_found)
    if body.error is not None:
        updates.append("error = ?");         params.append(body.error)

    if updates:
        params.append(job_id)
        db.execute(f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()

    return {"job_id": job_id, "status": body.status or row["status"]}


@app.get("/api/scan-jobs")
def list_scan_jobs(machine_id: Optional[str] = None,
                   status: Optional[str] = None,
                   payload: dict = Depends(require_user),
                   db: sqlite3.Connection = Depends(get_db)):
    """Dashboard reads job history for a customer."""
    cust_filter = _customer_filter(payload)
    conditions = []
    params: list = []
    if cust_filter:
        conditions.append("customer_id = ?"); params.append(cust_filter)
    if machine_id:
        conditions.append("machine_id = ?");  params.append(machine_id)
    if status:
        conditions.append("status = ?");      params.append(status)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = db.execute(f"""
        SELECT id, machine_id, target_path, location_type, location_label,
               status, files_scanned, pii_found, error,
               created_at, started_at, completed_at
        FROM scan_jobs {where}
        ORDER BY created_at DESC LIMIT 100
    """, params).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "DataSentry API", "version": "2.0.0"}


if __name__ == "__main__":
    import uvicorn, sys
    port = int(os.environ.get("PORT", 8000))
    print(f"[DataSentry] Starting on port {port}", flush=True)
    print(f"[DataSentry] DB path: {DATABASE_PATH}", flush=True)
    print(f"[DataSentry] Python: {sys.version}", flush=True)
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
