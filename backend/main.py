"""
DataSentry Backend API  v3.0
FastAPI + PostgreSQL (psycopg2), with JWT user auth and customer portal.

Environment variables (Railway sets DATABASE_URL automatically when you add
the PostgreSQL plugin):
    DATABASE_URL             PostgreSQL DSN  (e.g. postgresql://user:pass@host/db)
    DATASENTRY_JWT_SECRET    Secret for signing JWTs  (auto-generated if unset)
    DATASENTRY_MASTER_KEY    Legacy master key for direct API-key management
    DATASENTRY_CORS_ORIGINS  Comma-separated CORS origins (default: *)
    DATASENTRY_ADMIN_PASSWORD  Force admin dashboard password
    PORT                     HTTP port (Railway sets this automatically)
"""

import os
import io
import json
import hashlib
import secrets
import zipfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool
import psycopg2.errorcodes

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

DATABASE_URL = os.environ.get("DATABASE_URL", "")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set. "
        "Add a PostgreSQL plugin to your Railway project — it sets DATABASE_URL automatically."
    )

MASTER_API_KEY  = os.environ.get("DATASENTRY_MASTER_KEY", "changeme-set-in-env")
ALLOWED_ORIGINS = os.environ.get("DATASENTRY_CORS_ORIGINS", "*").split(",")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_HRS  = 8

# JWT secret: env var (required in production) or auto-generated per-restart (dev only).
# On Railway, always set DATASENTRY_JWT_SECRET so tokens survive redeploys.
if os.environ.get("DATASENTRY_JWT_SECRET"):
    JWT_SECRET = os.environ["DATASENTRY_JWT_SECRET"]
else:
    _fallback_file = Path("/tmp/.datasentry_jwt_secret")
    if _fallback_file.exists():
        JWT_SECRET = _fallback_file.read_text().strip()
    else:
        JWT_SECRET = secrets.token_hex(32)
        try:
            _fallback_file.write_text(JWT_SECRET)
        except OSError:
            pass
    print("WARNING: DATASENTRY_JWT_SECRET not set. Tokens will be invalidated on restart.")

import hashlib as _hashlib
import hmac as _hmac

def _hash_password(plain: str) -> str:
    salt = secrets.token_hex(16)
    dk   = _hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260_000)
    return f"pbkdf2:sha256:260000:{salt}:{dk.hex()}"

def _verify_password(plain: str, stored: str) -> bool:
    try:
        _, algo, iters, salt, dk_hex = stored.split(":")
        dk = _hashlib.pbkdf2_hmac(algo, plain.encode(), salt.encode(), int(iters))
        return _hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# CONNECTION POOL
# ─────────────────────────────────────────────────────────────────────────────
# ThreadedConnectionPool is safe for multi-threaded ASGI workers.
# min=2 keeps warm connections; max=15 caps concurrency to protect the DB server.

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def _get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2,
            maxconn=15,
            dsn=DATABASE_URL,
        )
    return _pool


class _PgConn:
    """
    Thin wrapper that gives psycopg2 the same execute/fetchone/fetchall/commit
    interface as sqlite3.Connection, so route handlers need minimal changes.
    Uses DictCursor so rows support both row["col"] and row[0] access.
    """
    def __init__(self, raw: psycopg2.extensions.connection):
        self._raw = raw
        self._cur = raw.cursor(cursor_factory=psycopg2.extras.DictCursor)

    def execute(self, sql: str, params=()):
        self._cur.execute(sql, params)
        return self._cur

    def executemany(self, sql: str, params_list):
        """Uses execute_batch for dramatically better throughput on bulk inserts."""
        psycopg2.extras.execute_batch(self._cur, sql, params_list, page_size=500)
        return self._cur

    def commit(self):
        self._raw.commit()

    def rollback(self):
        self._raw.rollback()

    def close(self):
        try:
            self._cur.close()
        except Exception:
            pass
        _get_pool().putconn(self._raw)


def get_db():
    raw  = _get_pool().getconn()
    conn = _PgConn(raw)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA INIT
# ─────────────────────────────────────────────────────────────────────────────

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        id          SERIAL PRIMARY KEY,
        key_hash    TEXT UNIQUE NOT NULL,
        label       TEXT NOT NULL,
        customer_id TEXT DEFAULT '',
        created_at  TEXT NOT NULL,
        active      BOOLEAN DEFAULT TRUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        email         TEXT UNIQUE NOT NULL,
        name          TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        customer_id   TEXT,
        customer_name TEXT DEFAULT '',
        role          TEXT DEFAULT 'admin',
        created_at    TEXT DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        active        BOOLEAN DEFAULT TRUE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id               SERIAL PRIMARY KEY,
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
        total_size_bytes BIGINT,
        total_pii_files  INTEGER,
        location_count   INTEGER,
        scanned_at       TEXT NOT NULL,
        received_at      TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_locations (
        id               SERIAL PRIMARY KEY,
        scan_id          INTEGER NOT NULL REFERENCES scans(id),
        machine_id       TEXT NOT NULL,
        label            TEXT,
        location_type    TEXT,
        path             TEXT,
        total_files      INTEGER,
        total_size_bytes BIGINT,
        pii_file_count   INTEGER,
        pii_summary      TEXT,
        top_extensions   TEXT,
        top_pii_files    TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS file_inventory (
        id             SERIAL PRIMARY KEY,
        customer_id    TEXT NOT NULL,
        machine_id     TEXT NOT NULL,
        hostname       TEXT,
        file_path      TEXT NOT NULL,
        file_name      TEXT NOT NULL,
        file_ext       TEXT DEFAULT '',
        file_size      BIGINT DEFAULT 0,
        file_modified  TEXT,
        location_type  TEXT NOT NULL DEFAULT 'local',
        location_label TEXT,
        is_local       BOOLEAN DEFAULT TRUE,
        pii_status     TEXT DEFAULT 'pending',
        pii_findings   TEXT DEFAULT '{}',
        pii_count      INTEGER DEFAULT 0,
        pii_scanned_at TEXT,
        last_seen      TEXT DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        created_at     TEXT DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        UNIQUE(machine_id, file_path)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id             SERIAL PRIMARY KEY,
        customer_id    TEXT NOT NULL,
        machine_id     TEXT NOT NULL,
        target_path    TEXT NOT NULL,
        location_type  TEXT,
        location_label TEXT,
        status         TEXT DEFAULT 'pending',
        created_by     INTEGER REFERENCES users(id),
        created_at     TEXT DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        started_at     TEXT,
        completed_at   TEXT,
        files_scanned  INTEGER DEFAULT 0,
        pii_found      INTEGER DEFAULT 0,
        error          TEXT
    )
    """,
    # Indexes — covering the most common query patterns
    "CREATE INDEX IF NOT EXISTS idx_scans_machine   ON scans(machine_id)",
    "CREATE INDEX IF NOT EXISTS idx_scans_received  ON scans(received_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scans_customer  ON scans(customer_id)",
    "CREATE INDEX IF NOT EXISTS idx_locs_scan       ON scan_locations(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_locs_machine    ON scan_locations(machine_id)",
    "CREATE INDEX IF NOT EXISTS idx_inv_customer    ON file_inventory(customer_id)",
    "CREATE INDEX IF NOT EXISTS idx_inv_machine     ON file_inventory(machine_id)",
    "CREATE INDEX IF NOT EXISTS idx_inv_loc_type    ON file_inventory(location_type, is_local)",
    "CREATE INDEX IF NOT EXISTS idx_inv_pii         ON file_inventory(pii_status)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_pending    ON scan_jobs(machine_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_customer   ON scan_jobs(customer_id)",
]


def _utcnow_z() -> str:
    return datetime.utcnow().isoformat() + "Z"


def init_db():
    raw  = psycopg2.connect(DATABASE_URL)
    cur  = raw.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Apply schema — each statement in its own try so re-runs are idempotent
    for stmt in _DDL:
        cur.execute(stmt)
    raw.commit()

    # ── First-run: create default API key ─────────────────────────────────────
    cur.execute("SELECT COUNT(*) FROM api_keys")
    if cur.fetchone()[0] == 0:
        raw_key  = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        cur.execute(
            "INSERT INTO api_keys (key_hash, label, created_at) VALUES (%s, %s, %s)",
            (key_hash, "Default Scanner Key", _utcnow_z())
        )
        raw.commit()
        print(f"\n{'='*62}")
        print(f"  DataSentry — First Run Setup")
        print(f"  Scanner API key : {raw_key}")
        print(f"  (shown once — used by scanner agents to submit reports)")
        print(f"{'='*62}")

    # ── Admin user: create once, or keep password in sync with env var ────────
    env_password = os.environ.get("DATASENTRY_ADMIN_PASSWORD", "")
    cur.execute("SELECT COUNT(*) FROM users WHERE email='admin@datasentry.local'")
    if cur.fetchone()[0] == 0:
        admin_password = env_password or secrets.token_urlsafe(10)
        cur.execute(
            "INSERT INTO users (email, name, password_hash, customer_id, role) "
            "VALUES (%s, %s, %s, NULL, 'admin')",
            ("admin@datasentry.local", "Admin", _hash_password(admin_password))
        )
        raw.commit()
        print(f"\n  Dashboard login   : admin@datasentry.local")
        print(f"  Dashboard password: {admin_password}")
        print(f"  (set DATASENTRY_ADMIN_PASSWORD env var to lock this in)")
        print(f"{'='*62}\n")
    elif env_password:
        cur.execute(
            "UPDATE users SET password_hash=%s WHERE email='admin@datasentry.local'",
            (_hash_password(env_password),)
        )
        raw.commit()
        print("  Admin password synced from DATASENTRY_ADMIN_PASSWORD env var.")

    cur.close()
    raw.close()


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


def require_api_key(x_api_key: str = Header(...), db: _PgConn = Depends(get_db)):
    if x_api_key == MASTER_API_KEY and MASTER_API_KEY != "changeme-set-in-env":
        return {"customer_id": None, "customer_name": None}
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    row = db.execute(
        "SELECT id, customer_id FROM api_keys WHERE key_hash = %s AND active = TRUE",
        (key_hash,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    cust_id = row["customer_id"] or ""
    urow = db.execute(
        "SELECT customer_name FROM users WHERE customer_id = %s LIMIT 1", (cust_id,)
    ).fetchone()
    return {"customer_id": cust_id, "customer_name": urow["customer_name"] if urow else ""}


def _customer_filter(payload: Optional[dict]) -> Optional[str]:
    """Return customer_id to filter by, or None if global admin (sees all)."""
    if not payload:
        return None
    if payload.get("role") == "admin" and payload.get("customer_id") is None:
        return None
    return payload.get("customer_id")


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="DataSentry API", version="3.0.0")

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
def login(body: LoginRequest, db: _PgConn = Depends(get_db)):
    if not HAS_AUTH:
        raise HTTPException(status_code=503, detail="Auth libraries not installed")
    row = db.execute(
        "SELECT id, email, name, password_hash, customer_id, customer_name, role, active "
        "FROM users WHERE email = %s",
        (body.email,)
    ).fetchone()
    if not row or not row["active"]:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not _verify_password(body.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = make_token(row["id"], row["email"], row["customer_id"], row["role"])
    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   JWT_EXPIRE_HRS * 3600,
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
def me(payload: dict = Depends(require_user), db: _PgConn = Depends(get_db)):
    row = db.execute(
        "SELECT id, email, name, customer_id, customer_name, role FROM users WHERE id = %s",
        (int(payload["sub"]),)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


@app.post("/auth/users", status_code=201)
def create_user(body: CreateUserRequest, payload: dict = Depends(require_admin),
                db: _PgConn = Depends(get_db)):
    pw_hash = _hash_password(body.password)
    try:
        db.execute(
            "INSERT INTO users (email, name, password_hash, customer_id, customer_name, role) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (body.email, body.name, pw_hash, body.customer_id, body.customer_name or "", body.role)
        )
        db.commit()
    except psycopg2.IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already exists")

    scanner_key = None
    if body.customer_id:
        raw_key  = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        label    = f"{body.customer_name or body.customer_id} Scanner Key"
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (%s, %s, %s, %s)",
            (key_hash, label, body.customer_id, _utcnow_z())
        )
        db.commit()
        scanner_key = raw_key

    return {
        "email":           body.email,
        "customer_id":     body.customer_id,
        "role":            body.role,
        "scanner_api_key": scanner_key,
        "note": "scanner_api_key is shown once — store it securely" if scanner_key else None,
    }


@app.get("/auth/users")
def list_users(payload: dict = Depends(require_admin), db: _PgConn = Depends(get_db)):
    rows = db.execute(
        "SELECT id, email, name, customer_id, customer_name, role, created_at, active FROM users"
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/auth/change-password")
def change_password(body: ChangePasswordRequest, payload: dict = Depends(require_user),
                    db: _PgConn = Depends(get_db)):
    row = db.execute(
        "SELECT password_hash FROM users WHERE id = %s", (int(payload["sub"]),)
    ).fetchone()
    if not row or not _verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password incorrect")
    db.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (_hash_password(body.new_password), int(payload["sub"]))
    )
    db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# SCANNER SUBMISSION  (X-API-Key auth)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/scans", status_code=201)
async def receive_scan(request: Request,
                       key_info: dict = Depends(require_api_key),
                       db: _PgConn = Depends(get_db)):
    try:
        report = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    machine       = report.get("machine", {})
    customer      = report.get("customer", {})
    summary       = report.get("summary", {})
    locations     = report.get("locations", [])
    machine_id    = machine.get("machine_id") or machine.get("hostname", "unknown")
    customer_id   = key_info.get("customer_id") or customer.get("id", "")
    customer_name = key_info.get("customer_name") or customer.get("name", "")
    scanned_at    = report.get("scan_started_at", _utcnow_z())
    received_at   = _utcnow_z()

    scan_id = db.execute("""
        INSERT INTO scans
            (machine_id, hostname, username, os, os_version, architecture,
             customer_id, customer_name, scan_json,
             total_files, total_size_bytes, total_pii_files,
             location_count, scanned_at, received_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
    """, (
        machine_id, machine.get("hostname"), machine.get("username"),
        machine.get("os"), machine.get("os_version"), machine.get("architecture"),
        customer_id, customer_name, json.dumps(report),
        summary.get("total_files", 0), summary.get("total_size_bytes", 0),
        summary.get("total_pii_files", 0), len(locations),
        scanned_at, received_at,
    )).fetchone()[0]

    for loc in locations:
        db.execute("""
            INSERT INTO scan_locations
                (scan_id, machine_id, label, location_type, path,
                 total_files, total_size_bytes, pii_file_count,
                 pii_summary, top_extensions, top_pii_files)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
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
def list_customers(payload: dict = Depends(require_user), db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    where  = "WHERE s.customer_id = %s" if cust_filter else ""
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
                           db: _PgConn = Depends(get_db)):
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
        WHERE s.customer_id = %s
        ORDER BY s.total_pii_files DESC
    """, (customer_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/machines")
def list_machines(customer_id: Optional[str] = None, payload: dict = Depends(require_user),
                  db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    effective   = cust_filter or customer_id
    where  = "WHERE s.customer_id = %s" if effective else ""
    params = (effective,) if effective else ()
    rows = db.execute(f"""
        SELECT s.machine_id, s.hostname, s.username, s.os,
               s.customer_id, s.customer_name,
               s.total_files, s.total_size_bytes, s.total_pii_files,
               s.location_count, s.scanned_at,
               COUNT(*) OVER (PARTITION BY s.machine_id) AS scan_count
        FROM scans s
        INNER JOIN (
            SELECT machine_id, MAX(received_at) AS latest FROM scans GROUP BY machine_id
        ) latest ON s.machine_id = latest.machine_id AND s.received_at = latest.latest
        {where}
        ORDER BY s.received_at DESC
    """, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/machines/{machine_id}")
def get_machine(machine_id: str, payload: dict = Depends(require_user),
                db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    row = db.execute("""
        SELECT scan_json, customer_id FROM scans
        WHERE machine_id = %s
        ORDER BY received_at DESC LIMIT 1
    """, (machine_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Machine not found")
    if cust_filter and row["customer_id"] != cust_filter:
        raise HTTPException(status_code=403, detail="Access denied")
    return json.loads(row["scan_json"])


@app.get("/api/machines/{machine_id}/history")
def get_machine_history(machine_id: str, payload: dict = Depends(require_user),
                        db: _PgConn = Depends(get_db)):
    rows = db.execute("""
        SELECT id, total_files, total_size_bytes, total_pii_files,
               location_count, scanned_at, received_at
        FROM scans WHERE machine_id = %s
        ORDER BY received_at DESC LIMIT 20
    """, (machine_id,)).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/summary")
def global_summary(customer_id: Optional[str] = None, payload: dict = Depends(require_user),
                   db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    effective   = cust_filter or customer_id
    where  = "WHERE s.customer_id = %s" if effective else ""
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
        ) sub
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
                 db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    where  = "WHERE s.customer_id = %s" if cust_filter else ""
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
        ORDER BY s.total_pii_files DESC LIMIT %s
    """, params).fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMER MANAGEMENT  (admin only)
# ─────────────────────────────────────────────────────────────────────────────

class NewCustomerRequest(BaseModel):
    customer_id:    str
    customer_name:  str
    admin_email:    str
    admin_name:     str
    admin_password: str


@app.post("/api/customers/create", status_code=201)
def create_customer(body: NewCustomerRequest, payload: dict = Depends(require_admin),
                    db: _PgConn = Depends(get_db)):
    """Admin creates a new customer — portal user + scanner API key in one step."""
    pw_hash = _hash_password(body.admin_password)
    try:
        db.execute(
            "INSERT INTO users (email, name, password_hash, customer_id, customer_name, role) "
            "VALUES (%s, %s, %s, %s, %s, 'admin')",
            (body.admin_email, body.admin_name, pw_hash, body.customer_id, body.customer_name)
        )
    except psycopg2.IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already in use")

    raw_key  = "dsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (%s, %s, %s, %s)",
        (key_hash, f"{body.customer_name} Scanner Key", body.customer_id, _utcnow_z())
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
    import urllib.request
    from datetime import timezone

    now = datetime.now(timezone.utc)
    cached     = _EXE_CACHE.get("bytes")
    fetched_at = _EXE_CACHE.get("fetched_at")

    if cached and fetched_at:
        age_hours = (now - fetched_at).total_seconds() / 3600
        if age_hours < _EXE_CACHE_TTL_HOURS:
            return cached

    try:
        print("[DataSentry] Fetching base EXE from GitHub Releases...", flush=True)
        req = urllib.request.Request(_BASE_EXE_URL, headers={"User-Agent": "DataSentry-Backend/3.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        _EXE_CACHE["bytes"]      = data
        _EXE_CACHE["fetched_at"] = now
        print(f"[DataSentry] EXE fetched: {len(data):,} bytes", flush=True)
        return data
    except Exception as e:
        print(f"[DataSentry] WARNING: Could not fetch base EXE: {e}", flush=True)
        return None


@app.get("/api/download/config")
def download_config(request: Request, payload: dict = Depends(require_user),
                    db: _PgConn = Depends(get_db)):
    cust_id   = payload.get("customer_id") or ""
    cust_name = ""
    api_key   = ""

    if cust_id:
        user_row = db.execute(
            "SELECT customer_name FROM users WHERE customer_id = %s LIMIT 1", (cust_id,)
        ).fetchone()
        cust_name = user_row["customer_name"] if user_row else cust_id

        raw_key  = "dsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (%s, %s, %s, %s)",
            (key_hash, f"{cust_name} Download Key", cust_id, _utcnow_z())
        )
        db.commit()
        api_key = raw_key

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
                       db: _PgConn = Depends(get_db)):
    cust_id   = payload.get("customer_id") or ""
    cust_name = ""
    api_key   = ""

    if cust_id:
        user_row = db.execute(
            "SELECT customer_name FROM users WHERE customer_id = %s LIMIT 1", (cust_id,)
        ).fetchone()
        cust_name = user_row["customer_name"] if user_row else cust_id
        raw_key   = "dsk_" + secrets.token_urlsafe(32)
        key_hash  = hashlib.sha256(raw_key.encode()).hexdigest()
        db.execute(
            "INSERT INTO api_keys (key_hash, label, customer_id, created_at) VALUES (%s, %s, %s, %s)",
            (key_hash, f"{cust_name} Installer Key", cust_id, _utcnow_z())
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
    slug     = (cust_id or "datasentry").replace(" ", "-").lower()
    exe_bytes = _fetch_base_exe()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if exe_bytes:
            zf.writestr("DataSentry.exe", exe_bytes)
        zf.writestr("datasentry.cfg", cfg)
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
                   db: _PgConn = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    raw_key  = "dsk_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_keys (key_hash, label, created_at) VALUES (%s, %s, %s)",
        (key_hash, body.label, _utcnow_z())
    )
    db.commit()
    return {"key": raw_key, "label": body.label,
            "note": "Store this key securely — it will not be shown again"}


@app.get("/api/keys")
def list_keys(x_master_key: str = Header(...), db: _PgConn = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    rows = db.execute(
        "SELECT id, label, customer_id, created_at, active FROM api_keys"
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/keys/{key_id}")
def revoke_key(key_id: int, x_master_key: str = Header(...),
               db: _PgConn = Depends(get_db)):
    if x_master_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Master key required")
    db.execute("UPDATE api_keys SET active = FALSE WHERE id = %s", (key_id,))
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
    pii_status:     str = "pending"
    pii_findings:   dict = {}
    pii_count:      int = 0
    pii_scanned_at: Optional[str] = None


class InventoryBatch(BaseModel):
    machine_id: str
    hostname:   Optional[str] = None
    records:    list[InventoryRecord]


@app.post("/api/inventory", status_code=200)
async def receive_inventory(body: InventoryBatch,
                            key_info: dict = Depends(require_api_key),
                            db: _PgConn = Depends(get_db)):
    """
    Scanner posts a batch of file inventory records (max 2000 per call).
    Uses INSERT … ON CONFLICT DO UPDATE so re-scans refresh existing rows.
    execute_batch sends records in 500-row pages for high throughput.
    """
    if len(body.records) > 2000:
        raise HTTPException(status_code=400, detail="Max 2000 records per batch")

    customer_id = key_info.get("customer_id") or ""
    now = _utcnow_z()

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
            r.is_local,
            r.pii_status,
            json.dumps(r.pii_findings),
            r.pii_count,
            r.pii_scanned_at,
            now,
        )
        for r in body.records
    ]

    db.executemany("""
        INSERT INTO file_inventory
            (customer_id, machine_id, hostname, file_path, file_name, file_ext,
             file_size, file_modified, location_type, location_label, is_local,
             pii_status, pii_findings, pii_count, pii_scanned_at, last_seen)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(machine_id, file_path) DO UPDATE SET
            file_size      = EXCLUDED.file_size,
            file_modified  = EXCLUDED.file_modified,
            location_type  = EXCLUDED.location_type,
            location_label = EXCLUDED.location_label,
            is_local       = EXCLUDED.is_local,
            pii_status     = CASE WHEN EXCLUDED.pii_status != 'pending'
                                  THEN EXCLUDED.pii_status
                                  ELSE file_inventory.pii_status END,
            pii_findings   = CASE WHEN EXCLUDED.pii_status != 'pending'
                                  THEN EXCLUDED.pii_findings
                                  ELSE file_inventory.pii_findings END,
            pii_count      = CASE WHEN EXCLUDED.pii_status != 'pending'
                                  THEN EXCLUDED.pii_count
                                  ELSE file_inventory.pii_count END,
            pii_scanned_at = CASE WHEN EXCLUDED.pii_scanned_at IS NOT NULL
                                  THEN EXCLUDED.pii_scanned_at
                                  ELSE file_inventory.pii_scanned_at END,
            last_seen      = EXCLUDED.last_seen
    """, rows)
    db.commit()
    return {"accepted": len(rows)}


@app.get("/api/inventory/summary")
def inventory_summary(payload: dict = Depends(require_user),
                      db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    where  = "WHERE customer_id = %s" if cust_filter else ""
    params = (cust_filter,) if cust_filter else ()

    machines = db.execute(f"""
        SELECT machine_id, hostname,
               COUNT(*)                                           AS total_files,
               SUM(file_size)                                     AS total_bytes,
               SUM(CASE WHEN is_local = FALSE THEN 1 ELSE 0 END) AS cloud_files,
               SUM(CASE WHEN is_local = TRUE  THEN 1 ELSE 0 END) AS local_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files,
               SUM(CASE WHEN pii_status = 'pending'  THEN 1 ELSE 0 END) AS unscanned_files,
               MAX(last_seen)                                     AS last_seen
        FROM file_inventory
        {where}
        GROUP BY machine_id, hostname
        ORDER BY total_files DESC
    """, params).fetchall()

    loc_types = db.execute(f"""
        SELECT location_type,
               COUNT(*)                                           AS total_files,
               SUM(file_size)                                     AS total_bytes,
               SUM(CASE WHEN is_local = FALSE THEN 1 ELSE 0 END) AS cloud_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files
        FROM file_inventory
        {where}
        GROUP BY location_type
        ORDER BY total_files DESC
    """, params).fetchall()

    machine_locs = db.execute(f"""
        SELECT machine_id, hostname, location_type, location_label,
               COUNT(*)                                                AS total_files,
               SUM(file_size)                                          AS total_bytes,
               SUM(CASE WHEN is_local = FALSE THEN 1 ELSE 0 END)      AS cloud_files,
               SUM(CASE WHEN is_local = TRUE  THEN 1 ELSE 0 END)      AS local_files,
               SUM(CASE WHEN pii_status = 'findings' THEN 1 ELSE 0 END) AS pii_files,
               SUM(CASE WHEN pii_status = 'pending' AND is_local = FALSE
                        THEN 1 ELSE 0 END)                             AS pending_cloud,
               SUM(pii_count)                                          AS total_pii_hits,
               MIN(last_seen)                                          AS last_seen
        FROM file_inventory
        {where}
        GROUP BY machine_id, hostname, location_type, location_label
        ORDER BY machine_id, total_files DESC
    """, params).fetchall()

    return {
        "machines":          [dict(r) for r in machines],
        "location_types":    [dict(r) for r in loc_types],
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
                   db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    conditions: list[str] = []
    params: list = []
    if cust_filter:
        conditions.append("customer_id = %s"); params.append(cust_filter)
    if machine_id:
        conditions.append("machine_id = %s");   params.append(machine_id)
    if location_type:
        conditions.append("location_type = %s"); params.append(location_type)
    if pii_status:
        conditions.append("pii_status = %s");    params.append(pii_status)
    if is_local is not None:
        conditions.append("is_local = %s");      params.append(bool(is_local))

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    limit = min(limit, 1000)
    count_params = list(params)
    params += [limit, offset]

    rows = db.execute(f"""
        SELECT id, machine_id, hostname, file_path, file_name, file_ext,
               file_size, file_modified, location_type, location_label,
               is_local, pii_status, pii_findings, pii_count,
               pii_scanned_at, last_seen
        FROM file_inventory {where}
        ORDER BY pii_count DESC, file_size DESC
        LIMIT %s OFFSET %s
    """, params).fetchall()

    total = db.execute(
        f"SELECT COUNT(*) FROM file_inventory {where}", count_params
    ).fetchone()[0]

    return {"total": total, "offset": offset, "limit": limit, "items": [dict(r) for r in rows]}


# ─────────────────────────────────────────────────────────────────────────────
# SCAN JOBS  (dashboard creates; scanner polls and executes)
# ─────────────────────────────────────────────────────────────────────────────

class CreateScanJobRequest(BaseModel):
    machine_id:     str
    target_path:    str
    location_type:  Optional[str] = None
    location_label: Optional[str] = None


class UpdateScanJobRequest(BaseModel):
    status:        Optional[str] = None
    files_scanned: Optional[int] = None
    pii_found:     Optional[int] = None
    error:         Optional[str] = None


@app.post("/api/scan-jobs", status_code=201)
def create_scan_job(body: CreateScanJobRequest,
                    payload: dict = Depends(require_user),
                    db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)

    owner = db.execute(
        "SELECT customer_id FROM file_inventory WHERE machine_id = %s LIMIT 1",
        (body.machine_id,)
    ).fetchone()
    if owner and cust_filter and owner["customer_id"] != cust_filter:
        raise HTTPException(status_code=403, detail="Access denied")

    existing = db.execute("""
        SELECT id FROM scan_jobs
        WHERE machine_id = %s AND target_path = %s AND status = 'pending'
    """, (body.machine_id, body.target_path)).fetchone()
    if existing:
        return {"job_id": existing["id"], "status": "pending", "note": "job already queued"}

    customer_id = cust_filter or (owner["customer_id"] if owner else "")
    job_id = db.execute("""
        INSERT INTO scan_jobs
            (customer_id, machine_id, target_path, location_type, location_label, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (customer_id, body.machine_id, body.target_path,
          body.location_type, body.location_label, int(payload["sub"]))).fetchone()[0]
    db.commit()
    return {"job_id": job_id, "status": "pending"}


@app.get("/api/scan-jobs/pending")
def get_pending_jobs(machine_id: str,
                     key_info: dict = Depends(require_api_key),
                     db: _PgConn = Depends(get_db)):
    customer_id = key_info.get("customer_id") or ""
    where_cust  = "AND customer_id = %s" if customer_id else ""
    params      = [machine_id] + ([customer_id] if customer_id else [])
    rows = db.execute(f"""
        SELECT id, target_path, location_type, location_label, created_at
        FROM scan_jobs
        WHERE machine_id = %s AND status = 'pending' {where_cust}
        ORDER BY created_at
        LIMIT 5
    """, params).fetchall()
    return [dict(r) for r in rows]


@app.patch("/api/scan-jobs/{job_id}")
def update_scan_job(job_id: int, body: UpdateScanJobRequest,
                    key_info: dict = Depends(require_api_key),
                    db: _PgConn = Depends(get_db)):
    row = db.execute(
        "SELECT id, status FROM scan_jobs WHERE id = %s", (job_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    updates: list[str] = []
    params: list = []

    if body.status:
        updates.append("status = %s");       params.append(body.status)
        if body.status == "running":
            updates.append("started_at = %s");   params.append(_utcnow_z())
        elif body.status in ("completed", "failed"):
            updates.append("completed_at = %s"); params.append(_utcnow_z())
    if body.files_scanned is not None:
        updates.append("files_scanned = %s"); params.append(body.files_scanned)
    if body.pii_found is not None:
        updates.append("pii_found = %s");     params.append(body.pii_found)
    if body.error is not None:
        updates.append("error = %s");         params.append(body.error)

    if updates:
        params.append(job_id)
        db.execute(f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = %s", params)
        db.commit()

    return {"job_id": job_id, "status": body.status or row["status"]}


@app.get("/api/scan-jobs")
def list_scan_jobs(machine_id: Optional[str] = None,
                   status: Optional[str] = None,
                   payload: dict = Depends(require_user),
                   db: _PgConn = Depends(get_db)):
    cust_filter = _customer_filter(payload)
    conditions: list[str] = []
    params: list = []
    if cust_filter:
        conditions.append("customer_id = %s"); params.append(cust_filter)
    if machine_id:
        conditions.append("machine_id = %s");  params.append(machine_id)
    if status:
        conditions.append("status = %s");      params.append(status)

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
def health(db: _PgConn = Depends(get_db)):
    """Health check — also verifies the database connection is live."""
    db.execute("SELECT 1")
    return {"status": "ok", "service": "DataSentry API", "version": "3.0.0", "db": "postgresql"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"[DataSentry] Starting on port {port}", flush=True)
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
