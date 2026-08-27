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

    # ── First-run: create admin user ───────────────────────────────────────────
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        admin_password = secrets.token_urlsafe(10)
        admin_hash     = _hash_password(admin_password)
        conn.execute(
            "INSERT INTO users (email, name, password_hash, customer_id, role) VALUES (?,?,?,NULL,'admin')",
            ("admin@datasentry.local", "Admin", admin_hash)
        )
        conn.commit()
        print(f"\n  Dashboard login   : admin@datasentry.local")
        print(f"  Dashboard password: {admin_password}")
        print(f"  (change this via POST /auth/change-password after first login)")
        print(f"{'='*62}\n")

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

    exe_url   = f"{api_url}/static/DataSentry.exe"
    slug      = (cust_id or "datasentry").replace(" ", "-").lower()

    bat = f"""@echo off
REM DataSentry Agent Installer
REM Customer: {cust_name or 'N/A'}
REM Generated: {datetime.utcnow().strftime('%Y-%m-%d')}

setlocal
set INSTALL_DIR=%ProgramFiles%\\DataSentry
set EXE=%INSTALL_DIR%\\DataSentry.exe
set CFG=%INSTALL_DIR%\\datasentry.cfg

echo Installing DataSentry agent for {cust_name or 'your organisation'}...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Download the agent executable
echo Downloading DataSentry.exe...
powershell -Command "Invoke-WebRequest -Uri '{exe_url}' -OutFile '%EXE%'"
if not exist "%EXE%" (
    echo ERROR: Download failed. Check your internet connection.
    pause & exit /b 1
)

REM Write the pre-configured config file
echo Writing configuration...
(
echo [datasentry]
echo api_url       = {api_url}
echo api_key       = {api_key}
echo customer_id   = {cust_id}
echo customer_name = {cust_name}
) > "%CFG%"

REM Create a scheduled task to run the scan weekly
echo Scheduling weekly scan...
schtasks /create /tn "DataSentry Weekly Scan" ^
    /tr "\"%EXE%\" --cli" ^
    /sc WEEKLY /d MON /st 07:00 ^
    /ru SYSTEM /f >nul 2>&1

REM Run first scan immediately
echo Running initial scan (this may take a few minutes)...
"%EXE%" --cli

echo.
echo DataSentry installed successfully!
echo Weekly scans are scheduled every Monday at 07:00.
pause
"""

    # Build ZIP in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("install-datasentry.bat", bat)
        zf.writestr("datasentry.cfg",         cfg)
        zf.writestr("README.txt", f"""DataSentry Agent Installer
Customer: {cust_name or 'N/A'}
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

HOW TO DEPLOY
=============
1. Place install-datasentry.bat and datasentry.cfg in the same folder.
2. Run install-datasentry.bat as Administrator on each endpoint.
   - Or deploy via Group Policy / Intune / SCCM using the BAT as a startup script.
3. The agent installs itself to Program Files and schedules a weekly scan.

The config file is pre-configured for your organisation — no manual
entry needed on each machine.
""")
    buf.seek(0)

    filename = f"datasentry-installer-{slug}.zip"
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
