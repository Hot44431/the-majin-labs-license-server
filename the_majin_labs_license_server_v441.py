"""
The Majin Labs License Server - v4.4.1 PRODUCTION

Features:
- Lifetime licenses
- 7-day trial licenses
- 30-day licenses
- 1-year licenses
- Custom-duration licenses
- Existing 5-minute test license
- Machine binding
- Admin create / revoke / reset
- Server-authoritative status checks
- SQLite by default; DATABASE_PATH can point at persistent storage
- Optional PostgreSQL support through DATABASE_URL

IMPORTANT FOR RENDER:
For real production persistence, use a Render Persistent Disk for SQLite
or set DATABASE_URL to a persistent PostgreSQL database. A normal Render
instance filesystem is not a permanent database store across deployments.

ADMIN API:
Set ADMIN_TOKEN in Render Environment Variables. Never put the token in
this source file or the Blender addon.
"""

import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict, deque
from threading import Lock
import re

from flask import Flask, request, jsonify

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB JSON requests

# ---------------------------------------------------------------------------
# Basic abuse protection
# ---------------------------------------------------------------------------
# This is intentionally dependency-free so it works on Render without adding
# another package. For multi-instance deployments, put a real rate limiter /
# WAF in front of the service as well.
_RATE_LIMIT_LOCK = Lock()
_RATE_BUCKETS = defaultdict(deque)

RATE_WINDOW_SECONDS = 60
ACTIVATE_LIMIT = 20
STATUS_LIMIT = 60
ADMIN_LIMIT = 30

def _client_ip():
    # Render/proxies should normally provide the connecting IP in X-Forwarded-For.
    # Take the first value because it is the original client in the usual proxy setup.
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "unknown")[:64]

def _rate_limit(bucket_name, limit):
    now = _utc_now().timestamp()
    cutoff = now - RATE_WINDOW_SECONDS
    key = f"{bucket_name}:{_client_ip()}"
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_BUCKETS[key]
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True

def _safe_license_key(key):
    return bool(re.fullmatch(r"[A-Z0-9]{2,16}-[A-Z0-9]{6,32}", key))

@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


PRODUCT_ID = "the_majin_labs_life_size_tool"
CURRENT_VERSION = "4.4.1"

TEST_KEY = "MJL-TEST-5MIN-8427"
TEST_DURATION_SECONDS = 5 * 60

TRIAL_DURATION_SECONDS = 7 * 24 * 60 * 60
THIRTY_DAY_SECONDS = 30 * 24 * 60 * 60
ONE_YEAR_SECONDS = 365 * 24 * 60 * 60

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATABASE_PATH = os.environ.get("DATABASE_PATH", "licenses.db").strip()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()


def _utc_now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat()


def _is_postgres():
    return bool(DATABASE_URL) and DATABASE_URL.startswith(("postgres://", "postgresql://")) and psycopg is not None


def _db():
    if _is_postgres():
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)

    parent = os.path.dirname(os.path.abspath(DATABASE_PATH))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db():
    conn = _db()
    if _is_postgres():
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                license_name TEXT NOT NULL,
                license_type TEXT NOT NULL DEFAULT 'custom',
                duration_seconds BIGINT,
                machine_id TEXT,
                activated_at TEXT,
                expires_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                notes TEXT DEFAULT ''
            )
        """)
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                license_key TEXT PRIMARY KEY,
                product_id TEXT NOT NULL,
                license_name TEXT NOT NULL,
                license_type TEXT NOT NULL DEFAULT 'custom',
                duration_seconds INTEGER,
                machine_id TEXT,
                activated_at TEXT,
                expires_at TEXT,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                notes TEXT DEFAULT ''
            )
        """)

        # Migrate the original v4.4.1 database if it already exists.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(licenses)").fetchall()}
        migrations = [
            ("license_type", "ALTER TABLE licenses ADD COLUMN license_type TEXT NOT NULL DEFAULT 'custom'"),
            ("duration_seconds", "ALTER TABLE licenses ADD COLUMN duration_seconds INTEGER"),
            ("created_at", "ALTER TABLE licenses ADD COLUMN created_at TEXT"),
            ("notes", "ALTER TABLE licenses ADD COLUMN notes TEXT DEFAULT ''"),
        ]
        for column, sql in migrations:
            if column not in existing:
                conn.execute(sql)

    now = _iso(_utc_now())
    if _is_postgres():
        conn.execute("""
            INSERT INTO licenses
            (license_key, product_id, license_name, license_type, duration_seconds, created_at, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (license_key) DO NOTHING
        """, (TEST_KEY, PRODUCT_ID, "5 Minute Test License 8427", "5m", TEST_DURATION_SECONDS, now, "Built-in test key"))
    else:
        conn.execute("""
            INSERT OR IGNORE INTO licenses
            (license_key, product_id, license_name, license_type, duration_seconds, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (TEST_KEY, PRODUCT_ID, "5 Minute Test License 8427", "5m", TEST_DURATION_SECONDS, now, "Built-in test key"))

        # Upgrade the original test key record if it came from the old server.
        conn.execute("""
            UPDATE licenses
            SET license_type = '5m', duration_seconds = ?,
                created_at = COALESCE(created_at, ?)
            WHERE license_key = ?
        """, (TEST_DURATION_SECONDS, now, TEST_KEY))

    conn.commit()
    conn.close()


def _row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def _get_license(key):
    conn = _db()
    if _is_postgres():
        row = conn.execute("SELECT * FROM licenses WHERE license_key = %s", (key,)).fetchone()
    else:
        row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (key,)).fetchone()
    conn.close()
    return _row_to_dict(row)


def _update_license(key, **fields):
    allowed = {
        "machine_id", "activated_at", "expires_at", "revoked",
        "license_name", "license_type", "duration_seconds", "notes"
    }
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return

    assignments = ", ".join(f"{k} = {'%s' if _is_postgres() else '?'}" for k in fields)
    values = list(fields.values()) + [key]
    conn = _db()
    if _is_postgres():
        conn.execute(f"UPDATE licenses SET {assignments} WHERE license_key = %s", values)
    else:
        conn.execute(f"UPDATE licenses SET {assignments} WHERE license_key = ?", values)
    conn.commit()
    conn.close()


def _require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _rate_limit("admin", ADMIN_LIMIT):
            return jsonify(ok=False, message="Too many admin requests. Please try again later."), 429
        if not ADMIN_TOKEN:
            return jsonify(ok=False, message="Admin API is not configured."), 503
        supplied = request.headers.get("X-Admin-Token", "")
        if not secrets.compare_digest(supplied, ADMIN_TOKEN):
            return jsonify(ok=False, message="Unauthorized."), 401
        return fn(*args, **kwargs)
    return wrapper


def _duration_from_request(data):
    license_type = str(data.get("license_type", data.get("duration", "custom"))).strip().lower()
    aliases = {
        "5": "5m", "5m": "5m", "5min": "5m", "5mins": "5m", "5minute": "5m", "5minutes": "5m",
        "7": "7d", "7d": "7d", "trial": "7d", "trial7d": "7d", "7day": "7d", "7days": "7d",
        "30": "30d", "30d": "30d", "month": "30d", "monthly": "30d",
        "365": "365d", "365d": "365d", "year": "365d", "yearly": "365d", "1y": "365d",
        "lifetime": "lifetime", "permanent": "lifetime",
    }
    license_type = aliases.get(license_type, license_type)

    if license_type == "lifetime":
        return "lifetime", None, "Lifetime License"
    if license_type == "5m":
        return "5m", TEST_DURATION_SECONDS, "5 Minute Test License"
    if license_type == "7d":
        return "7d", TRIAL_DURATION_SECONDS, "7 Day Trial License"
    if license_type == "30d":
        return "30d", THIRTY_DAY_SECONDS, "30 Day License"
    if license_type == "365d":
        return "365d", ONE_YEAR_SECONDS, "1 Year License"

    custom_days = data.get("custom_days", data.get("days"))
    if custom_days is None:
        custom_seconds = data.get("custom_seconds", data.get("duration_seconds"))
        if custom_seconds is None:
            raise ValueError("Use lifetime, 5m, 7d, 30d, 365d, or provide custom_days/custom_seconds.")
        seconds = int(custom_seconds)
    else:
        seconds = int(float(custom_days) * 86400)

    if seconds <= 0:
        raise ValueError("Custom duration must be greater than zero.")
    return "custom", seconds, f"Custom {seconds / 86400:g} Day License"


def _generate_key(prefix="MJL"):
    return f"{prefix}-{secrets.token_hex(16).upper()}"


_init_db()


@app.get("/")
def health():
    return jsonify(ok=True, service="The Majin Labs License Server")


@app.post("/api/activate")
def activate():
    if not _rate_limit("activate", ACTIVATE_LIMIT):
        return jsonify(ok=False, message="Too many activation attempts. Please try again later."), 429
    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    key = str(data.get("license_key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()

    if product_id != PRODUCT_ID:
        return jsonify(ok=False, message="Invalid product."), 400
    if not key or not machine_id:
        return jsonify(ok=False, message="License key and machine ID are required."), 400

    record = _get_license(key)
    if record is None:
        return jsonify(ok=False, message="Invalid license key."), 403
    if int(record.get("revoked", 0)):
        return jsonify(ok=False, message="License revoked."), 403

    now = _utc_now()
    expires_at = record.get("expires_at")
    if expires_at:
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if now >= expires:
            return jsonify(ok=False, message="License expired."), 403

    # First activation binds the key to this machine and starts its timer.
    if not record.get("machine_id"):
        duration = record.get("duration_seconds")
        activated_at = _iso(now)
        new_expires = None if duration is None else _iso(now + timedelta(seconds=int(duration)))
        _update_license(key, machine_id=machine_id, activated_at=activated_at, expires_at=new_expires)
        return jsonify(
            ok=True,
            message="License activated.",
            license_name=record["license_name"],
            license_type=record.get("license_type", "custom"),
            activated_at=activated_at,
            expires_at=new_expires,
        )

    if record["machine_id"] == machine_id:
        return jsonify(
            ok=True,
            message="License is active.",
            license_name=record["license_name"],
            license_type=record.get("license_type", "custom"),
            activated_at=record.get("activated_at"),
            expires_at=record.get("expires_at"),
        )

    return jsonify(ok=False, message="This license key has already been activated on another computer."), 403


@app.post("/api/status")
def status():
    if not _rate_limit("status", STATUS_LIMIT):
        return jsonify(ok=False, message="Too many status requests. Please try again later."), 429
    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    key = str(data.get("license_key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()

    if product_id != PRODUCT_ID or not key or not machine_id:
        return jsonify(ok=False, message="Invalid status request."), 400

    record = _get_license(key)
    if record is None:
        return jsonify(ok=False, message="Invalid license key."), 403
    if int(record.get("revoked", 0)):
        return jsonify(ok=False, message="License revoked."), 403
    if record.get("machine_id") != machine_id:
        return jsonify(ok=False, message="License is bound to another computer."), 403

    expires_at = record.get("expires_at")
    if expires_at:
        expires = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if _utc_now() >= expires:
            return jsonify(ok=False, message="License expired."), 403

    remaining = None
    if expires_at:
        remaining = max(0, int((expires - _utc_now()).total_seconds()))

    return jsonify(
        ok=True,
        license_name=record["license_name"],
        license_type=record.get("license_type", "custom"),
        activated_at=record.get("activated_at"),
        expires_at=expires_at,
        remaining_seconds=remaining,
        server_time=_iso(_utc_now()),
    )



@app.get("/admin")
def admin_page():
    return """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>The Majin Labs — License Admin</title>
<style>
body{margin:0;background:#101014;color:#eee;font-family:Arial,sans-serif}
.wrap{max-width:1100px;margin:30px auto;padding:0 20px}
h1{margin-bottom:6px}.sub{color:#aaa;margin-bottom:25px}
.card{background:#19191f;border:1px solid #333;border-radius:12px;padding:20px;margin-bottom:18px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
button{background:#6d35d9;color:#fff;border:0;border-radius:7px;padding:11px 15px;cursor:pointer;font-weight:700}
button:hover{filter:brightness(1.15)}
input,select{width:100%;box-sizing:border-box;background:#101014;color:#fff;border:1px solid #444;border-radius:6px;padding:10px;margin-top:6px}
label{display:block;color:#bbb;font-size:13px;margin-top:12px}
.key{font-family:monospace;font-size:20px;color:#9f7cff;word-break:break-all}
.result{margin-top:15px;padding:15px;border-radius:8px;background:#0d2115;border:1px solid #285d37}
.error{background:#2a1111;border-color:#6b2b2b}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:9px;border-bottom:1px solid #333;text-align:left;vertical-align:top}
.actions button{margin:2px;padding:7px 9px;font-size:12px}
.small{color:#888;font-size:12px}
@media(max-width:800px){.grid{grid-template-columns:1fr 1fr}table{font-size:11px}}
</style>
</head>
<body>
<div class="wrap">
<h1>🔐 The Majin Labs — License Admin</h1>
<div class="sub">Create, view, reset and revoke licenses. Admin token is never stored by this page.</div>

<div class="card">
<label>Admin Token
<input id="token" type="password" placeholder="Enter your Render ADMIN_TOKEN">
</label>
</div>

<div class="card">
<h2>Generate License</h2>
<div class="grid">
<div><label>License Type<select id="type">
<option value="7d">7 Day Free Trial</option>
<option value="30d">30 Days</option>
<option value="365d">1 Year</option>
<option value="lifetime">Lifetime</option>
<option value="5m">5 Minute Test</option>
<option value="custom">Custom</option>
</select></label></div>
<div><label>License Name<input id="name" placeholder="Optional"></label></div>
<div><label>Custom Days<input id="days" type="number" min="0.001" step="0.001" placeholder="Only for Custom"></label></div>
<div><label>Notes<input id="notes" placeholder="Optional note"></label></div>
</div>
<br>
<button id="generate-btn">GENERATE KEY</button>
<button id="refresh-btn" style="margin-left:8px">REFRESH LICENSES</button>
<div id="result"></div>
</div>

<div class="card">
<h2>Licenses</h2>
<div id="licenses">Enter your admin token, then click REFRESH LICENSES.</div>
</div>
</div>

<script>
const $ = (id) => document.getElementById(id);
const adminToken = () => $('token').value.trim();
const authHeaders = () => ({'Content-Type':'application/json','X-Admin-Token':adminToken()});

function result(message, ok) {
  const box = $('result');
  box.className = ok ? 'result' : 'result error';
  box.innerHTML = message;
}

async function createLicense() {
  if (!adminToken()) { result('Enter the Admin Token first.', false); return; }
  const type = $('type').value;
  const data = {license_type:type};
  const name = $('name').value.trim();
  const notes = $('notes').value.trim();
  if (name) data.license_name = name;
  if (notes) data.notes = notes;
  if (type === 'custom') {
    const days = $('days').value;
    if (!days) { result('Enter Custom Days.', false); return; }
    data.custom_days = Number(days);
  }
  try {
    const response = await fetch('/api/admin/create-license', {
      method:'POST', headers:authHeaders(), body:JSON.stringify(data)
    });
    const json = await response.json();
    if (!json.ok) { result('❌ ' + (json.message || 'Failed'), false); return; }
    result('<b>KEY CREATED</b><div class="key">' + json.license_key + '</div><div>' +
      json.license_name + ' — ' + json.license_type + '</div><div class="small">Copy this key and keep it secure.</div>', true);
    await loadLicenses();
  } catch (error) {
    result('❌ Request failed. Please try again.', false);
  }
}

async function loadLicenses() {
  if (!adminToken()) { $('licenses').innerText = 'Enter your admin token, then click REFRESH LICENSES.'; return; }
  try {
    const response = await fetch('/api/admin/licenses', {headers:{'X-Admin-Token':adminToken()}});
    const json = await response.json();
    if (!json.ok) { $('licenses').innerText = '❌ ' + (json.message || 'Unauthorized'); return; }
    if (!json.licenses.length) { $('licenses').innerText = 'No licenses yet.'; return; }
    let html = '<table><tr><th>Key</th><th>Type</th><th>Status</th><th>Machine</th><th>Expires</th><th>Actions</th></tr>';
    for (const item of json.licenses) {
      const status = Number(item.revoked) ? 'REVOKED' : (item.machine_id ? 'ACTIVATED' : 'UNUSED');
      html += '<tr><td><b>' + escapeHtml(item.license_key) + '</b><br><span class="small">' + escapeHtml(item.license_name) +
        '</span></td><td>' + escapeHtml(item.license_type) + '</td><td>' + status + '</td><td>' +
        escapeHtml(item.machine_id || '—') + '</td><td>' + escapeHtml(item.expires_at || 'LIFETIME / not activated') +
        '</td><td class="actions"><button class="reset-btn" data-key="' + escapeAttr(item.license_key) + '">RESET</button> ' +
        '<button class="revoke-btn" data-key="' + escapeAttr(item.license_key) + '">REVOKE</button> ' +
        '<button class="delete-btn" data-key="' + escapeAttr(item.license_key) + '" style="background:#b3261e">DELETE</button></td></tr>';
    }
    html += '</table>';
    $('licenses').innerHTML = html;
    document.querySelectorAll('.reset-btn').forEach(btn => btn.addEventListener('click', () => resetLicense(btn.dataset.key)));
    document.querySelectorAll('.revoke-btn').forEach(btn => btn.addEventListener('click', () => revokeLicense(btn.dataset.key)));
    document.querySelectorAll('.delete-btn').forEach(btn => btn.addEventListener('click', () => deleteLicense(btn.dataset.key)));
  } catch (error) {
    $('licenses').innerText = '❌ ' + error;
  }
}

async function resetLicense(key) {
  if (!confirm('Reset this license for a new machine activation?')) return;
  const response = await fetch('/api/admin/reset', {method:'POST', headers:authHeaders(), body:JSON.stringify({license_key:key})});
  const json = await response.json();
  if (!json.ok) alert(json.message || 'Failed');
  await loadLicenses();
}

async function revokeLicense(key) {
  if (!confirm('Revoke this license? The customer will be locked out on the next server check.')) return;
  const response = await fetch('/api/admin/revoke', {method:'POST', headers:authHeaders(), body:JSON.stringify({license_key:key})});
  const json = await response.json();
  if (!json.ok) alert(json.message || 'Failed');
  await loadLicenses();
}

async function deleteLicense(key) {
  if (!confirm('PERMANENTLY DELETE this license? This cannot be undone. The key will immediately become invalid.')) return;
  const response = await fetch('/api/admin/delete', {
    method:'POST',
    headers:authHeaders(),
    body:JSON.stringify({license_key:key})
  });
  const json = await response.json();
  if (!json.ok) {
    alert(json.message || 'Failed');
    return;
  }
  await loadLicenses();
  result('🗑️ <b>LICENSE DELETED</b><div class="small">' + escapeHtml(key) + '</div>', true);
}

function escapeHtml(value) {
  return String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#39;');
}
function escapeAttr(value) { return escapeHtml(value); }

$('generate-btn').addEventListener('click', createLicense);
$('refresh-btn').addEventListener('click', loadLicenses);
</script>
</body>
</html>
"""

@app.post("/api/admin/create-license")
@_require_admin
def admin_create_license():
    data = request.get_json(silent=True) or {}
    try:
        license_type, duration_seconds, default_name = _duration_from_request(data)
    except Exception as exc:
        return jsonify(ok=False, message="Invalid license configuration."), 400

    key = str(data.get("license_key", "")).strip().upper() or _generate_key()
    if not _safe_license_key(key):
        return jsonify(ok=False, message="Invalid license key format."), 400
    name = str(data.get("license_name", "")).strip() or default_name
    notes = str(data.get("notes", "")).strip()

    if _get_license(key):
        return jsonify(ok=False, message="That license key already exists."), 409

    now = _iso(_utc_now())
    conn = _db()
    params = (key, PRODUCT_ID, name, license_type, duration_seconds, now, notes)
    if _is_postgres():
        conn.execute("""
            INSERT INTO licenses
            (license_key, product_id, license_name, license_type, duration_seconds, created_at, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, params)
    else:
        conn.execute("""
            INSERT INTO licenses
            (license_key, product_id, license_name, license_type, duration_seconds, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, params)
    conn.commit()
    conn.close()

    return jsonify(ok=True, license_key=key, license_name=name, license_type=license_type,
                   duration_seconds=duration_seconds, created_at=now)


@app.post("/api/admin/revoke")
@_require_admin
def admin_revoke():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key", "")).strip().upper()
    record = _get_license(key)
    if not record:
        return jsonify(ok=False, message="License not found."), 404
    _update_license(key, revoked=1)
    return jsonify(ok=True, message="License revoked.", license_key=key)


@app.post("/api/admin/delete")
@_require_admin
def admin_delete():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key", "")).strip().upper()
    if not key:
        return jsonify(ok=False, message="License key is required."), 400

    record = _get_license(key)
    if not record:
        return jsonify(ok=False, message="License not found."), 404

    conn = _db()
    if _is_postgres():
        conn.execute("DELETE FROM licenses WHERE license_key = %s", (key,))
    else:
        conn.execute("DELETE FROM licenses WHERE license_key = ?", (key,))
    conn.commit()
    conn.close()

    return jsonify(ok=True, message="License permanently deleted.", license_key=key)


@app.post("/api/admin/reset")
@_require_admin
def admin_reset():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key", "")).strip().upper()
    record = _get_license(key)
    if not record:
        return jsonify(ok=False, message="License not found."), 404
    _update_license(key, machine_id=None, activated_at=None, expires_at=None, revoked=0)
    return jsonify(ok=True, message="License reset and ready for a new machine activation.", license_key=key)


@app.get("/api/admin/licenses")
@_require_admin
def admin_list():
    conn = _db()
    rows = conn.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify(ok=True, licenses=[_row_to_dict(row) for row in rows])


@app.get("/update.json")
def update_manifest():
    return jsonify(
        version="4.4.6",
        download_url=(
            "https://raw.githubusercontent.com/Hot44431/"
            "the-majin-labs-license-server/main/"
            "The_Majin_Labs_Life_Size_Tool_v446_Online_Licensed.zip"
        ),
        notes="The Majin Labs Life Size Tool v4.4.1 production license system.",
    )


@app.errorhandler(413)
def request_too_large(error):
    return jsonify(ok=False, message="Request too large."), 413

@app.errorhandler(400)
def bad_request(error):
    return jsonify(ok=False, message="Bad request."), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify(ok=False, message="Not found."), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify(ok=False, message="Method not allowed."), 405



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
