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
import base64
from io import BytesIO

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
UPDATE_VERSION = "4.4.9"

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



# ---------------------------------------------------------------------------
# EMBEDDED CLIENT UPDATE - v4.4.9
# ---------------------------------------------------------------------------
_V449_ZIP_B64 = """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"""

@app.get("/download/v449.zip")
def download_v449():
    try:
        payload = base64.b64decode(_V449_ZIP_B64)
        return app.response_class(
            payload,
            mimetype="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="The_Majin_Labs_Life_Size_Tool_v449_Production_Customer.zip"',
                "Cache-Control": "no-store",
            },
        )
    except Exception:
        return jsonify(ok=False, message="Update package unavailable."), 503


@app.get("/update.json")
def update_manifest():
    return jsonify(
        version=UPDATE_VERSION,
        download_url=(
            "https://the-majin-labs-license-server.onrender.com/download/v449.zip"
        ),
        notes="The Majin Labs Life Size Tool v4.4.9 production update.",
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
