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
GEOMETRY_LIMIT = 60
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
UPDATE_VERSION = "4.4.11"

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


@app.post("/api/geometry-params")
def geometry_params():
    """Same validation as /api/status (rate limit, key lookup, revoked,
    machine match, expiry) -- this just returns the geometry scale
    factors the client folds into its cutting/connector math instead of
    a plain yes/no. Kept as its own route (not reusing /api/status's
    response) so a future paid tier could return different factors here
    without touching license activation/status at all.
    """
    if not _rate_limit("geometry", GEOMETRY_LIMIT):
        return jsonify(ok=False, message="Too many requests. Please try again later."), 429
    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    key = str(data.get("license_key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()

    if product_id != PRODUCT_ID or not key or not machine_id:
        return jsonify(ok=False, message="Invalid request."), 400

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

    # 1.0 = "use exactly what the customer entered in the panel". These
    # don't have to stay 1.0 forever -- a future tier could get tighter
    # default tolerances etc. by changing what this route returns, with
    # no client update needed.
    return jsonify(
        ok=True,
        hole_tolerance_scale=1.0,
        hole_radius_scale=1.0,
        bed_margin_scale=1.0,
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
_V4411_ZIP_B64 = """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"""

@app.get("/download/v4411.zip")
def download_v4411():
    try:
        payload = base64.b64decode(_V4411_ZIP_B64)
        return app.response_class(
            payload,
            mimetype="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="The_Majin_Labs_Life_Size_Tool_v4411_Production_Customer.zip"',
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
            "https://the-majin-labs-license-server.onrender.com/download/v4411.zip"
        ),
        notes="The Majin Labs Life Size Tool v4.4.11 production update.",
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
