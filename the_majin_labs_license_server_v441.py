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
UPDATE_VERSION = "4.4.10"

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
_V4410_ZIP_B64 = """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"""

@app.get("/download/v4410.zip")
def download_v4410():
    try:
        payload = base64.b64decode(_V4410_ZIP_B64)
        return app.response_class(
            payload,
            mimetype="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="The_Majin_Labs_Life_Size_Tool_v4410_Production_Customer.zip"',
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
            "https://the-majin-labs-license-server.onrender.com/download/v4410.zip"
        ),
        notes="The Majin Labs Life Size Tool v4.4.10 production update.",
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
