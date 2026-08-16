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
import json
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict, deque
from threading import Lock
import re
import base64
from io import BytesIO

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception:
    hashes = None
    serialization = None
    padding = None

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
UPDATE_VERSION = "4.4.12"

TEST_KEY = "MJL-TEST-5MIN-8427"
TEST_DURATION_SECONDS = 5 * 60

TRIAL_DURATION_SECONDS = 7 * 24 * 60 * 60
THIRTY_DAY_SECONDS = 30 * 24 * 60 * 60
ONE_YEAR_SECONDS = 365 * 24 * 60 * 60

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DATABASE_PATH = os.environ.get("DATABASE_PATH", "licenses.db").strip()
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "").strip()
GEOMETRY_SIGNING_PRIVATE_KEY_B64 = os.environ.get("GEOMETRY_SIGNING_PRIVATE_KEY_B64", "").strip()


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
    """Return short-lived, server-signed geometry authorization.

    The customer receives only a signature and public geometry factors.
    The RSA private signing key exists only in Render environment variables.
    """
    if not _rate_limit("geometry", GEOMETRY_LIMIT):
        return jsonify(ok=False, message="Too many requests. Please try again later."), 429

    if not GEOMETRY_SIGNING_PRIVATE_KEY_B64 or serialization is None or padding is None:
        return jsonify(ok=False, message="Geometry signing is not configured."), 503

    data = request.get_json(silent=True) or {}
    product_id = str(data.get("product_id", "")).strip()
    key = str(data.get("license_key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()
    addon_version = str(data.get("addon_version", "")).strip()

    if product_id != PRODUCT_ID or not key or not machine_id or not addon_version:
        return jsonify(ok=False, message="Invalid geometry authorization request."), 400

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

    issued = _utc_now()
    auth_expires = issued + timedelta(minutes=15)

    payload = {
        "addon_version": addon_version,
        "bed_margin_scale": 1.0,
        "expires_at": _iso(auth_expires),
        "hole_radius_scale": 1.0,
        "hole_tolerance_scale": 1.0,
        "issued_at": _iso(issued),
        "license_key": key,
        "machine_id": machine_id,
        "product_id": product_id,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    try:
        private_pem = base64.b64decode(GEOMETRY_SIGNING_PRIVATE_KEY_B64, validate=True)
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        signature = private_key.sign(
            canonical,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except Exception:
        return jsonify(ok=False, message="Geometry signing failed."), 503

    return jsonify(
        ok=True,
        **payload,
        signature=base64.b64encode(signature).decode("ascii"),
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
# EMBEDDED CLIENT UPDATE - v4.4.12
# ---------------------------------------------------------------------------
_V4412_ZIP_B64 = """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"""

@app.get("/download/v4412.zip")
def download_v4411():
    try:
        payload = base64.b64decode(_V4412_ZIP_B64)
        return app.response_class(
            payload,
            mimetype="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="The_Majin_Labs_Life_Size_Tool_v4412_Production_Customer.zip"',
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
            "https://the-majin-labs-license-server.onrender.com/download/v4412.zip"
        ),
        notes="The Majin Labs Life Size Tool v4.4.12 — signed server geometry authorization.",
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
