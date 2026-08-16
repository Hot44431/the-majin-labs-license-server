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
import json
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
CURRENT_VERSION = "4.4.12"
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
_V4412_ZIP_B64 = """
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
"""

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
