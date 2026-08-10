"""
The Majin Labs License Server - v4.4.1
Persistent license server with a 5-minute test key.

TEST KEY:
    MJL-TEST-5MIN-8427

The key starts its 5-minute timer on first successful activation.
License state is stored in SQLite so it survives application restarts.
"""

from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

PRODUCT_ID = "the_majin_labs_life_size_tool"

TEST_KEY = "MJL-TEST-5MIN-8427"
TEST_DURATION_MINUTES = 5

DATABASE_PATH = "licenses.db"


def _db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    conn = _db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            product_id TEXT NOT NULL,
            license_name TEXT NOT NULL,
            machine_id TEXT,
            activated_at TEXT,
            expires_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        INSERT OR IGNORE INTO licenses
        (license_key, product_id, license_name)
        VALUES (?, ?, ?)
    """, (
        TEST_KEY,
        PRODUCT_ID,
        "5 Minute Test License 8427",
    ))
    conn.commit()
    conn.close()


def _get_license(key):
    conn = _db()
    row = conn.execute(
        "SELECT * FROM licenses WHERE license_key = ?",
        (key,),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def _update_license(key, **fields):
    if not fields:
        return

    allowed = {
        "machine_id",
        "activated_at",
        "expires_at",
        "revoked",
        "license_name",
    }
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return

    assignments = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [key]

    conn = _db()
    conn.execute(
        f"UPDATE licenses SET {assignments} WHERE license_key = ?",
        values,
    )
    conn.commit()
    conn.close()


_init_db()



@app.post("/api/activate")
def activate():
    data = request.get_json(silent=True) or {}

    product_id = str(data.get("product_id", "")).strip()
    key = str(data.get("license_key", "")).strip().upper()
    machine_id = str(data.get("machine_id", "")).strip()

    if product_id != PRODUCT_ID:
        return jsonify(ok=False, message="Invalid product."), 400

    if not key or not machine_id:
        return jsonify(
            ok=False,
            message="License key and machine ID are required."
        ), 400

    record = _get_license(key)

    if record is None:
        return jsonify(ok=False, message="Invalid license key."), 403

    if record["revoked"]:
        return jsonify(ok=False, message="License revoked."), 403

    # Check expiration if this key has already been activated.
    if record["expires_at"] is not None:
        expires_at = datetime.fromisoformat(record["expires_at"])

        if datetime.now(timezone.utc) >= expires_at:
            return jsonify(
                ok=False,
                message="License expired."
            ), 403

    # First activation starts the 5-minute timer.
    if record["machine_id"] is None:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=TEST_DURATION_MINUTES)

        _update_license(
            key,
            machine_id=machine_id,
            activated_at=now.isoformat(),
            expires_at=expires.isoformat(),
        )

        return jsonify(
            ok=True,
            message="5-minute test license activated.",
            license_name=record["license_name"],
            activated_at=record["activated_at"],
            expires_at=record["expires_at"],
            server_token="test-token",
        )

    # Same computer can re-run activation while the key is valid.
    if record["machine_id"] == machine_id:
        return jsonify(
            ok=True,
            message="5-minute test license is active.",
            license_name=record["license_name"],
            activated_at=record["activated_at"],
            expires_at=record["expires_at"],
            server_token="test-token",
        )

    return jsonify(
        ok=False,
        message="This license key has already been activated on another computer."
    ), 403


@app.get("/update.json")
def update_manifest():
    return jsonify(
        version="4.4.1",
        download_url=(
            "https://raw.githubusercontent.com/Hot44431/"
            "the-majin-labs-license-server/main/"
            "The_Majin_Labs_Life_Size_Tool_v441_Online_Licensed.zip"
        ),
        notes="TEST UPDATE v4.4.1 - update system test.",
    )


if __name__ == "__main__":
    _init_db()
    app.run(host="0.0.0.0", port=8000, debug=False)
