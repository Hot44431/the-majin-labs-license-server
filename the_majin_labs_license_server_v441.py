"""
The Majin Labs License Server - v4.4.1
5-minute license test server.

TEST KEY:
    MJL-TEST-5MIN-8427

The key starts its 5-minute timer on first successful activation.
This is an in-memory test only.
"""

from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

PRODUCT_ID = "the_majin_labs_life_size_tool"

TEST_KEY = "MJL-TEST-5MIN-8427"
TEST_DURATION_MINUTES = 5

LICENSES = {
    TEST_KEY: {
        "product_id": PRODUCT_ID,
        "license_name": "5 Minute Test License 8427",
        "machine_id": None,
        "activated_at": None,
        "expires_at": None,
    }
}


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

    record = LICENSES.get(key)

    if record is None:
        return jsonify(ok=False, message="Invalid license key."), 403

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

        record["machine_id"] = machine_id
        record["activated_at"] = now.isoformat()
        record["expires_at"] = expires.isoformat()

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
    app.run(host="0.0.0.0", port=8000, debug=False)
