"""
The Majin Labs License Server - v4.4 starter.

Install:
    pip install flask

Run locally for testing:
    python the_majin_labs_license_server_v44.py

IMPORTANT:
This starter server uses an in-memory dictionary for testing only.
For real sales, replace it with persistent database storage and deploy
behind HTTPS.
"""
from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

PRODUCT_ID = "the_majin_labs_life_size_tool"

# Demo key for testing only.
LICENSES = {
    "MJL-DEMO-0001": {
        "product_id": PRODUCT_ID,
        "license_name": "Demo Lifetime License",
        "machine_id": None,
        "activated_at": None,
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
        return jsonify(ok=False, message="License key and machine ID are required."), 400

    record = LICENSES.get(key)
    if record is None:
        return jsonify(ok=False, message="Invalid license key."), 403

    # FIRST USE: permanently bind the key to this machine.
    if record["machine_id"] is None:
        record["machine_id"] = machine_id
        record["activated_at"] = datetime.now(timezone.utc).isoformat()
        return jsonify(
            ok=True,
            message="License activated successfully.",
            license_name=record["license_name"],
            activated_at=record["activated_at"],
            server_token="demo-token",
        )

    # SAME MACHINE: allow the customer to re-run activation.
    if record["machine_id"] == machine_id:
        return jsonify(
            ok=True,
            message="License already belongs to this computer.",
            license_name=record["license_name"],
            activated_at=record["activated_at"],
            server_token="demo-token",
        )

    # DIFFERENT MACHINE: reject permanently until YOU reset it.
    return jsonify(
        ok=False,
        message="This license key has already been activated on another computer."
    ), 403


@app.get("/update.json")
def update_manifest():
    # Change these values whenever you publish a new version.
    return jsonify(
        version="4.4.0",
        download_url="https://YOUR-DOWNLOAD-HOST.example.com/The_Majin_Labs_Life_Size_Tool_v44_Licensed.zip",
        notes="v4.4 commercial licensing/update build.",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
