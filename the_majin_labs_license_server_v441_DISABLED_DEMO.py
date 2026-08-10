from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

PRODUCT_ID = "the_majin_labs_life_size_tool"

# Demo Lifetime License DISABLED for this server-side test.
LICENSES = {}

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

    if record["machine_id"] == machine_id:
        return jsonify(
            ok=True,
            message="License already belongs to this computer.",
            license_name=record["license_name"],
            activated_at=record["activated_at"],
            server_token="demo-token",
        )

    return jsonify(
        ok=False,
        message="This license key has already been activated on another computer."
    ), 403

@app.get("/update.json")
def update_manifest():
    return jsonify(
        version="4.4.1",
        download_url="https://raw.githubusercontent.com/Hot44431/the-majin-labs-license-server/main/The_Majin_Labs_Life_Size_Tool_v441_Online_Licensed.zip",
        notes="TEST UPDATE v4.4.1 - update system test.",
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
