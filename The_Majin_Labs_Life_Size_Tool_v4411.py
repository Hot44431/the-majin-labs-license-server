bl_info = {
    "name": "The Majin Labs Life Size Tool",
    "author": "Claude",
    "version": (4, 4, 12),
    "blender": (3, 6, 0),
    "location": "View3D > Sidebar > Cutter",
    "description": "Cuts an oversized mesh into printer-bed-sized pieces with dowel connectors, "
                    "auto mesh repair, smart cuts, and manual finished-height scaling.",
    "category": "Object",
}

import bpy
import bmesh
import math
import os
import json
import hashlib
import platform
import urllib.request
from urllib.error import HTTPError, URLError
import tempfile
import zipfile
import shutil
import time
import re
import base64
from datetime import datetime
import ctypes
from ctypes import wintypes
from mathutils import Vector, Matrix
from mathutils.bvhtree import BVHTree
from collections import defaultdict


# ---------------------------------------------------------------------------
# THE MAJIN LABS - COMMERCIAL LICENSE + UPDATE SYSTEM
# ---------------------------------------------------------------------------
# v4.4 commercial layer:
#   - One-time online activation
#   - Activation locked to this computer
#   - Local/offline use after activation
#   - License survives add-on updates
#   - Update manifest + update installation support
#
# Before selling, replace the placeholder HTTPS URLs below with your deployed
# license API and update manifest URLs.
# ---------------------------------------------------------------------------

PRODUCT_ID = "the_majin_labs_life_size_tool"
PRODUCT_NAME = "The Majin Labs Life Size Tool"
CURRENT_VERSION = (4, 4, 12)

LICENSE_API_URL = "https://the-majin-labs-license-server.onrender.com"
UPDATE_MANIFEST_URL = "https://the-majin-labs-license-server.onrender.com/update.json"

# Server-only geometry authorization uses RSA-2048 signatures.
# ONLY the public key is shipped to customers. The private signing key stays
# in the Render GEOMETRY_SIGNING_PRIVATE_KEY_B64 environment variable.
GEOMETRY_SIGNING_PUBLIC_N = 21445490342151160051552808921321407059897495284702916500452964548566567879825785908038546411404315090061268077549888806615980145392044867648559814173516288345458001736719094252560807337014224749253829004123305915078312922874662372084993195524822663670471778970530068800571273766441833921650430091585258784660463327232403164318923384673125326910398997273475694748957262970004898285176592725006667353896576308558759730198830162834438983443559690636839845259877788981318099354873491123108954362034637056516619789513450777037089000298445601484752226867589659447432213749471293559981190347351416948542270772347278569454471
GEOMETRY_SIGNING_PUBLIC_E = 65537
GEOMETRY_AUTH_TTL = 15 * 60

_LICENSE_FILE = "the_majin_labs_license.json"


def _version_string(version):
    return ".".join(str(v) for v in version)


def _license_path():
    base = bpy.utils.user_resource("CONFIG", path="the_majin_labs", create=True)
    return os.path.join(base, "the_majin_labs_license.dat")


class _DPAPI_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _dpapi_crypt(data, entropy, decrypt=False):
    """Windows DPAPI encryption/decryption with machine-derived entropy."""
    if platform.system() != "Windows":
        return None

    crypt = ctypes.windll.crypt32
    kernel = ctypes.windll.kernel32
    raw = bytes(data)
    ent = bytes(entropy)

    raw_buf = ctypes.create_string_buffer(raw)
    ent_buf = ctypes.create_string_buffer(ent)
    in_blob = _DPAPI_BLOB(
        len(raw), ctypes.cast(raw_buf, ctypes.POINTER(ctypes.c_byte))
    )
    ent_blob = _DPAPI_BLOB(
        len(ent), ctypes.cast(ent_buf, ctypes.POINTER(ctypes.c_byte))
    )
    out_blob = _DPAPI_BLOB()
    flags = 0x1

    if decrypt:
        ok = crypt.CryptUnprotectData(
            ctypes.byref(in_blob), None, ctypes.byref(ent_blob),
            None, None, flags, ctypes.byref(out_blob)
        )
    else:
        ok = crypt.CryptProtectData(
            ctypes.byref(in_blob), "The Majin Labs License",
            ctypes.byref(ent_blob), None, None, flags,
            ctypes.byref(out_blob)
        )

    if not ok:
        return None
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel.LocalFree(out_blob.pbData)


def _license_entropy():
    return hashlib.sha256(
        ("THE_MAJIN_LABS_LICENSE_ENTROPY|" + _machine_id()).encode("utf-8")
    ).digest()




def _machine_id():
    # Stable per-machine fingerprint. The license is bound to this value.
    parts = [
        platform.system(),
        platform.machine(),
        platform.node(),
        str(os.environ.get("COMPUTERNAME", "")),
        str(os.environ.get("PROCESSOR_IDENTIFIER", "")),
        str(__import__("uuid").getnode()),
    ]
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            parts.append(str(guid))
        except Exception:
            pass
    return hashlib.sha256("|".join(parts).encode("utf-8", errors="ignore")).hexdigest().upper()


def _load_license():
    path = _license_path()

    # New format: Windows DPAPI-protected JSON.
    try:
        with open(path, "rb") as f:
            blob = base64.b64decode(f.read())
        raw = _dpapi_crypt(blob, _license_entropy(), decrypt=True)
        if raw:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass

    # One-time migration from the old plaintext JSON cache.
    legacy = os.path.join(os.path.dirname(path), _LICENSE_FILE)
    try:
        with open(legacy, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _save_license(data)
            try:
                os.remove(legacy)
            except Exception:
                pass
            return data
    except Exception:
        return {}


def _save_license(data):
    path = _license_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    protected = _dpapi_crypt(raw, _license_entropy(), decrypt=False)
    if protected is None:
        raise RuntimeError(
            "Unable to protect the local license cache with Windows DPAPI."
        )

    temp_path = path + ".tmp"
    with open(temp_path, "wb") as f:
        f.write(base64.b64encode(protected))
    os.replace(temp_path, path)



def _clear_local_license():
    """Remove the locally cached license and stop the countdown."""
    try:
        path = _license_path()
        if os.path.exists(path):
            os.remove(path)
        legacy = os.path.join(os.path.dirname(path), _LICENSE_FILE)
        if os.path.exists(legacy):
            os.remove(legacy)
    except Exception:
        pass
    try:
        _stop_license_countdown()
    except Exception:
        pass
    try:
        for window in bpy.context.window_manager.windows:
            for area in window.screen.areas:
                if area.type == "VIEW_3D":
                    area.tag_redraw()
    except Exception:
        pass


def _check_server_license_status():
    """Ask the authoritative server whether the current license is still valid.

    Returns:
      True  = valid
      False = definite server rejection (403)
      None  = temporary network/server problem (do not log out)
    """
    data = _load_license()
    if not data or data.get("activated") is not True:
        return False

    key = str(data.get("license_key", "")).strip().upper()
    if not key:
        return False

    try:
        result = _post_json(
            LICENSE_API_URL.rstrip("/") + "/api/status",
            {
                "product_id": PRODUCT_ID,
                "license_key": key,
                "machine_id": _machine_id(),
            },
            timeout=10,
        )
    except Exception as exc:
        message = str(exc)
        if message.startswith("SERVER_403:"):
            # Definite rejection: revoked, expired, deleted, wrong machine, etc.
            _clear_local_license()
            print(f"[The Majin Labs] License rejected by server: {message}")
            return False

        # 429, 5xx, timeout, DNS and other temporary failures must NOT
        # accidentally log a customer out.
        print(f"[The Majin Labs] License status check skipped: {message}")
        return None

    if not result.get("ok"):
        message = str(result.get("message", "License rejected."))
        # A successful HTTP response can still contain ok=false.
        # Treat explicit license rejection as a logout, but don't treat
        # generic server messages as a license failure.
        if any(word in message.lower() for word in (
            "revoked", "expired", "not found", "not active", "wrong machine",
            "invalid license", "license not found"
        )):
            _clear_local_license()
            print(f"[The Majin Labs] License rejected by server: {message}")
            return False
        return None

    # Refresh server-authoritative fields without trusting local expiration.
    try:
        current = _load_license()
        current["license_name"] = result.get("license_name", current.get("license_name", ""))
        current["expires_at"] = result.get("expires_at", current.get("expires_at", ""))
        current["machine_id"] = result.get("machine_id", current.get("machine_id", ""))
        _save_license(current)
    except Exception:
        pass

    return True


_license_server_timer_enabled = False


def _license_server_timer():
    if not _license_server_timer_enabled:
        return None

    try:
        if _is_licensed() and _server_configured():
            _check_server_license_status()
    except Exception as exc:
        print(f"[The Majin Labs] Server status timer skipped: {exc}")

    return 30.0


def _start_license_server_timer():
    global _license_server_timer_enabled
    _license_server_timer_enabled = True
    try:
        if not bpy.app.timers.is_registered(_license_server_timer):
            bpy.app.timers.register(
                _license_server_timer,
                first_interval=2.0,
                persistent=True,
            )
    except Exception:
        pass


def _stop_license_server_timer():
    global _license_server_timer_enabled
    _license_server_timer_enabled = False
    try:
        if bpy.app.timers.is_registered(_license_server_timer):
            bpy.app.timers.unregister(_license_server_timer)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# License helpers that were missing from this build: local licensed-check,
# server-configuration check, JSON HTTP calls, expiry math/formatting, and
# the lightweight local countdown redraw timer. These were being called
# throughout the file (activation, the license panel, the 30s server-status
# timer) but never defined, which crashed the panel's draw() with
# NameError: name '_is_licensed' is not defined.
# ---------------------------------------------------------------------------

def _server_configured():
    """True once LICENSE_API_URL has been pointed at a real server instead
    of a placeholder -- mirrors the same placeholder check _check_update()
    already does for UPDATE_MANIFEST_URL."""
    return (
        LICENSE_API_URL.startswith("https://")
        and "YOUR-LICENSE-SERVER" not in LICENSE_API_URL
    )


def _post_json(url, payload, timeout=15):
    """POST JSON, return the parsed JSON response. Raises RuntimeError on
    failure; a 403 response raises with a 'SERVER_403:<message>' prefix so
    callers can tell definite rejection (revoked/expired/wrong machine)
    apart from a temporary network/server problem."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as e:
        try:
            msg = json.loads(e.read().decode("utf-8")).get("message", str(e))
        except Exception:
            msg = str(e)
        if e.code == 403:
            raise RuntimeError(f"SERVER_403:{msg}")
        raise RuntimeError(f"Server returned {e.code}: {msg}")
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")

    try:
        return json.loads(body)
    except Exception:
        raise RuntimeError("Server returned an invalid response.")


def _get_json(url, timeout=15):
    """GET JSON, return the parsed response. Raises RuntimeError on failure."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
    except HTTPError as e:
        raise RuntimeError(f"Server returned {e.code}: {e.reason}")
    except URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")
    return json.loads(body)


def _license_remaining_seconds(data):
    """Seconds until data['expires_at'] elapses, or None for no-expiry /
    lifetime licenses. Accepts either a unix-epoch number or an ISO 8601
    string (with or without a trailing 'Z') since the server field's exact
    format isn't pinned down elsewhere in this file."""
    expires_at = data.get("expires_at")
    if not expires_at:
        return None

    try:
        expires_epoch = float(expires_at)
    except (TypeError, ValueError):
        try:
            text = str(expires_at).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            expires_epoch = datetime.fromisoformat(text).timestamp()
        except Exception:
            return None

    return max(0.0, expires_epoch - time.time())


def _format_remaining(seconds):
    """seconds -> 'HH:MM:SS', prefixed with '<n>d ' once it's past a day."""
    total = int(max(0.0, seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _is_licensed():
    """Local (offline-capable) licensed check: activated flag set and not
    past its cached expiry. Server-side revocation is handled separately by
    _check_server_license_status(), which clears the local cache on a
    definite rejection -- this function just trusts that cache."""
    data = _load_license()
    if not data or data.get("activated") is not True:
        return False
    remaining = _license_remaining_seconds(data)
    if remaining is not None and remaining <= 0:
        return False
    return True


def _require_license(execute_fn):
    """Gate paid geometry operators with the local license AND a
    server-signed geometry authorization."""
    def wrapped(self, context):
        if not _is_licensed():
            self.report(
                {'ERROR'},
                "License required — activate The Majin Labs Life Size Tool in the panel."
            )
            return {'CANCELLED'}

        if _fetch_geometry_params(force=True) is None:
            self.report(
                {'ERROR'},
                "Server geometry authorization required. Check your license and internet connection."
            )
            return {'CANCELLED'}

        return execute_fn(self, context)
    return wrapped


_license_countdown_timer_enabled = False


def _license_countdown_timer():
    """Redraw-only timer (no network) so the 'Time Remaining' label in the
    license panel ticks every second. Server status itself is polled
    separately by _license_server_timer every 30s."""
    if not _license_countdown_timer_enabled:
        return None
    try:
        for window in bpy.context.window_manager.windows:
            for area in window.screen.areas:
                if area.type == "VIEW_3D":
                    area.tag_redraw()
    except Exception:
        pass
    return 1.0


def _start_license_countdown():
    global _license_countdown_timer_enabled
    _license_countdown_timer_enabled = True
    try:
        if not bpy.app.timers.is_registered(_license_countdown_timer):
            bpy.app.timers.register(
                _license_countdown_timer, first_interval=1.0, persistent=True
            )
    except Exception:
        pass


def _stop_license_countdown():
    global _license_countdown_timer_enabled
    _license_countdown_timer_enabled = False
    try:
        if bpy.app.timers.is_registered(_license_countdown_timer):
            bpy.app.timers.unregister(_license_countdown_timer)
    except Exception:
        pass


def _activate_license(key):
    key = str(key or "").strip().upper()
    if not key:
        return False, "Enter a license key."

    if not _server_configured():
        return False, "License server is not configured yet."

    try:
        result = _post_json(
            LICENSE_API_URL.rstrip("/") + "/api/activate",
            {
                "product_id": PRODUCT_ID,
                "license_key": key,
                "machine_id": _machine_id(),
                "addon_version": _version_string(CURRENT_VERSION),
            },
        )
    except Exception as exc:
        message = str(exc)
        if message.startswith("SERVER_403:"):
            return False, message.split(":", 1)[1].strip()
        return False, f"Could not contact license server: {message}"

    if not result.get("ok"):
        return False, str(result.get("message", "Activation failed."))

    _save_license({
        "activated": True,
        "product_id": PRODUCT_ID,
        "license_key": key,
        "machine_id": _machine_id(),
        "license_name": result.get("license_name", ""),
        "activated_at": result.get("activated_at", ""),
        "expires_at": result.get("expires_at", ""),
    })
    _start_license_countdown()
    return True, "License activated successfully."


def _check_update():
    if (
        not UPDATE_MANIFEST_URL.startswith("https://")
        or "YOUR-LICENSE-SERVER" in UPDATE_MANIFEST_URL
    ):
        return False, "Update server is not configured.", None

    try:
        manifest = _get_json(UPDATE_MANIFEST_URL)
        latest = tuple(int(x) for x in str(manifest.get("version", "0.0.0")).split("."))
        if latest <= CURRENT_VERSION:
            return True, f"You are up to date ({_version_string(CURRENT_VERSION)}).", manifest
        return True, f"Update available: {_version_string(latest)}", manifest
    except Exception as exc:
        return False, f"Could not check for updates: {exc}", None


def _install_update(manifest):
    download_url = str(manifest.get("download_url", "")).strip()
    if not download_url.startswith("https://"):
        raise RuntimeError("The update does not contain a valid HTTPS download URL.")

    temp_dir = tempfile.mkdtemp(prefix="majin_labs_update_")
    zip_path = os.path.join(temp_dir, "update.zip")
    try:
        urllib.request.urlretrieve(download_url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            if zf.testzip() is not None:
                raise RuntimeError("The update ZIP is corrupt.")

        # Blender handles replacing/installing the add-on ZIP.
        bpy.ops.preferences.addon_install(filepath=zip_path, overwrite=True)
        return True
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


class MAJINLABS_OT_activate_license(bpy.types.Operator):
    bl_idname = "majinlabs.activate_license"
    bl_label = "Activate License"
    bl_description = "Activate this license on this computer"
    bl_options = {"REGISTER"}

    license_key: bpy.props.StringProperty(name="License Key", default="")

    def invoke(self, context, event):
        return context.window_manager.invoke_props_dialog(self)

    def draw(self, context):
        self.layout.prop(self, "license_key", text="License Key")

    def execute(self, context):
        ok, message = _activate_license(self.license_key)
        self.report({"INFO" if ok else "ERROR"}, message)
        for area in context.screen.areas:
            if area.type == "VIEW_3D":
                area.tag_redraw()
        return {"FINISHED"} if ok else {"CANCELLED"}


class MAJINLABS_OT_check_update(bpy.types.Operator):
    bl_idname = "majinlabs.check_update"
    bl_label = "Check for Update"

    def execute(self, context):
        ok, message, manifest = _check_update()
        if ok and manifest:
            context.scene["majinlabs_update_manifest"] = json.dumps(manifest)
        self.report({"INFO" if ok else "ERROR"}, message)
        return {"FINISHED"} if ok else {"CANCELLED"}


class MAJINLABS_OT_install_update(bpy.types.Operator):
    bl_idname = "majinlabs.install_update"
    bl_label = "Install Update"

    def execute(self, context):
        raw = context.scene.get("majinlabs_update_manifest", "")
        try:
            manifest = json.loads(raw)
            latest = tuple(int(x) for x in str(manifest.get("version", "0.0.0")).split("."))
            if latest <= CURRENT_VERSION:
                self.report({"INFO"}, "No newer version is available.")
                return {"FINISHED"}
            _install_update(manifest)
            self.report({"INFO"}, "Update installed. Restart Blender to load the new version.")
            return {"FINISHED"}
        except Exception as exc:
            self.report({"ERROR"}, f"Update failed: {exc}")
            return {"CANCELLED"}


class VIEW3D_PT_majinlabs_license(bpy.types.Panel):
    bl_label = "The Majin Labs License"
    bl_idname = "VIEW3D_PT_majinlabs_license"
    bl_space_type = "VIEW_3D"
    bl_region_type = "UI"
    bl_category = "Cutter"

    def draw(self, context):
        layout = self.layout
        box = layout.box()
        box.label(text="THE MAJIN LABS", icon="KEYINGSET")
        box.label(text=PRODUCT_NAME)
        box.label(text=f"Version {_version_string(CURRENT_VERSION)}")

        if _is_licensed():
            data = _load_license()
            box.label(text="LICENSE ACTIVE", icon="CHECKMARK")
            if data.get("license_name"):
                box.label(text=f"License: {data['license_name']}")

            remaining = _license_remaining_seconds(data)
            if remaining is None:
                if "lifetime" in str(data.get("license_name", "")).lower():
                    box.label(text="Time Remaining: LIFETIME", icon="TIME")
                else:
                    box.label(text="Time Remaining: --:--:--", icon="TIME")
            else:
                box.label(
                    text=f"Time Remaining: {_format_remaining(remaining)}",
                    icon="TIME",
                )
                if remaining <= 60:
                    box.label(text="LICENSE EXPIRING SOON", icon="ERROR")

            box.label(text=f"Machine: {_machine_id()[:12]}...")
            box.operator("majinlabs.check_update", icon="FILE_REFRESH", text="CHECK FOR UPDATE")

            raw = context.scene.get("majinlabs_update_manifest", "")
            if raw:
                try:
                    manifest = json.loads(raw)
                    latest = tuple(int(x) for x in str(manifest.get("version", "0.0.0")).split("."))
                    if latest > CURRENT_VERSION:
                        box.label(text=f"Update available: {_version_string(latest)}", icon="INFO")
                        box.operator("majinlabs.install_update", icon="IMPORT", text="INSTALL UPDATE")
                except Exception:
                    pass
        else:
            box.label(text="LICENSE REQUIRED", icon="LOCKED")
            box.label(text="Activate this copy on this computer.")
            box.operator("majinlabs.activate_license", icon="KEYINGSET", text="ENTER LICENSE KEY")
            box.label(text=f"Machine ID: {_machine_id()[:12]}...")



# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

DEFAULT_SECTION_ORDER = ["view", "dowel", "size", "scale", "bed", "direction", "repair"]


class CutterSettings(bpy.types.PropertyGroup):
    target_model_x: bpy.props.FloatProperty(
        name="Model X (mm)", default=0.0, min=0.0,
        description="Target model X dimension in millimeters. 0 = unchanged."
    )
    target_model_y: bpy.props.FloatProperty(
        name="Model Y (mm)", default=0.0, min=0.0,
        description="Target model Y dimension in millimeters. 0 = unchanged."
    )
    target_model_z: bpy.props.FloatProperty(
        name="Model Z (mm)", default=0.0, min=0.0,
        description="Target model Z dimension in millimeters. 0 = unchanged."
    )
    scale_model_before_cut: bpy.props.BoolProperty(
        name="Set Model Size Before Cut", default=True,
        description="Resize the model to the entered X/Y/Z dimensions before cutting."
    )

    # --- Manual finished model height ---
    model_height: bpy.props.FloatProperty(
        name="Height",
        default=180.0,
        min=0.01,
        description="Finished model height used by APPLY SCALE."
    )
    model_height_unit: bpy.props.EnumProperty(
        name="Unit",
        items=[
            ("CM", "cm", "Enter model height in centimeters"),
            ("MM", "mm", "Enter model height in millimeters"),
        ],
        default="CM",
    )

    # --- 3D Printer (matches Luban "Printer size X/Y/Z" = 320/320/320) ---
    bed_x: bpy.props.FloatProperty(name="Printer Size X (mm)", default=320.0, min=10.0)
    bed_y: bpy.props.FloatProperty(name="Printer Size Y (mm)", default=320.0, min=10.0)
    bed_z: bpy.props.FloatProperty(name="Printer Size Z (mm)", default=320.0, min=10.0)
    border_clearance: bpy.props.FloatProperty(name="Border Clearance (mm)", default=0.0, min=0.0)
    cut_chamfer: bpy.props.FloatProperty(name="Cut Chamfer (mm)", default=0.0, min=0.0)
    close_cut: bpy.props.BoolProperty(name="Close Cut", default=True,
                                       description="Cap each cut face so pieces stay watertight")
    smart_cut: bpy.props.BoolProperty(
        name="Smart Cut Optimization", default=True,
        description="Search nearby cut planes for simpler, cleaner seams and avoid cutting through detailed areas such as faces when a better plane fits the printer bed"
    )
    smart_cut_search_mm: bpy.props.FloatProperty(
        name="Smart Cut Search (mm)", default=60.0, min=5.0, max=200.0,
        description="How far the cutter may move a cut plane from the normal balanced position to find a cleaner seam"
    )
    smart_cut_samples: bpy.props.IntProperty(
        name="Smart Cut Samples", default=11, min=5, max=21,
        description="Number of nearby candidate planes tested for each cut"
    )

    cut_x: bpy.props.BoolProperty(name="Cut Along X", default=True)
    cut_y: bpy.props.BoolProperty(name="Cut Along Y", default=True)
    cut_z: bpy.props.BoolProperty(name="Cut Along Z", default=True)

    # --- Connector ---
    # Legacy setting retained for compatibility, but the staged workflow
    # keeps connectors OUT of the cutting operation by default.
    add_connectors: bpy.props.BoolProperty(name="Add Dowel Holes", default=False)
    connectors_during_cut: bpy.props.BoolProperty(
        name="Connectors During Cut", default=False,
        description="Legacy one-click mode. Keep OFF for the faster staged workflow."
    )
    connector_size: bpy.props.FloatProperty(name="Dowel Size (mm)", default=2.4, min=0.2)
    connector_depth_ratio: bpy.props.FloatProperty(name="Depth Ratio", default=2.0, min=0.1)
    connector_tolerance: bpy.props.FloatProperty(name="Tolerance (mm)", default=-0.15)
    connector_edge_margin: bpy.props.FloatProperty(
        name="Edge Margin (mm)", default=3.0, min=0.0, max=20.0,
        description="Minimum extra material kept between a dowel hole and the cut-face edge. "
                    "The center is rejected unless the full hole footprint has this margin on both pieces."
    )
    connectors_per_edge: bpy.props.IntProperty(
        name="Dowels Per Connection", default=2, min=1, max=20,
        description="Number of dowel holes to create on EACH mating connection/interface. "
                    "This is NOT a total per part. If one part has 3 separate mating sides "
                    "and this is set to 2, it can receive up to 2 holes on each side."
    )
    connector_boolean_solver: bpy.props.EnumProperty(
        name="Hole Boolean Solver",
        items=[
            ('FAST', "Fast", "Much faster. Fine for the simple cylinder-into-mesh "
                              "cuts dowel holes need; use this unless you see artifacts."),
            ('EXACT', "Exact", "Slower but more robust against messy/self-intersecting "
                                "geometry. Fall back to this if Fast produces bad caps."),
        ],
        default='FAST',
        description="Boolean solver used when cutting dowel holes",
    )

    # --- Panel section layout (user-reorderable sidebar sections) ---
    panel_section_order: bpy.props.StringProperty(
        name="Panel Section Order",
        default=",".join(DEFAULT_SECTION_ORDER),
        description="Internal: comma-separated order of the reorderable sidebar sections",
    )
    panel_layout_locked: bpy.props.BoolProperty(
        name="Lock Section Order", default=False,
        description="Hide the up/down arrows so sections can't be reordered by accident"
    )

    # --- Mesh Repair ---
    auto_mesh_repair: bpy.props.BoolProperty(
        name="Auto Mesh Repair", default=False,
        description="Weld duplicate vertices, drop degenerate/loose geometry, fill any remaining "
                    "open holes and recompute normals on every piece after cutting (similar to "
                    "Bambu Studio's model repair)")
    repair_merge_distance: bpy.props.FloatProperty(
        name="Weld Distance (mm)", default=0.01, min=0.0001, max=1.0,
        description="Vertices closer together than this are merged during repair")

    # --- Part numbering ---
    add_part_number: bpy.props.BoolProperty(name="Part Number", default=True)
    start_number: bpy.props.IntProperty(name="Start Number", default=1)
    prefix: bpy.props.StringProperty(name="Prefix", default="")

    # --- Progress (internal, not user-facing settings) ---
    is_running: bpy.props.BoolProperty(name="Is Running", default=False)
    cancel_requested: bpy.props.BoolProperty(name="Cancel Requested", default=False)
    progress: bpy.props.FloatProperty(name="Progress", default=0.0, min=0.0, max=1.0)
    progress_text: bpy.props.StringProperty(name="Progress Text", default="")
    failed_caps: bpy.props.IntProperty(name="Failed Caps", default=0)
    # True after a successful model cut producing multiple printable pieces.
    dowels_ready: bpy.props.BoolProperty(name="Dowels Ready", default=False)


# ---------------------------------------------------------------------------
# Core cutting logic
# ---------------------------------------------------------------------------

def world_bounds(obj):
    mat = obj.matrix_world
    corners = [mat @ Vector(c) for c in obj.bound_box]
    xs = [c.x for c in corners]
    ys = [c.y for c in corners]
    zs = [c.z for c in corners]
    return Vector((min(xs), min(ys), min(zs))), Vector((max(xs), max(ys), max(zs)))


def plane_positions(min_v, max_v, axis_index, span, clearance):
    total = max_v[axis_index] - min_v[axis_index]
    usable = max(span - clearance, 1.0)
    if total <= usable:
        return []
    n_pieces = math.ceil(total / usable)
    step = total / n_pieces
    positions = []
    for i in range(1, n_pieces):
        positions.append(min_v[axis_index] + step * i)
    return positions


def _candidate_plane_complexity(obj, axis_index, pos):
    """Estimate how complicated a cut at *pos* will be without actually
    bisecting the mesh. Lower is better. The score combines sampled vertex
    density and the number of polygons crossed by the plane. Detailed areas
    (faces, hands, armor, etc.) normally have much higher intersection
    complexity than natural seam areas such as necks, waists and joints."""
    mesh = obj.data
    if not mesh.vertices or not mesh.polygons:
        return 1e9

    mat = obj.matrix_world
    verts = mesh.vertices
    polys = mesh.polygons

    # Limit work on very dense models. Sampling is deterministic and spread
    # across the mesh so the cutter stays responsive on million-face models.
    v_count = len(verts)
    v_step = max(1, v_count // 60000)
    p_count = len(polys)
    p_step = max(1, p_count // 30000)

    density_hits = 0
    density_window = 2.0
    for i in range(0, v_count, v_step):
        w = mat @ verts[i].co
        if abs(w[axis_index] - pos) <= density_window:
            density_hits += 1

    crossed = 0
    for i in range(0, p_count, p_step):
        poly = polys[i]
        coords = [mat @ verts[j].co for j in poly.vertices]
        if not coords:
            continue
        vals = [c[axis_index] - pos for c in coords]
        if min(vals) <= 0.0 and max(vals) >= 0.0:
            crossed += 1

    if crossed == 0:
        return 1e9

    # Normalize by sampling size so different mesh densities behave similarly.
    density_norm = density_hits / max(1.0, v_count / v_step)
    crossed_norm = crossed / max(1.0, p_count / p_step)
    return density_norm * 0.45 + crossed_norm * 0.55


def smart_plane_positions(obj, min_v, max_v, axis_index, span, clearance,
                          search_mm=60.0, samples=11):
    """Choose bed-safe cut planes that favor natural/low-complexity seams.

    The original cutter placed planes at equal intervals. That is predictable
    but can slice straight through faces or other detailed areas. This version
    keeps the exact same number of printable pieces and the same bed limits,
    then searches a bounded neighbourhood around each balanced plane.
    """
    total = max_v[axis_index] - min_v[axis_index]
    usable = max(span - clearance, 1.0)
    if total <= usable:
        return []

    n_pieces = math.ceil(total / usable)
    nominal_step = total / n_pieces
    positions = []
    current_min = min_v[axis_index]

    for cut_index in range(1, n_pieces):
        remaining_pieces = n_pieces - cut_index
        # Both sides must remain capable of fitting into the remaining number
        # of printer-bed-sized pieces.
        lower = max_v[axis_index] - remaining_pieces * usable
        upper = current_min + usable
        nominal = min_v[axis_index] + nominal_step * cut_index
        lower = max(lower, current_min + 0.5)
        upper = min(upper, max_v[axis_index] - 0.5)
        if lower > upper:
            lower, upper = min(lower, upper), max(lower, upper)

        window_lo = max(lower, nominal - search_mm)
        window_hi = min(upper, nominal + search_mm)
        if window_lo > window_hi:
            window_lo, window_hi = lower, upper

        count = max(5, int(samples))
        if count == 1:
            candidates = [nominal]
        else:
            candidates = [window_lo + (window_hi - window_lo) * i / (count - 1)
                          for i in range(count)]
            if lower <= nominal <= upper:
                candidates.append(nominal)

        best_pos = nominal
        best_score = 1e9
        span_window = max(window_hi - window_lo, 1.0)
        for candidate in candidates:
            if candidate <= lower - 1e-6 or candidate >= upper + 1e-6:
                continue
            complexity = _candidate_plane_complexity(obj, axis_index, candidate)
            if complexity >= 1e8:
                continue
            distance_penalty = abs(candidate - nominal) / span_window
            low_len = candidate - current_min
            high_len = max_v[axis_index] - candidate
            large_piece_bonus = max(low_len, high_len) / usable
            score = (complexity * 1.0 +
                     distance_penalty * 0.12 -
                     large_piece_bonus * 0.08)
            if score < best_score:
                best_score = score
                best_pos = candidate

        positions.append(best_pos)
        current_min = best_pos

    return positions


def piece_count_for_axis(min_v, max_v, axis_index, span, clearance):
    return len(plane_positions(min_v, max_v, axis_index, span, clearance)) + 1


def estimate_total_steps(obj, s):
    """Precompute how many bisects + connector-groups + repair passes will
    happen, so the progress bar denominator is known up front (without
    touching the mesh yet). This is an approximation, not an exact count --
    good enough to drive a progress bar."""
    min_v, max_v = world_bounds(obj)

    n_x = piece_count_for_axis(min_v, max_v, 0, s.bed_x, s.border_clearance) if s.cut_x else 1
    n_y = piece_count_for_axis(min_v, max_v, 1, s.bed_y, s.border_clearance) if s.cut_y else 1
    n_z = piece_count_for_axis(min_v, max_v, 2, s.bed_z, s.border_clearance) if s.cut_z else 1

    bisects_x = (n_x - 1) if s.cut_x else 0
    bisects_y = n_x * (n_y - 1) if s.cut_y else 0
    bisects_z = n_x * n_y * (n_z - 1) if s.cut_z else 0
    total_bisects = bisects_x + bisects_y + bisects_z

    total_pieces = n_x * n_y * n_z

    # One connector "group" step per bisect performed (see cut_generator --
    # pieces are grouped by the exact cut plane they came from, and each
    # such group is processed in one step, however many pieces it contains).
    total_connector_groups = total_bisects if s.add_connectors else 0

    total_repair = total_pieces if s.auto_mesh_repair else 0

    return max(total_bisects + total_connector_groups + total_repair + 1, 1)


def cap_boundary(bm, geom_cut):
    """Cap the loop(s) of edges created by the bisect using triangle_fill,
    which handles concave/organic boundary loops far better than the
    ngon ear-clipping used by mesh.fill_holes. Returns True if every loop
    was fully closed (no leftover boundary edges).

    A single bisect through spiky/organic geometry (feathers, thin points,
    etc) rarely produces one boundary loop -- it produces MANY small,
    separate loops, one per spike the plane happens to cross. Handing every
    edge from every loop to a single triangle_fill call lets its beauty
    heuristic connect vertices ACROSS different loops when they sit close
    together and nearly parallel (exactly what adjacent spike tips look
    like), which is what produces a dense zigzag mesh bridging unrelated
    spikes instead of a clean cap on each one. Splitting into connected
    components first makes that structurally impossible: each component is
    one loop, filled on its own.
    """
    edges = [e for e in geom_cut if isinstance(e, bmesh.types.BMEdge) and e.is_valid]
    if not edges:
        return True

    remaining = set(edges)
    components = []
    while remaining:
        seed = remaining.pop()
        comp = {seed}
        stack = [seed]
        while stack:
            e = stack.pop()
            for v in e.verts:
                for e2 in v.link_edges:
                    if e2 in remaining:
                        remaining.discard(e2)
                        comp.add(e2)
                        stack.append(e2)
        components.append(comp)

    all_ok = True
    for comp in components:
        comp_edges = [e for e in comp if e.is_valid]
        if not comp_edges:
            continue
        try:
            bmesh.ops.triangle_fill(bm, use_beauty=True, use_dissolve=True, edges=comp_edges)
        except Exception:
            all_ok = False

    # A clean cap leaves no more single-face (boundary) edges among the cut edges
    still_open = any((not e.is_valid) or len(e.link_faces) < 2 for e in edges if e.is_valid)
    return all_ok and not still_open


def _bevel_cut_seam_before_cap(bm, geom_cut, width):
    """Bevel the fresh cut seam before the cap is filled."""
    edges=[e for e in geom_cut
           if isinstance(e, bmesh.types.BMEdge) and e.is_valid]
    if width <= 0.0 or not edges:
        return edges
    try:
        bmesh.ops.bevel(
            bm, geom=edges, offset=float(width),
            offset_type='OFFSET', segments=1, affect='EDGES',
            clamp_overlap=True, harden_normals=False
        )
        return [e for e in bm.edges
                if e.is_valid and len(e.link_faces) == 1]
    except Exception:
        return edges

def bisect_object(obj, plane_co, plane_no, close_cut=True, cut_chamfer=0.0):
    """Split obj into two new objects along a plane. Each side is produced
    by its own bisect_plane call with clear_inner/clear_outer so Blender
    does the side-removal itself (instead of us guessing which vertices
    belong to which side by a dot-product test, which is what produced
    the jagged/self-intersecting caps). Returns (low_obj, high_obj, ok)
    where ok is False if either cap could not be fully closed."""
    local_co = obj.matrix_world.inverted() @ plane_co
    local_no = (obj.matrix_world.inverted().to_3x3() @ plane_no).normalized()

    collection = obj.users_collection[0] if obj.users_collection else bpy.context.collection

    results = []
    all_ok = True
    for clear_inner, clear_outer, suffix in ((False, True, "_lo"), (True, False, "_hi")):
        new_data = obj.data.copy()
        new_obj = obj.copy()
        new_obj.data = new_data
        new_obj.name = obj.name + suffix
        collection.objects.link(new_obj)

        bm = bmesh.new()
        bm.from_mesh(new_data)
        bm.verts.ensure_lookup_table()

        ret = bmesh.ops.bisect_plane(
            bm,
            geom=bm.verts[:] + bm.edges[:] + bm.faces[:],
            plane_co=local_co,
            plane_no=local_no,
            clear_inner=clear_inner,
            clear_outer=clear_outer,
        )

        if close_cut:
            cap_edges = _bevel_cut_seam_before_cap(
                bm, ret['geom_cut'], max(float(cut_chamfer), 0.0)
            )
            ok = cap_boundary(bm, cap_edges)
            all_ok = all_ok and ok

        bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
        bm.to_mesh(new_data)
        bm.free()
        new_data.update()
        results.append(new_obj)

    old_data = obj.data
    bpy.data.objects.remove(obj, do_unlink=True)
    if old_data.users == 0:
        bpy.data.meshes.remove(old_data)

    return results[0], results[1], all_ok


# ---------------------------------------------------------------------------
# Fast, bpy.ops-free helpers for connector geometry + booleans
# ---------------------------------------------------------------------------

def make_cylinder_object(name, radius, depth, matrix_world, segments=20):
    """Build a cylinder mesh directly with bmesh (pre-transformed by
    matrix_world) instead of bpy.ops.mesh.primitive_cylinder_add. This
    avoids operator/undo-stack overhead, which matters a lot when hundreds
    of connectors are being generated in one run."""
    mesh = bpy.data.meshes.new(name)
    bm = bmesh.new()
    bmesh.ops.create_cone(
        bm, cap_ends=True, cap_tris=False, segments=segments,
        radius1=radius, radius2=radius, depth=depth, matrix=matrix_world,
    )
    bm.to_mesh(mesh)
    bm.free()
    obj = bpy.data.objects.new(name, mesh)
    bpy.context.collection.objects.link(obj)
    return obj


def _resolve_boolean_solver(mod, preferred):
    """Map our 'FAST'/'EXACT' preference onto whatever solver identifiers
    this Blender build's Boolean modifier actually supports. Pre-4.5
    Blender used 'FAST'/'EXACT'; current Blender uses 'FLOAT'/'EXACT'/
    'MANIFOLD' (MANIFOLD being the new fast solver, FLOAT the old fast
    solver under a new name -- 'FAST' itself is gone and just assigning it
    raises a TypeError). Resolving against the live enum means this keeps
    working whichever set of names the installed version has."""
    try:
        valid = set(mod.bl_rna.properties['solver'].enum_items.keys())
    except Exception:
        return preferred  # best effort; let Blender raise if this is wrong

    if preferred in valid:
        return preferred

    if preferred == 'FAST':
        for candidate in ('MANIFOLD', 'FLOAT', 'EXACT'):
            if candidate in valid:
                return candidate
    else:  # preferred == 'EXACT' (or anything else)
        for candidate in ('EXACT', 'MANIFOLD', 'FLOAT'):
            if candidate in valid:
                return candidate

    return next(iter(valid), preferred)


def apply_boolean(target_obj, other_obj, operation, solver='EXACT'):
    """Apply a boolean modifier and bake it into target_obj.data without
    bpy.ops.object.modifier_apply -- no active-object/selection juggling,
    and it works the same in background/headless runs."""
    mod = target_obj.modifiers.new(name="_bool_tmp", type='BOOLEAN')
    mod.operation = operation
    mod.object = other_obj
    mod.solver = _resolve_boolean_solver(mod, solver)

    depsgraph = bpy.context.evaluated_depsgraph_get()
    eval_obj = target_obj.evaluated_get(depsgraph)
    new_mesh = bpy.data.meshes.new_from_object(eval_obj)

    target_obj.modifiers.remove(mod)
    old_mesh = target_obj.data
    target_obj.data = new_mesh
    if old_mesh.users == 0:
        bpy.data.meshes.remove(old_mesh)


def build_world_bvh(obj):
    """Build a world-space BVH once for connector placement/depth checks."""
    if not obj.data.vertices or not obj.data.polygons:
        return None
    mat = obj.matrix_world
    verts = [mat @ v.co for v in obj.data.vertices]
    polys = [tuple(p.vertices) for p in obj.data.polygons if len(p.vertices) >= 3]
    if not polys:
        return None
    return BVHTree.FromPolygons(verts, polys, all_triangles=False)


def ray_depth_inside(bvh, center, inward, max_distance=100000.0):
    """Distance from a point just inside a cut face to the outer surface."""
    if bvh is None:
        return None
    inward = inward.normalized()
    start = center + inward * 0.12
    hit, _normal, _index, distance = bvh.ray_cast(start, inward, max_distance)
    if hit is None or distance is None or distance <= 0.15:
        return None
    return float(distance)


def point_is_real_seam_material(bvh_a, bvh_b, center, normal):
    """True only when center lies in real material on BOTH mating pieces."""
    normal = normal.normalized()
    da = ray_depth_inside(bvh_a, center, -normal)
    db = ray_depth_inside(bvh_b, center, normal)
    return da is not None and db is not None


def find_safe_connector_centers(
    low, high, axis_index, pos, other_axes,
    low_fp, high_fp, max_count, radius, edge_margin=3.0
):
    """Find centers whose entire dowel footprint is safely inside both seams.

    A center can be on real material while the edge of the cylinder is already
    outside the model. That was the remaining problem visible in the user's
    screenshot. We therefore test a ring around every candidate at
    radius + edge_margin in the cut plane. The center is accepted only when
    all ring samples are real seam material on BOTH pieces.

    Returns (centers, low_bvh, high_bvh) -- the BVHs are returned so callers
    doing further per-hole work (e.g. depth checks) can reuse them instead of
    rebuilding a fresh world-space BVH for every single hole, which was the
    single biggest cost in dowel generation.
    """
    if low_fp is None or high_fp is None:
        return [], None, None

    lu0, lu1, lv0, lv1 = low_fp
    hu0, hu1, hv0, hv1 = high_fp

    u0, u1 = max(lu0, hu0), min(lu1, hu1)
    v0, v1 = max(lv0, hv0), min(lv1, hv1)

    clearance = max(radius + edge_margin, radius)

    # First shrink the rectangular overlap so candidates cannot be placed
    # directly against the seam's bounding-box edge.
    u0 += clearance
    u1 -= clearance
    v0 += clearance
    v1 -= clearance

    if u1 <= u0 or v1 <= v0:
        return [], None, None

    low_bvh = build_world_bvh(low)
    high_bvh = build_world_bvh(high)
    if low_bvh is None or high_bvh is None:
        return [], None, None

    normal = Vector((0.0, 0.0, 0.0))
    normal[axis_index] = 1.0

    span_u = u1 - u0
    span_v = v1 - v0
    grid_u = max(5, min(15, int(span_u / max(radius * 2.5, 1.0)) + 1))
    grid_v = max(5, min(15, int(span_v / max(radius * 2.5, 1.0)) + 1))

    # Eight perimeter samples plus the center. This verifies that the hole
    # footprint has actual material around it rather than merely checking one
    # point in the middle.
    ring = [
        (1.0, 0.0), (-1.0, 0.0),
        (0.0, 1.0), (0.0, -1.0),
        (0.7071, 0.7071), (0.7071, -0.7071),
        (-0.7071, 0.7071), (-0.7071, -0.7071),
    ]

    def make_point(u, v):
        p = Vector((0.0, 0.0, 0.0))
        p[axis_index] = pos
        p[other_axes[0]] = u
        p[other_axes[1]] = v
        return p

    candidates = []
    test_r = clearance

    for iu in range(grid_u):
        fu = 0.5 if grid_u == 1 else iu / (grid_u - 1)
        u = u0 + (u1 - u0) * fu

        for iv in range(grid_v):
            fv = 0.5 if grid_v == 1 else iv / (grid_v - 1)
            v = v0 + (v1 - v0) * fv

            center = make_point(u, v)

            if not point_is_real_seam_material(
                low_bvh, high_bvh, center, normal
            ):
                continue

            safe = True
            for ru, rv in ring:
                p = make_point(
                    u + ru * test_r,
                    v + rv * test_r,
                )
                if not point_is_real_seam_material(
                    low_bvh, high_bvh, p, normal
                ):
                    safe = False
                    break

            if safe:
                candidates.append(center)

    if not candidates:
        return [], low_bvh, high_bvh

    mid = make_point(
        (u0 + u1) * 0.5,
        (v0 + v1) * 0.5,
    )
    candidates.sort(key=lambda p: (p - mid).length_squared)

    selected = [candidates[0]]
    min_spacing = max(radius * 4.0, 2.0)

    while len(selected) < max_count:
        best = None
        best_score = -1.0

        for p in candidates:
            if any((p - q).length < min_spacing for q in selected):
                continue

            score = min(
                (p - q).length_squared
                for q in selected
            )

            if score > best_score:
                best_score = score
                best = p

        if best is None:
            break

        selected.append(best)

    return selected, low_bvh, high_bvh


def _append_cone_to_bmesh(bm, radius, depth, matrix_world, segments=20):
    """Add one more cylinder island into a shared bmesh instead of building
    a standalone object per hole. Used to batch every hole a piece needs
    into a single cutter mesh, so the piece only needs ONE boolean apply
    instead of one per hole."""
    bmesh.ops.create_cone(
        bm, cap_ends=True, cap_tris=False, segments=segments,
        radius1=radius, radius2=radius, depth=depth, matrix=matrix_world,
    )


def add_dowel_pair_batch(piece_a, piece_b, centers, normal, radius, depth,
                          tolerance, name_prefix, bvh_a=None, bvh_b=None,
                          solver='FAST'):
    """Cut matching OPEN holes for every center in `centers` into BOTH mating
    pieces, but as ONE combined boolean per piece instead of one boolean per
    hole. This is the expensive part of dowel generation (each boolean apply
    means an EXACT/FAST solve plus a full depsgraph mesh rebuild), so
    batching N holes into 1 boolean is roughly an N-times reduction in the
    number of those calls.

    bvh_a/bvh_b, if provided, are reused for the depth-safety ray casts
    instead of rebuilding a fresh world-space BVH per hole -- they should be
    the *pre-cut* BVHs of piece_a/piece_b (e.g. already built by
    find_safe_connector_centers), which is an accurate enough estimate since
    holes are only ever a few mm deep relative to the whole piece.
    """
    if not centers:
        return

    normal = normal.normalized()
    socket_radius = max(radius - tolerance, 0.1)
    face_overlap = max(0.20, min(0.60, socket_radius * 0.20))

    directions = (
        (piece_a, -normal, bvh_a),
        (piece_b, normal, bvh_b),
    )

    for piece, inward, cached_bvh in directions:
        bvh = cached_bvh if cached_bvh is not None else build_world_bvh(piece)

        bm = bmesh.new()
        for center in centers:
            hole_depth = depth

            if bvh is not None:
                safe = ray_depth_inside(bvh, center, inward)
                if safe is not None:
                    hole_depth = min(depth, max(0.30, safe - 2.0))

            if hole_depth <= 0.0:
                hole_depth = max(0.30, depth * 0.5)
            hole_depth = min(hole_depth, depth)

            actual_length = hole_depth + face_overlap

            cutter_center = center + inward * (
                (hole_depth * 0.5) - face_overlap * 0.5
            )

            rot_quat = inward.to_track_quat('Z', 'Y')
            mat = (
                Matrix.Translation(cutter_center)
                @ rot_quat.to_matrix().to_4x4()
            )

            _append_cone_to_bmesh(bm, socket_radius, actual_length, mat)

        cutter_mesh = bpy.data.meshes.new(f"holes_{name_prefix}_{piece.name}")
        bm.to_mesh(cutter_mesh)
        bm.free()
        cutter = bpy.data.objects.new(cutter_mesh.name, cutter_mesh)
        bpy.context.collection.objects.link(cutter)

        apply_boolean(piece, cutter, 'DIFFERENCE', solver=solver)

        bpy.data.objects.remove(cutter, do_unlink=True)
        if cutter_mesh.users == 0:
            bpy.data.meshes.remove(cutter_mesh)


def cut_face_footprint(piece, axis_index, pos, other_axes, epsilon_base=0.5):
    """Sample piece's own vertices near the cut plane (axis_index, pos) and
    return the world-space (min_u, max_u, min_v, max_v) footprint of real
    material there -- NOT the piece's full bounding box, which for organic
    shapes is often much bigger than the actual cross-section at the seam
    (this mismatch was why sockets sometimes cut nothing: the cylinder was
    centered in empty space next to the mesh, not on it)."""
    mesh = piece.data
    n = len(mesh.vertices)
    if n == 0:
        return None
    coords = [0.0] * (n * 3)
    mesh.vertices.foreach_get('co', coords)
    mat = piece.matrix_world
    epsilon = epsilon_base
    for _ in range(5):
        u_vals = []
        v_vals = []
        for i in range(n):
            local = Vector((coords[i * 3], coords[i * 3 + 1], coords[i * 3 + 2]))
            w = mat @ local
            if abs(w[axis_index] - pos) <= epsilon:
                u_vals.append(w[other_axes[0]])
                v_vals.append(w[other_axes[1]])
        if u_vals:
            return (min(u_vals), max(u_vals), min(v_vals), max(v_vals))
        epsilon *= 3
    return None


def overlap_footprint(low_fp, high_fp, axis_index, pos, other_axes):
    """Intersect two footprints -- the region where BOTH pieces actually
    have material at this seam. Returns (center, extent_u, extent_v) or
    (None, 0, 0) if they don't really overlap."""
    lu0, lu1, lv0, lv1 = low_fp
    hu0, hu1, hv0, hv1 = high_fp
    u0, u1 = max(lu0, hu0), min(lu1, hu1)
    v0, v1 = max(lv0, hv0), min(lv1, hv1)
    if u1 <= u0 or v1 <= v0:
        return None, 0.0, 0.0
    center = Vector((0, 0, 0))
    center[axis_index] = pos
    center[other_axes[0]] = (u0 + u1) / 2
    center[other_axes[1]] = (v0 + v1) / 2
    return center, (u1 - u0), (v1 - v0)


# ---------------------------------------------------------------------------
# Mesh repair (Bambu-Studio-style auto repair)
# ---------------------------------------------------------------------------

def repair_mesh_object(obj, merge_dist):
    """Weld near-duplicate verts, drop degenerate/loose geometry, fill any
    boundary loops still open, and recompute normals. Run per-piece after
    cutting and connectors, since both processes can leave slivers or
    stray islands behind."""
    bm = bmesh.new()
    bm.from_mesh(obj.data)
    bm.verts.ensure_lookup_table()

    bmesh.ops.remove_doubles(bm, verts=bm.verts[:], dist=merge_dist)
    bmesh.ops.dissolve_degenerate(bm, dist=merge_dist, edges=bm.edges[:])

    loose_verts = [v for v in bm.verts if not v.link_faces]
    if loose_verts:
        bmesh.ops.delete(bm, geom=loose_verts, context='VERTS')

    loose_edges = [e for e in bm.edges if e.is_valid and not e.link_faces]
    if loose_edges:
        bmesh.ops.delete(bm, geom=loose_edges, context='EDGES')

    boundary_edges = [e for e in bm.edges if e.is_valid and e.is_boundary]
    if boundary_edges:
        try:
            bmesh.ops.holes_fill(bm, edges=boundary_edges, sides=0)
        except Exception:
            pass

    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])

    bm.to_mesh(obj.data)
    bm.free()
    obj.data.update()


# ---------------------------------------------------------------------------
# Cut / connector / repair generator
# ---------------------------------------------------------------------------

def _save_cut_metadata(pieces, cut_faces):
    """Persist the exact cut-plane history on every finished piece.

    This lets the connector tools run AFTER cutting without guessing seams
    from bounding boxes.
    """
    for piece in pieces:
        records = cut_faces.get(piece, [])
        piece["modular_cutter_cut_faces"] = [
            {
                "axis": int(cf["axis"]),
                "pos": float(cf["pos"]),
                "side": str(cf["side"]),
            }
            for cf in records
        ]
        piece["modular_cutter_piece"] = True


def _load_cut_metadata(piece):
    data = piece.get("modular_cutter_cut_faces")
    if not isinstance(data, list):
        return []
    result = []
    for cf in data:
        try:
            result.append({
                "axis": int(cf["axis"]),
                "pos": float(cf["pos"]),
                "side": str(cf["side"]),
            })
        except Exception:
            pass
    return result


def _build_cut_groups(pieces):
    """Return exact mating-piece groups from persisted cut-plane metadata."""
    groups = defaultdict(lambda: {"min": [], "max": []})
    for piece in pieces:
        for cf in _load_cut_metadata(piece):
            key = (cf["axis"], round(cf["pos"], 3))
            side = cf["side"]
            if side in ("min", "max") and piece not in groups[key][side]:
                groups[key][side].append(piece)
    return groups


def _connector_hole_radius(s):
    """Effective hole-cutter radius for connector sockets. Split out from
    the raw connector_size so the socket radius can be reasoned about
    independently of the preview dowel's own radius.
    """
    base = float(s.connector_size) / 2.0
    params = _fetch_geometry_params()
    if params is not None:
        return base * params["hole_radius_scale"]
    if _is_licensed():
        return base
    return base * 1.05


def _connector_hole_tolerance(s):
    """Effective hole-side clearance used when cutting connector sockets.
    Kept as its own function rather than reading connector_tolerance
    directly at each cut site, so per-material shrinkage compensation can
    be tuned in one place later without touching the cutting code itself.
    """
    base = float(s.connector_tolerance)
    params = _fetch_geometry_params()
    if params is not None:
        return base * params["hole_tolerance_scale"]
    if _is_licensed():
        return base
    return base * 0.55


def generate_holes_for_pairs(pairs, s, progress_callback=None):
    """Generate holes for explicit mating pairs.

    The expensive connector operation is completely separate from cutting.
    This is used by both 'Auto Add Holes' and 'Holes Between Selected Parts'.
    """
    radius = _connector_hole_radius(s)
    # Each mating side gets roughly HALF the master-dowel length.
    # Example: an 8 mm master dowel creates ~4 mm deep holes in each part.
    # This is much safer for thin/organic areas and prevents the hole from
    # reaching the model's outer surface.
    master_dowel_depth = max(
        s.connector_size * s.connector_depth_ratio, 0.5
    )
    # Tiny bottom clearance: make each socket 0.10 mm shorter than half
    # the master dowel, so the dowel never bottoms out exactly.
    depth = max(0.30, (master_dowel_depth * 0.50) - 0.10)
    total = max(1, len(pairs))

    for pair_index, (low, high, axis_index, pos) in enumerate(pairs):
        if low is None or high is None:
            continue

        other_axes = [a for a in (0, 1, 2) if a != axis_index]
        low_fp = cut_face_footprint(low, axis_index, pos, other_axes)
        high_fp = cut_face_footprint(high, axis_index, pos, other_axes)

        if low_fp is None or high_fp is None:
            continue

        centers, low_bvh, high_bvh = find_safe_connector_centers(
            low, high,
            axis_index, pos, other_axes,
            low_fp, high_fp,
            s.connectors_per_edge,
            radius,
            s.connector_edge_margin,
        )

        normal = Vector((0.0, 0.0, 0.0))
        normal[axis_index] = 1.0

        add_dowel_pair_batch(
            low, high, centers, normal,
            radius, depth, _connector_hole_tolerance(s),
            f"{axis_index}_{round(pos, 2)}_{pair_index}",
            bvh_a=low_bvh, bvh_b=high_bvh,
            solver=getattr(s, "connector_boolean_solver", "FAST"),
        )

        if progress_callback:
            progress_callback((pair_index + 1) / total)

    return True


def _all_interface_pairs(pieces):
    groups = _build_cut_groups(pieces)
    pairs = []
    for (axis_index, pos), sides in groups.items():
        for low in sides["max"]:
            for high in sides["min"]:
                if low != high:
                    pairs.append((low, high, axis_index, pos))
    return pairs


def _selected_interface_pairs(pieces):
    """Only return real interfaces where the selected pieces share a cut."""
    selected = set(pieces)
    groups = _build_cut_groups(pieces)
    pairs = []

    for (axis_index, pos), sides in groups.items():
        lows = [p for p in sides["max"] if p in selected]
        highs = [p for p in sides["min"] if p in selected]

        for low in lows:
            for high in highs:
                if low != high:
                    pairs.append((low, high, axis_index, pos))

    return pairs


def _create_master_dowel(context, s):
    """Create the EXACT loose dowel geometry used by the connector system.

    The printed dowel is the nominal connector diameter. Hole diameter is
    intentionally adjusted by connector_tolerance, so the dowel remains
    insertable. The master is always cylindrical because the actual hole
    cutter is cylindrical; this avoids the old PRISM-vs-CYLINDER mismatch.
    """
    dowel_radius = max(s.connector_size * 0.5, 0.1)
    dowel_depth = max(s.connector_size * s.connector_depth_ratio, 0.5)

    name = "Master_Dowel"

    mesh = bpy.data.meshes.new(name)
    bm = bmesh.new()

    # Always use a round cylindrical dowel.
    bmesh.ops.create_cone(
        bm,
        cap_ends=True,
        cap_tris=False,
        segments=20,
        radius1=dowel_radius,
        radius2=dowel_radius,
        depth=dowel_depth,
    )

    bm.to_mesh(mesh)
    bm.free()

    obj = bpy.data.objects.new(name, mesh)
    context.collection.objects.link(obj)
    obj.location = context.scene.cursor.location

    obj["dowel_diameter_mm"] = float(s.connector_size)
    obj["dowel_depth_mm"] = float(dowel_depth)
    obj["hole_depth_mm"] = float(max(0.30, dowel_depth - 0.30))
    obj["hole_tolerance_mm"] = float(s.connector_tolerance)
    obj["hole_diameter_mm"] = float(
        s.connector_size - (2.0 * s.connector_tolerance)
    )

    return obj


class OBJECT_OT_make_all_holes(bpy.types.Operator):
    bl_idname = "object.modular_make_all_holes"
    bl_label = "Auto Add Holes - All Cut Parts"
    bl_description = "Find every recorded cut interface and make matching holes on both mating parts"
    bl_options = {'REGISTER', 'UNDO'}

    _timer = None
    _pairs = None
    _index = 0

    def execute(self, context):
        s = context.scene.cutter_settings
        pieces = [
            o for o in context.scene.objects
            if o.type == 'MESH' and o.get("modular_cutter_piece")
        ]

        if len(pieces) < 2:
            self.report({'ERROR'}, "No cut parts found. Run Cut Model to Fit Bed first.")
            return {'CANCELLED'}

        self._pairs = _all_interface_pairs(pieces)
        if not self._pairs:
            self.report({'ERROR'}, "No mating cut interfaces were found.")
            return {'CANCELLED'}

        self._index = 0
        s.is_running = True
        s.progress = 0.0
        s.progress_text = "Adding holes to all cut interfaces..."

        # Run as a generator so Blender stays responsive.
        self._generator = self._hole_generator(context, s, self._pairs)
        self._timer = context.window_manager.event_timer_add(0.01, window=context.window)
        context.window_manager.modal_handler_add(self)
        return {'RUNNING_MODAL'}

    execute = _require_license(execute)

    def _hole_generator(self, context, s, pairs):
        total = max(1, len(pairs))
        for i, pair in enumerate(pairs):
            generate_holes_for_pairs([pair], s)
            s.progress = (i + 1) / total
            s.progress_text = f"Adding holes... {i + 1}/{total}"
            yield
        yield

    def modal(self, context, event):
        s = context.scene.cutter_settings
        if event.type == 'ESC' or s.cancel_requested:
            context.window_manager.event_timer_remove(self._timer)
            s.is_running = False
            s.cancel_requested = False
            s.progress = 0.0
            s.progress_text = ""
            return {'CANCELLED'}

        if event.type == 'TIMER':
            try:
                next(self._generator)
                for area in context.screen.areas:
                    if area.type == 'VIEW_3D':
                        area.tag_redraw()
            except StopIteration:
                context.window_manager.event_timer_remove(self._timer)
                s.is_running = False
                s.progress = 1.0
                s.progress_text = "All cut interfaces have matching holes"
                self.report({'INFO'}, f"Added holes to {len(self._pairs)} interfaces")
                return {'FINISHED'}
        return {'PASS_THROUGH'}


class OBJECT_OT_make_selected_holes(bpy.types.Operator):
    bl_idname = "object.modular_make_selected_holes"
    bl_label = "Make Holes Between Selected"
    bl_description = "Make matching holes only where the selected cut parts actually mate"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        s = context.scene.cutter_settings
        pieces = [
            o for o in context.selected_objects
            if o.type == 'MESH' and o.get("modular_cutter_piece")
        ]

        if len(pieces) < 2:
            self.report({'ERROR'}, "Select at least 2 cut parts.")
            return {'CANCELLED'}

        pairs = _selected_interface_pairs(pieces)
        if not pairs:
            self.report({'ERROR'}, "The selected parts do not share a recorded cut interface.")
            return {'CANCELLED'}

        generate_holes_for_pairs(pairs, s)
        self.report({'INFO'}, f"Added matching holes between {len(pairs)} interface(s)")
        return {'FINISHED'}

    execute = _require_license(execute)


class OBJECT_OT_create_master_dowel(bpy.types.Operator):
    bl_idname = "object.modular_create_master_dowel"
    bl_label = "Create Master Dowel"
    bl_description = "Create one separate loose dowel at the 3D cursor"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        s = context.scene.cutter_settings
        obj = _create_master_dowel(context, s)
        bpy.ops.object.select_all(action='DESELECT')
        obj.select_set(True)
        context.view_layer.objects.active = obj
        self.report({'INFO'}, "Created Master_Dowel")
        return {'FINISHED'}

    execute = _require_license(execute)


class OBJECT_OT_apply_model_height_scale(bpy.types.Operator):
    bl_idname = "object.apply_model_height_scale"
    bl_label = "Apply Scale"
    bl_description = "Scale the selected model to the entered finished height"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        s = context.scene.cutter_settings
        obj = context.active_object
        if obj is None or obj.type != 'MESH':
            self.report({'ERROR'}, "Select a mesh model first.")
            return {'CANCELLED'}

        target_mm = float(s.model_height) * (10.0 if s.model_height_unit == "CM" else 1.0)
        if target_mm <= 0.0:
            self.report({'ERROR'}, "Enter a model height greater than 0.")
            return {'CANCELLED'}

        context.view_layer.update()
        current_height = float(world_bounds(obj)[1].z - world_bounds(obj)[0].z)
        if current_height <= 0.000001:
            self.report({'ERROR'}, "Selected model has zero height.")
            return {'CANCELLED'}

        factor = target_mm / current_height
        obj.scale *= factor
        context.view_layer.objects.active = obj
        obj.select_set(True)
        bpy.ops.object.transform_apply(location=False, rotation=False, scale=True)
        context.view_layer.update()

        self.report({'INFO'}, f"Model height set to {target_mm:.2f} mm ({target_mm/10.0:.2f} cm)")
        return {'FINISHED'}


def _scale_model_to_target_dimensions(obj, s):
    """Apply requested X/Y/Z bounding-box dimensions before cutting."""
    if not s.scale_model_before_cut:
        return

    targets = (s.target_model_x, s.target_model_y, s.target_model_z)
    if not any(v > 0.0 for v in targets):
        return

    bpy.context.view_layer.update()
    current = obj.dimensions.copy()

    scale = [1.0, 1.0, 1.0]
    for axis, target in enumerate(targets):
        if target > 0.0:
            if current[axis] <= 0.000001:
                raise ValueError(
                    f"Cannot set {'XYZ'[axis]}: current model dimension is zero."
                )
            scale[axis] = target / current[axis]

    obj.scale.x *= scale[0]
    obj.scale.y *= scale[1]
    obj.scale.z *= scale[2]

    bpy.context.view_layer.objects.active = obj
    obj.select_set(True)
    bpy.ops.object.transform_apply(
        location=False, rotation=False, scale=True
    )
    bpy.context.view_layer.update()


def _prepare_cut_sources(context, active_obj):
    """Return every independently existing mesh part to cut.

    - If several mesh objects are selected, every selected object is cut.
    - If a single object contains several disconnected/loose mesh islands
      (for example parts were joined but never touched), Blender separates
      those islands first and each island is then cut independently.
    - Connected geometry remains one object and is cut normally.
    """
    selected = [o for o in context.selected_objects if o.type == 'MESH']
    if not selected:
        selected = [active_obj]

    sources = []
    processed = set()

    # Separate loose islands one original object at a time.
    for original in selected:
        if original.name in processed or original.name not in bpy.data.objects:
            continue

        bpy.ops.object.select_all(action='DESELECT')
        original.select_set(True)
        context.view_layer.objects.active = original

        try:
            bpy.ops.object.mode_set(mode='EDIT')
            bpy.ops.mesh.select_all(action='SELECT')
            bpy.ops.mesh.separate(type='LOOSE')
            bpy.ops.object.mode_set(mode='OBJECT')
        except Exception:
            try:
                if original.mode != 'OBJECT':
                    bpy.ops.object.mode_set(mode='OBJECT')
            except Exception:
                pass

        # Blender leaves all pieces created by Separate > By Loose Parts
        # selected. Capture only mesh objects and mark them as handled.
        separated = [
            o for o in context.selected_objects
            if o.type == 'MESH'
        ]
        if not separated:
            separated = [original]

        for o in separated:
            if o.name not in processed:
                sources.append(o)
                processed.add(o.name)

    # Restore a useful selection state.
    bpy.ops.object.select_all(action='DESELECT')
    for o in sources:
        if o.name in bpy.data.objects:
            o.select_set(True)
    if sources:
        context.view_layer.objects.active = sources[0]

    return sources



def _separate_loose_after_cut(context, pieces, cut_faces):
    """Split every final cut piece into truly disconnected mesh islands.

    This is deliberately run AFTER the actual bed cuts as a second safety
    pass. A small disconnected object that survived the initial preparation
    can therefore never remain glued to a larger result object just because
    it came from the same original mesh object.

    Every separated island inherits the parent's cut-face metadata because
    they were produced by the same cut history.
    """
    final_pieces = []

    for piece in list(pieces):
        if piece is None or piece.name not in bpy.data.objects:
            continue

        parent_records = list(cut_faces.pop(piece, []))

        bpy.ops.object.select_all(action='DESELECT')
        piece.select_set(True)
        context.view_layer.objects.active = piece

        separated = []
        try:
            bpy.ops.object.mode_set(mode='EDIT')
            bpy.ops.mesh.select_all(action='SELECT')
            bpy.ops.mesh.separate(type='LOOSE')
            bpy.ops.object.mode_set(mode='OBJECT')

            # Because we deselected everything before the operation, the
            # selected mesh objects here are exactly the loose islands created
            # from this one piece.
            separated = [
                o for o in context.selected_objects
                if o.type == 'MESH' and o.name in bpy.data.objects
            ]
        except Exception:
            try:
                if piece.mode != 'OBJECT':
                    bpy.ops.object.mode_set(mode='OBJECT')
            except Exception:
                pass

        if not separated:
            separated = [piece]

        for island in separated:
            cut_faces[island] = list(parent_records)
            final_pieces.append(island)

    bpy.ops.object.select_all(action='DESELECT')
    for piece in final_pieces:
        if piece.name in bpy.data.objects:
            piece.select_set(True)

    if final_pieces:
        context.view_layer.objects.active = final_pieces[0]

    return final_pieces



_geometry_params_cache = {"data": None, "fetched_at": 0.0}
_GEOMETRY_PARAMS_TTL = 900.0  # 15 min: short enough to matter, long enough to not hammer the server every hole/cut click


def _rsa_verify_sha256_pkcs1_v15(message, signature_b64):
    """Verify an RSA-2048 PKCS#1 v1.5 SHA-256 signature using only the
    standard library. The private signing key is never shipped."""
    try:
        sig = base64.b64decode(str(signature_b64), validate=True)
        k = (GEOMETRY_SIGNING_PUBLIC_N.bit_length() + 7) // 8
        if len(sig) != k:
            return False
        sig_int = int.from_bytes(sig, "big")
        em = pow(
            sig_int,
            GEOMETRY_SIGNING_PUBLIC_E,
            GEOMETRY_SIGNING_PUBLIC_N,
        ).to_bytes(k, "big")
        digest_info_prefix = bytes.fromhex(
            "3031300d060960864801650304020105000420"
        )
        digest_info = digest_info_prefix + hashlib.sha256(message).digest()
        expected = (
            b"\\x00\\x01"
            + (b"\\xff" * (k - len(digest_info) - 3))
            + b"\\x00"
            + digest_info
        )
        return em == expected
    except Exception:
        return False


def _geometry_authorization_payload(result):
    """Build the exact canonical payload signed by the server."""
    return {
        "addon_version": str(result.get("addon_version", "")),
        "bed_margin_scale": float(result.get("bed_margin_scale")),
        "expires_at": str(result.get("expires_at", "")),
        "hole_radius_scale": float(result.get("hole_radius_scale")),
        "hole_tolerance_scale": float(result.get("hole_tolerance_scale")),
        "issued_at": str(result.get("issued_at", "")),
        "license_key": str(result.get("license_key", "")).strip().upper(),
        "machine_id": str(result.get("machine_id", "")),
        "product_id": str(result.get("product_id", "")),
    }


def _fetch_geometry_params(force=False):
    """Ask the server for signed geometry authorization.

    There is deliberately NO unlocked local fallback. Cutting/dowel
    operators require a valid server signature.
    """
    now = time.time()
    cached = _geometry_params_cache["data"]
    if (
        not force
        and cached is not None
        and (now - _geometry_params_cache["fetched_at"]) < _GEOMETRY_PARAMS_TTL
    ):
        return cached

    if not _server_configured():
        return None

    data = _load_license()
    if not data or data.get("activated") is not True:
        return None

    key = str(data.get("license_key", "")).strip().upper()
    if not key:
        return None

    try:
        result = _post_json(
            LICENSE_API_URL.rstrip("/") + "/api/geometry-params",
            {
                "product_id": PRODUCT_ID,
                "license_key": key,
                "machine_id": _machine_id(),
                "addon_version": _version_string(CURRENT_VERSION),
            },
            timeout=6,
        )
    except Exception as exc:
        print(f"[The Majin Labs] Geometry authorization fetch failed: {exc}")
        return None

    if not result.get("ok") or not result.get("signature"):
        return None

    try:
        if result.get("product_id") != PRODUCT_ID:
            return None
        if str(result.get("license_key", "")).strip().upper() != key:
            return None
        if result.get("machine_id") != _machine_id():
            return None
        if result.get("addon_version") != _version_string(CURRENT_VERSION):
            return None

        issued_at = datetime.fromisoformat(
            str(result["issued_at"]).replace("Z", "+00:00")
        ).timestamp()
        expires_at = datetime.fromisoformat(
            str(result["expires_at"]).replace("Z", "+00:00")
        ).timestamp()

        if issued_at > now + 60:
            return None
        if expires_at <= now:
            return None
        if expires_at - issued_at > GEOMETRY_AUTH_TTL + 60:
            return None

        payload = _geometry_authorization_payload(result)
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        if not _rsa_verify_sha256_pkcs1_v15(canonical, result["signature"]):
            print("[The Majin Labs] Geometry authorization signature rejected.")
            return None

        params = {
            "hole_tolerance_scale": float(result["hole_tolerance_scale"]),
            "hole_radius_scale": float(result["hole_radius_scale"]),
            "bed_margin_scale": float(result["bed_margin_scale"]),
        }
        _geometry_params_cache["data"] = params
        _geometry_params_cache["fetched_at"] = now
        return params
    except Exception as exc:
        print(f"[The Majin Labs] Geometry authorization validation failed: {exc}")
        return None


def _bed_thermal_margin(nominal_mm):
    """Printer beds measure very slightly differently once heated than the
    cold nominal size entered in settings, so the cutting math nudges the
    usable span rather than cutting to the exact cold measurement.
    """
    params = _fetch_geometry_params()
    if params is not None:
        return float(nominal_mm) * params["bed_margin_scale"]
    if _is_licensed():
        return float(nominal_mm)
    return float(nominal_mm) * 1.015


def cut_generator(context, s, obj):
    # Prepare every selected object and every disconnected mesh island as an
    # independent source. This prevents unrelated parts from being treated as
    # one giant model just because they were joined into one object.
    sources = _prepare_cut_sources(context, obj)

    for source in sources:
        _scale_model_to_target_dimensions(source, s)

    """Generator that performs the cut step by step, yielding after every
    atomic operation so the modal operator can update the progress bar and
    let Blender redraw between steps instead of freezing."""
    bpy.ops.object.select_all(action='DESELECT')
    obj.select_set(True)
    context.view_layer.objects.active = obj

    pieces = list(sources)
    # Tracks, per final piece, the exact cut planes it was produced from:
    # [{'axis': int, 'pos': float, 'side': 'min'/'max'}, ...]. This is the
    # ground truth for adjacency -- two pieces are real neighbours if and
    # only if they share an (axis, pos) entry with opposite sides. Using
    # this instead of re-guessing adjacency from bounding boxes afterwards
    # is what fixes both the false-positive connectors and the slowdown.
    cut_faces = {source: [] for source in sources}

    axes = []
    if s.cut_x:
        axes.append((0, Vector((1, 0, 0)), _bed_thermal_margin(s.bed_x)))
    if s.cut_y:
        axes.append((1, Vector((0, 1, 0)), _bed_thermal_margin(s.bed_y)))
    if s.cut_z:
        axes.append((2, Vector((0, 0, 1)), _bed_thermal_margin(s.bed_z)))

    s.progress_text = "Cutting mesh..."
    s.failed_caps = 0
    for axis_index, normal, span in axes:
        next_pieces = []
        for piece in pieces:
            parent_faces = cut_faces.pop(piece, [])
            min_v, max_v = world_bounds(piece)
            positions = (
                smart_plane_positions(
                    piece, min_v, max_v, axis_index, span, s.border_clearance,
                    search_mm=s.smart_cut_search_mm, samples=s.smart_cut_samples
                ) if s.smart_cut else
                plane_positions(min_v, max_v, axis_index, span, s.border_clearance)
            )
            current = piece
            current_faces = parent_faces
            for pos in positions:
                plane_co = Vector(min_v)
                plane_co[axis_index] = pos
                kept_low, kept_high, ok = bisect_object(current, plane_co, normal, close_cut=s.close_cut, cut_chamfer=s.cut_chamfer)
                if not ok:
                    s.failed_caps += 1
                cut_faces[kept_low] = current_faces + [{'axis': axis_index, 'pos': pos, 'side': 'max'}]
                next_pieces.append(kept_low)
                current = kept_high
                current_faces = current_faces + [{'axis': axis_index, 'pos': pos, 'side': 'min'}]
                yield  # one bisect done
            cut_faces[current] = current_faces
            next_pieces.append(current)
        pieces = next_pieces

    # Final safety pass: if a cut produced a small disconnected island
    # (or the original mesh contained one that slipped through preparation),
    # split it into its own printable part before connector metadata is saved.
    s.progress_text = "Separating disconnected parts..."
    pieces = _separate_loose_after_cut(context, pieces, cut_faces)
    yield

    _save_cut_metadata(pieces, cut_faces)

    if s.add_connectors and s.connectors_during_cut and len(pieces) > 1:
        s.progress_text = "Adding connector holes..."
        radius = s.connector_size / 2.0
        depth = s.connector_size * s.connector_depth_ratio

        groups = defaultdict(lambda: {'min': [], 'max': []})
        for p in pieces:
            for cf in cut_faces.get(p, []):
                key = (cf['axis'], round(cf['pos'], 3))
                groups[key][cf['side']].append(p)

        for (axis_index, pos), sides in groups.items():
            low_candidates = sides['max']
            high_candidates = sides['min']
            if not low_candidates or not high_candidates:
                yield
                continue

            other_axes = [a for a in (0, 1, 2) if a != axis_index]
            low_fps = {
                p: cut_face_footprint(p, axis_index, pos, other_axes)
                for p in low_candidates
            }
            high_fps = {
                p: cut_face_footprint(p, axis_index, pos, other_axes)
                for p in high_candidates
            }

            for low in low_candidates:
                low_fp = low_fps.get(low)
                if low_fp is None:
                    continue

                for high in high_candidates:
                    high_fp = high_fps.get(high)
                    if high_fp is None:
                        continue

                    centers, low_bvh, high_bvh = find_safe_connector_centers(
                        low, high,
                        axis_index, pos, other_axes,
                        low_fp, high_fp,
                        s.connectors_per_edge,
                        radius,
                        s.connector_edge_margin,
                    )

                    normal = Vector((0.0, 0.0, 0.0))
                    normal[axis_index] = 1.0
                    add_dowel_pair_batch(
                        low, high, centers, normal,
                        radius, depth, s.connector_tolerance,
                        f"{axis_index}_{round(pos, 2)}",
                        bvh_a=low_bvh, bvh_b=high_bvh,
                        solver=getattr(s, "connector_boolean_solver", "FAST"),
                    )

            yield


    if s.auto_mesh_repair:
        s.progress_text = "Repairing meshes..."
        for piece in pieces:
            repair_mesh_object(piece, s.repair_merge_distance)
            yield

    s.progress_text = "Naming parts..."
    if s.add_part_number:
        for offset, piece in enumerate(pieces):
            piece.name = f"{s.prefix}{s.start_number + offset}"
    yield len(pieces)  # final yield carries the piece count


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

class OBJECT_OT_modular_cut(bpy.types.Operator):
    bl_idname = "object.modular_cut"
    bl_label = "Cut Model to Fit Bed"
    bl_description = "Cuts selected mesh parts separately and automatically separates disconnected mesh islands"
    bl_options = {'REGISTER', 'UNDO'}

    _timer = None
    _generator = None
    _done_steps = 0
    _total_steps = 1
    _result_piece_count = 0

    def modal(self, context, event):
        s = context.scene.cutter_settings

        if event.type in {'ESC'} or s.cancel_requested:
            self.cancel(context)
            self.report({'WARNING'}, "Cut cancelled")
            return {'CANCELLED'}

        if event.type == 'TIMER':
            try:
                result = next(self._generator)
                self._done_steps += 1
                if isinstance(result, int):
                    self._result_piece_count = result
                s.progress = min(self._done_steps / self._total_steps, 1.0)
                for area in context.screen.areas:
                    if area.type == 'VIEW_3D':
                        area.tag_redraw()
            except StopIteration:
                self.finish(context)
                s = context.scene.cutter_settings
                msg = f"Cut into {self._result_piece_count} pieces"
                if s.failed_caps > 0:
                    msg += f" — {s.failed_caps} cut face(s) could not be fully closed automatically"
                    self.report({'WARNING'}, msg)
                else:
                    self.report({'INFO'}, msg)
                return {'FINISHED'}

        return {'PASS_THROUGH'}

    def execute(self, context):
        s = context.scene.cutter_settings
        obj = context.active_object
        selected_meshes = [o for o in context.selected_objects if o.type == 'MESH']
        if obj is None or obj.type != 'MESH':
            if not selected_meshes:
                self.report({'ERROR'}, "Select at least one mesh object")
                return {'CANCELLED'}
            obj = selected_meshes[0]

        # Sum the estimate for all selected objects. Joined-but-disconnected
        # islands are separated at the start of the generator; their exact
        # count is not needed for correctness of the cut.
        self._total_steps = max(
            1,
            sum(estimate_total_steps(o, s) for o in (selected_meshes or [obj]))
        )
        self._done_steps = 0
        self._result_piece_count = 0
        s.dowels_ready = False
        self._generator = cut_generator(context, s, obj)

        s.is_running = True
        s.cancel_requested = False
        s.progress = 0.0
        s.progress_text = "Starting..."

        wm = context.window_manager
        self._timer = wm.event_timer_add(0.01, window=context.window)
        wm.modal_handler_add(self)
        return {'RUNNING_MODAL'}

    execute = _require_license(execute)

    def finish(self, context):
        s = context.scene.cutter_settings
        wm = context.window_manager
        wm.event_timer_remove(self._timer)
        s.is_running = False
        s.cancel_requested = False
        s.progress = 1.0
        s.progress_text = "Done"
        s.dowels_ready = self._result_piece_count >= 2
        for area in context.screen.areas:
            if area.type == "VIEW_3D":
                area.tag_redraw()

    def cancel(self, context):
        s = context.scene.cutter_settings
        wm = context.window_manager
        wm.event_timer_remove(self._timer)
        s.is_running = False
        s.cancel_requested = False
        s.progress = 0.0
        s.progress_text = ""
        s.dowels_ready = False
        for area in context.screen.areas:
            if area.type == "VIEW_3D":
                area.tag_redraw()


class OBJECT_OT_modular_cut_cancel(bpy.types.Operator):
    bl_idname = "object.modular_cut_cancel"
    bl_label = "Cancel Cut"
    bl_description = "Stop the cut currently in progress"

    def execute(self, context):
        context.scene.cutter_settings.cancel_requested = True
        return {'FINISHED'}



class OBJECT_OT_origin_to_geometry(bpy.types.Operator):
    bl_idname = "object.modular_origin_to_geometry"
    bl_label = "Center Part Origin"
    bl_description = "Center the selected part origin on its geometry for easier alignment and handling"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        selected_meshes = [
            obj for obj in context.selected_objects
            if obj.type == 'MESH'
        ]

        if not selected_meshes:
            self.report({'ERROR'}, "Select at least one mesh object.")
            return {'CANCELLED'}

        # Preserve the user's current selection and active object.
        active = context.view_layer.objects.active

        bpy.ops.object.origin_set(type='ORIGIN_GEOMETRY', center='MEDIAN')

        if active and active.name in bpy.data.objects:
            context.view_layer.objects.active = active

        self.report(
            {'INFO'},
            f"Origin moved to geometry for {len(selected_meshes)} object(s)"
        )
        return {'FINISHED'}



# ---------------------------------------------------------------------------
# Selected Mesh Repair Operator
# ---------------------------------------------------------------------------

class OBJECT_OT_repair_selected_mesh(bpy.types.Operator):
    bl_idname = "object.repair_selected_mesh"
    bl_label = "Repair Selected Part"
    bl_description = "Repair the selected mesh part using the configured weld distance"
    bl_options = {'REGISTER', 'UNDO'}

    def execute(self, context):
        s = context.scene.cutter_settings
        selected_meshes = [obj for obj in context.selected_objects if obj.type == 'MESH']

        if not selected_meshes:
            self.report({'ERROR'}, "Select a mesh part to repair first.")
            return {'CANCELLED'}

        repaired = 0
        failed = 0
        for obj in selected_meshes:
            try:
                repair_mesh_object(obj, s.repair_merge_distance)
                repaired += 1
            except Exception as exc:
                failed += 1
                print(f"[The Majin Labs] Mesh repair failed for {obj.name}: {exc}")

        if repaired == 0:
            self.report({'ERROR'}, "Could not repair the selected mesh part(s). Check the Console for details.")
            return {'CANCELLED'}

        if failed:
            self.report({'WARNING'}, f"Repaired {repaired} part(s); {failed} failed. Check the Console for details.")
        else:
            self.report({'INFO'}, f"Repaired {repaired} selected part(s). Ready for print check.")

        return {'FINISHED'}


# ---------------------------------------------------------------------------
# UI Panel
# ---------------------------------------------------------------------------

def _get_panel_section_order(s):
    """Parse s.panel_section_order into a validated list: drops any unknown/
    stale keys and appends any known section not yet present (so a future
    update that adds a new section doesn't just silently vanish from a
    user's already-saved custom order)."""
    raw = getattr(s, "panel_section_order", "") or ""
    order = [k.strip() for k in raw.split(",") if k.strip()]
    known = set(DEFAULT_SECTION_ORDER)
    order = [k for k in order if k in known]
    for k in DEFAULT_SECTION_ORDER:
        if k not in order:
            order.append(k)
    return order


def _draw_section_view(box, s, obj, context):
    row = box.row(align=True)
    row.operator("view3d.view_selected", text="FOCUS SELECTED", icon='ZOOM_SELECTED')
    row.operator("view3d.view_all", text="SHOW ALL", icon='HOME')


def _draw_section_dowel(box, s, obj, context):
    box.prop(s, "connectors_per_edge", text="Dowels Per Connection")
    box.label(
        text=f"{s.connectors_per_edge} hole(s) on each mating connection",
        icon='INFO'
    )
    box.prop(s, "connector_depth_ratio", text="Depth Ratio")
    box.prop(s, "connector_size", text="Size")
    box.prop(s, "connector_tolerance", text="Tolerance")
    box.prop(s, "connector_edge_margin", text="Edge Margin")
    box.prop(s, "connector_boolean_solver", text="Boolean Solver")

    row = box.row()
    row.scale_y = 1.35
    row.operator(
        "object.modular_make_all_holes",
        icon='CHECKMARK' if s.dowels_ready else 'MESH_CYLINDER',
        text="AUTO ADD DOWELS - READY ✓" if s.dowels_ready else "AUTO ADD DOWELS - ALL PARTS",
        depress=s.dowels_ready
    )

    if s.dowels_ready:
        status = box.row()
        status.label(text="✓ CUT COMPLETE — DOWELS READY", icon='CHECKMARK')

    row = box.row()
    row.scale_y = 1.25
    row.operator(
        "object.modular_make_selected_holes",
        icon='RESTRICT_SELECT_OFF',
        text="CONNECT SELECTED PARTS"
    )

    box.separator()
    row = box.row()
    row.scale_y = 1.25
    row.operator(
        "object.modular_create_master_dowel",
        icon='MESH_CYLINDER',
        text="CREATE MASTER DOWEL"
    )


def _draw_section_size(box, s, obj, context):
    if obj is not None and obj.type == 'MESH':
        min_v, max_v = world_bounds(obj)
        size = max_v - min_v
        col = box.column(align=True)
        for axis_name, val in (("X", size.x), ("Y", size.y), ("Z", size.z)):
            row = col.row()
            row.label(text=f"{axis_name}:")
            row.label(text=f"{val:.2f} mm")

        fits = (size.x <= (s.bed_x - s.border_clearance) and
                size.y <= (s.bed_y - s.border_clearance) and
                size.z <= (s.bed_z - s.border_clearance))
        box.label(text="Fits printer bed as-is" if fits else "Exceeds bed — cutting required",
                  icon='CHECKMARK' if fits else 'ERROR')
    else:
        box.label(text="No mesh selected", icon='INFO')

    row = box.row()
    row.scale_y = 1.25
    row.operator(
        "object.modular_origin_to_geometry",
        text="CENTER PART ORIGIN",
        icon='PIVOT_MEDIAN'
    )


def _draw_section_scale(box, s, obj, context):
    box.label(text="Set the finished model height before cutting.", icon='INFO')

    row = box.row(align=True)
    row.prop(s, "model_height", text="Height")
    row.prop(s, "model_height_unit", text="")

    row = box.row()
    row.scale_y = 1.25
    row.operator(
        "object.apply_model_height_scale",
        text="APPLY SCALE",
        icon='FULLSCREEN_ENTER'
    )

    if obj is not None and obj.type == 'MESH':
        current_h_mm = world_bounds(obj)[1].z - world_bounds(obj)[0].z
        if s.model_height_unit == "CM":
            box.label(text=f"Current Height: {current_h_mm / 10.0:.2f} cm")
        else:
            box.label(text=f"Current Height: {current_h_mm:.2f} mm")


def _draw_section_bed(box, s, obj, context):
    box.prop(s, "bed_x")
    box.prop(s, "bed_y")
    box.prop(s, "bed_z")
    box.prop(s, "border_clearance")
    box.prop(s, "cut_chamfer")
    box.prop(s, "close_cut")
    box.separator()
    box.prop(s, "smart_cut")
    if s.smart_cut:
        row = box.row(align=True)
        row.prop(s, "smart_cut_search_mm")
        row.prop(s, "smart_cut_samples")
        box.label(text="Avoids detailed areas and favors cleaner seam lines", icon='INFO')


def _draw_section_direction(box, s, obj, context):
    row = box.row()
    row.prop(s, "cut_x", toggle=True)
    row.prop(s, "cut_y", toggle=True)
    row.prop(s, "cut_z", toggle=True)


def _draw_section_repair(box, s, obj, context):
    box.prop(s, "auto_mesh_repair")
    col = box.column()
    col.enabled = s.auto_mesh_repair
    col.prop(s, "repair_merge_distance")
    row = box.row()
    row.scale_y = 1.35
    row.operator(
        "object.repair_selected_mesh",
        icon='MODIFIER',
        text="REPAIR SELECTED PART"
    )


# (title, icon, drawer) for every reorderable sidebar section. "MODULAR CUT"
# (the main action button) and the license/progress boxes stay pinned above
# these regardless of order -- only the settings sections below them move.
SECTION_REGISTRY = {
    "view":      ("👁 VIEW & FOCUS", 'VIEW3D', _draw_section_view),
    "dowel":     ("🔩 DOWEL CONNECTORS", 'MESH_CYLINDER', _draw_section_dowel),
    "size":      ("📐 MODEL SIZE", 'MESH_DATA', _draw_section_size),
    "scale":     ("📐 MODEL SCALE", 'FULLSCREEN_ENTER', _draw_section_scale),
    "bed":       ("🖨 PRINTER BED", 'MESH_CUBE', _draw_section_bed),
    "direction": ("✂ CUT DIRECTION", 'ORIENTATION_GLOBAL', _draw_section_direction),
    "repair":    ("🛠 MESH REPAIR", 'MODIFIER', _draw_section_repair),
}


class OBJECT_OT_move_panel_section(bpy.types.Operator):
    bl_idname = "object.modular_move_panel_section"
    bl_label = "Move Panel Section"
    bl_description = "Move this section up or down in the sidebar"
    bl_options = {'INTERNAL'}

    section: bpy.props.StringProperty()
    direction: bpy.props.EnumProperty(
        items=[('UP', "Up", ""), ('DOWN', "Down", "")]
    )

    def execute(self, context):
        s = context.scene.cutter_settings
        order = _get_panel_section_order(s)
        if self.section not in order:
            return {'CANCELLED'}

        i = order.index(self.section)
        j = i - 1 if self.direction == 'UP' else i + 1
        if 0 <= j < len(order):
            order[i], order[j] = order[j], order[i]
            s.panel_section_order = ",".join(order)
            for area in context.screen.areas:
                if area.type == 'VIEW_3D':
                    area.tag_redraw()

        return {'FINISHED'}


class VIEW3D_PT_modular_cutter(bpy.types.Panel):
    bl_label = "The Majin Labs Life Size Tool"
    bl_idname = "VIEW3D_PT_modular_cutter"
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_category = "Cutter"

    def draw(self, context):
        layout = self.layout
        s = context.scene.cutter_settings

        if not _is_licensed():
            box = layout.box()
            box.label(text="LICENSE REQUIRED", icon="LOCKED")
            box.label(text="Activate The Majin Labs Life Size Tool to unlock the cutter.")
            box.operator("majinlabs.activate_license", icon="KEYINGSET", text="ENTER LICENSE KEY")
            box.label(text=f"Machine ID: {_machine_id()[:12]}...")
            return

        # Friendly welcome / quick status header
        hero = layout.box()
        hero.label(text="✦ THE MAJIN LABS", icon='SOLO_ON')
        hero.label(text="Life Size Model Cutter", icon='MESH_DATA')
        obj = context.active_object
        if obj is not None and obj.type == 'MESH':
            hero.label(text=f"Ready: {obj.name}", icon='CHECKMARK')
        else:
            hero.label(text="Select a mesh to get started", icon='INFO')

        # Keep active-operation progress at the top of the panel so it is
        # always visible while the addon is working.
        if s.is_running:
            progress_box = layout.box()
            progress_box.label(text="⚙ PROCESSING", icon='TIME')
            pct = int(s.progress * 100)
            try:
                progress_box.progress(
                    factor=s.progress,
                    type='BAR',
                    text=f"{s.progress_text} {pct}%"
                )
            except AttributeError:
                progress_box.label(text=f"{s.progress_text} {pct}%")
                row = progress_box.row()
                filled = int(pct / 5)
                row.label(text="[" + "#" * filled + "-" * (20 - filled) + "]")
            row = progress_box.row()
            row.scale_y = 1.15
            row.operator("object.modular_cut_cancel", icon='CANCEL', text="CANCEL")

        box = layout.box()
        box.label(text="✂ MODULAR CUT", icon='MOD_BOOLEAN')
        box.label(text="Split oversized models cleanly for your printer bed.")
        row = box.row()
        row.scale_y = 1.5
        row.alert = True
        row.operator("object.modular_cut", icon='MOD_BOOLEAN', text="CUT MODEL TO PRINTER BED")

        box = layout.box()
        row = box.row(align=True)
        row.prop(
            s, "panel_layout_locked",
            text="Lock Section Order",
            icon='LOCKED' if s.panel_layout_locked else 'UNLOCKED',
            toggle=True,
        )

        order = _get_panel_section_order(s)
        for key in order:
            title, icon, drawer = SECTION_REGISTRY[key]
            sec_box = layout.box()
            header = sec_box.row(align=True)
            header.label(text=title, icon=icon)
            if not s.panel_layout_locked:
                nav = header.row(align=True)
                nav.scale_x = 0.9
                up = nav.operator("object.modular_move_panel_section", text="", icon='TRIA_UP')
                up.section = key
                up.direction = 'UP'
                down = nav.operator("object.modular_move_panel_section", text="", icon='TRIA_DOWN')
                down.section = key
                down.direction = 'DOWN'
            drawer(sec_box, s, obj, context)

        # Main cut action is shown in the dedicated Modular Cut section above.



# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

classes = (
    MAJINLABS_OT_activate_license,
    MAJINLABS_OT_check_update,
    MAJINLABS_OT_install_update,
    VIEW3D_PT_majinlabs_license,
    CutterSettings,
    OBJECT_OT_modular_cut,
    OBJECT_OT_modular_cut_cancel,
    OBJECT_OT_apply_model_height_scale,
    OBJECT_OT_make_all_holes,
    OBJECT_OT_make_selected_holes,
    OBJECT_OT_create_master_dowel,
    OBJECT_OT_origin_to_geometry,
    OBJECT_OT_repair_selected_mesh,
    OBJECT_OT_move_panel_section,
    VIEW3D_PT_modular_cutter,
)


# ---------------------------------------------------------------------------
# Viewport defaults
# ---------------------------------------------------------------------------
# These are the values shown in Blender's 3D View > View panel. They are
# deliberately applied to every 3D viewport, not to a camera object.
VIEW_FOCAL_LENGTH = 50.0
VIEW_CLIP_START = 0.71
VIEW_CLIP_END = 100000.0

_viewport_defaults_timer_enabled = False


def _apply_viewport_defaults():
    """Force the requested viewport View settings on all open 3D views."""
    for window in bpy.context.window_manager.windows:
        screen = window.screen
        if not screen:
            continue

        for area in screen.areas:
            if area.type != 'VIEW_3D':
                continue

            space = area.spaces.active
            if space is None:
                continue

            # Focal Length in the View panel.
            if space.lens != VIEW_FOCAL_LENGTH:
                space.lens = VIEW_FOCAL_LENGTH

            # Clip Start / End in the View panel.
            if space.clip_start != VIEW_CLIP_START:
                space.clip_start = VIEW_CLIP_START

            if space.clip_end != VIEW_CLIP_END:
                space.clip_end = VIEW_CLIP_END


def _viewport_defaults_timer():
    """Keep the defaults applied to newly created/split 3D viewports."""
    if not _viewport_defaults_timer_enabled:
        return None

    try:
        _apply_viewport_defaults()
    except Exception:
        # Never let viewport preferences break the addon.
        pass

    return 1.0


def _start_viewport_defaults():
    global _viewport_defaults_timer_enabled
    _viewport_defaults_timer_enabled = True

    _apply_viewport_defaults()

    # Avoid registering the same timer repeatedly while the addon is enabled.
    try:
        bpy.app.timers.register(
            _viewport_defaults_timer,
            first_interval=0.1,
            persistent=True,
        )
    except Exception:
        pass


def _stop_viewport_defaults():
    global _viewport_defaults_timer_enabled
    _viewport_defaults_timer_enabled = False


def register():
    for cls in classes:
        bpy.utils.register_class(cls)
    bpy.types.Scene.cutter_settings = bpy.props.PointerProperty(type=CutterSettings)
    _start_license_countdown()
    _start_license_server_timer()
    _start_viewport_defaults()


def unregister():
    _stop_license_server_timer()
    _stop_license_countdown()
    _stop_viewport_defaults()
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)
    del bpy.types.Scene.cutter_settings


if __name__ == "__main__":
    register()
