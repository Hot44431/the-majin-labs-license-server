bl_info = {
    "name": "The Majin Labs Life Size Tool",
    "author": "Claude",
    "version": (4, 4, 1),
    "blender": (3, 6, 0),
    "location": "View3D > Sidebar > Cutter",
    "description": "Cuts an oversized mesh into printer-bed-sized pieces with dowel connectors and "
                    "auto mesh repair, like Luban's Modular Cut.",
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
import tempfile
import zipfile
import shutil
import time
import re
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
CURRENT_VERSION = (4, 4, 1)

LICENSE_API_URL = "https://the-majin-labs-license-server.onrender.com"
UPDATE_MANIFEST_URL = "https://the-majin-labs-license-server.onrender.com/update.json"

_LICENSE_FILE = "the_majin_labs_license.json"


def _version_string(version):
    return ".".join(str(v) for v in version)


def _license_path():
    base = bpy.utils.user_resource("CONFIG", path="the_majin_labs", create=True)
    return os.path.join(base, _LICENSE_FILE)


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
    try:
        with open(_license_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _license_duration_seconds(data):
    """Return test-license duration from the server-provided license name.

    Examples:
      "5 Minute Test License" -> 300 seconds
      "1 Hour Test License"   -> 3600 seconds
      "Demo Lifetime License" -> None
    """
    name = str(data.get("license_name", "") or "")
    lower = name.lower()

    if "lifetime" in lower or "permanent" in lower:
        return None

    match = re.search(r"(\d+(?:\.\d+)?)\s*(second|seconds|minute|minutes|hour|hours|day|days)", lower)
    if not match:
        return None

    value = float(match.group(1))
    unit = match.group(2)

    if unit.startswith("second"):
        multiplier = 1
    elif unit.startswith("minute"):
        multiplier = 60
    elif unit.startswith("hour"):
        multiplier = 3600
    else:
        multiplier = 86400

    return int(value * multiplier)


def _license_remaining_seconds(data=None):
    """Return remaining seconds using the server expiration when available."""
    data = data if isinstance(data, dict) else _load_license()

    # Prefer the server-authoritative expiration timestamp.
    expires_at = str(data.get("expires_at", "") or "")
    if expires_at:
        try:
            stamp = expires_at.replace("Z", "+00:00")
            from datetime import datetime, timezone
            expires = datetime.fromisoformat(stamp)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            return max(0, int(expires.timestamp() - time.time()))
        except Exception:
            pass

    # Fallback for older local license files that do not contain expires_at.
    duration = _license_duration_seconds(data)
    if duration is None:
        return None

    activated_at = str(data.get("activated_at", "") or "")
    if not activated_at:
        return None

    try:
        stamp = activated_at.replace("Z", "+00:00")
        from datetime import datetime, timezone
        activated = datetime.fromisoformat(stamp)
        if activated.tzinfo is None:
            activated = activated.replace(tzinfo=timezone.utc)
        elapsed = time.time() - activated.timestamp()
        return max(0, int(duration - elapsed))
    except Exception:
        return None


def _format_remaining(seconds):
    if seconds is None:
        return "LIFETIME"
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _expire_local_license_if_needed():
    """Remove an expired timed test license from the local machine."""
    data = _load_license()
    if not data or data.get("activated") is not True:
        return False

    remaining = _license_remaining_seconds(data)
    if remaining is not None and remaining <= 0:
        try:
            path = _license_path()
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return True

    return False


def _license_countdown_timer():
    """Refresh the license panel once per second and expire timed keys."""
    expired = _expire_local_license_if_needed()

    try:
        for window in bpy.context.window_manager.windows:
            screen = window.screen
            if not screen:
                continue
            for area in screen.areas:
                if area.type == "VIEW_3D":
                    area.tag_redraw()
    except Exception:
        pass

    return 1.0


def _start_license_countdown():
    try:
        if not bpy.app.timers.is_registered(_license_countdown_timer):
            bpy.app.timers.register(
                _license_countdown_timer,
                first_interval=1.0,
                persistent=True,
            )
    except Exception:
        pass


def _stop_license_countdown():
    try:
        if bpy.app.timers.is_registered(_license_countdown_timer):
            bpy.app.timers.unregister(_license_countdown_timer)
    except Exception:
        pass


def _save_license(data):
    path = _license_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = path + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(temp_path, path)


def _is_licensed():
    _expire_local_license_if_needed()
    data = _load_license()
    return (
        data.get("activated") is True
        and data.get("product_id") == PRODUCT_ID
        and data.get("machine_id") == _machine_id()
        and bool(data.get("license_key"))
    )


def _server_configured():
    return (
        LICENSE_API_URL.startswith("https://")
        and "YOUR-LICENSE-SERVER" not in LICENSE_API_URL
    )


def _post_json(url, payload, timeout=15):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"{PRODUCT_ID}/{_version_string(CURRENT_VERSION)}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _get_json(url, timeout=15):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"{PRODUCT_ID}/{_version_string(CURRENT_VERSION)}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


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
        return False, f"Could not contact license server: {exc}"

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
        "server_token": result.get("server_token", ""),
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

    # --- 3D Printer (matches Luban "Printer size X/Y/Z" = 320/320/320) ---
    bed_x: bpy.props.FloatProperty(name="Printer Size X (mm)", default=320.0, min=10.0)
    bed_y: bpy.props.FloatProperty(name="Printer Size Y (mm)", default=320.0, min=10.0)
    bed_z: bpy.props.FloatProperty(name="Printer Size Z (mm)", default=320.0, min=10.0)
    border_clearance: bpy.props.FloatProperty(name="Border Clearance (mm)", default=0.0, min=0.0)
    cut_chamfer: bpy.props.FloatProperty(name="Cut Chamfer (mm)", default=0.0, min=0.0)
    close_cut: bpy.props.BoolProperty(name="Close Cut", default=True,
                                       description="Cap each cut face so pieces stay watertight")

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
    """Cap the loop of edges created by the bisect using triangle_fill,
    which handles concave/organic boundary loops far better than the
    ngon ear-clipping used by mesh.fill_holes. Returns True if the loop
    was fully closed (no leftover boundary edges)."""
    edges = [e for e in geom_cut if isinstance(e, bmesh.types.BMEdge)]
    if not edges:
        return True
    try:
        bmesh.ops.triangle_fill(bm, use_beauty=True, use_dissolve=True, edges=edges)
    except Exception:
        return False
    # A clean cap leaves no more single-face (boundary) edges among the cut edges
    still_open = any((not e.is_valid) or len(e.link_faces) < 2 for e in edges if e.is_valid)
    return not still_open


def bisect_object(obj, plane_co, plane_no, close_cut=True):
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
            ok = cap_boundary(bm, ret['geom_cut'])
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


def apply_boolean(target_obj, other_obj, operation):
    """Apply a boolean modifier and bake it into target_obj.data without
    bpy.ops.object.modifier_apply -- no active-object/selection juggling,
    and it works the same in background/headless runs."""
    mod = target_obj.modifiers.new(name="_bool_tmp", type='BOOLEAN')
    mod.operation = operation
    mod.object = other_obj
    mod.solver = 'EXACT'

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
    """
    if low_fp is None or high_fp is None:
        return []

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
        return []

    low_bvh = build_world_bvh(low)
    high_bvh = build_world_bvh(high)
    if low_bvh is None or high_bvh is None:
        return []

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
        return []

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

    return selected


def add_dowel_pair(piece_a, piece_b, center, normal, radius, depth, tolerance, name_suffix):
    """Cut a matching OPEN hole into BOTH mating pieces.

    The cutter deliberately crosses the cut surface by a small amount.
    Starting the Boolean cylinder exactly on the cap face can make Blender's
    Boolean solver fail on one side due to coplanar faces. Crossing the face
    guarantees that both mating parts receive an actual open socket.
    """
    normal = normal.normalized()
    socket_radius = max(radius - tolerance, 0.1)

    # Small overlap outside the cut face prevents coplanar Boolean failures.
    face_overlap = max(0.20, min(0.60, socket_radius * 0.20))
    cutter_length = depth + face_overlap

    directions = (
        (piece_a, -normal),
        (piece_b, normal),
    )

    for piece, inward in directions:
        bvh = build_world_bvh(piece)

        hole_depth = depth

        if bvh is not None:
            safe = ray_depth_inside(bvh, center, inward)
            if safe is not None:
                hole_depth = min(
                    depth,
                    max(0.30, safe - 2.0)
                )

        if hole_depth <= 0.0:
            hole_depth = max(0.30, depth * 0.5)

        # Never allow a socket longer than the planned half-dowel depth.
        hole_depth = min(hole_depth, depth)

        actual_length = hole_depth + face_overlap

        # Start slightly outside the cut face and extend inward. This makes
        # the Boolean intersection unambiguous instead of relying on
        # coincident cutter/cap surfaces.
        cutter_center = center + inward * (
            (hole_depth * 0.5) - face_overlap * 0.5
        )

        rot_quat = inward.to_track_quat('Z', 'Y')
        mat = (
            Matrix.Translation(cutter_center)
            @ rot_quat.to_matrix().to_4x4()
        )

        cutter = make_cylinder_object(
            f"hole_{name_suffix}_{piece.name}",
            socket_radius,
            actual_length,
            mat,
        )

        apply_boolean(piece, cutter, 'DIFFERENCE')

        cutter_mesh = cutter.data
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


def generate_holes_for_pairs(pairs, s, progress_callback=None):
    """Generate holes for explicit mating pairs.

    The expensive connector operation is completely separate from cutting.
    This is used by both 'Auto Add Holes' and 'Holes Between Selected Parts'.
    """
    radius = s.connector_size / 2.0
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

        centers = find_safe_connector_centers(
            low, high,
            axis_index, pos, other_axes,
            low_fp, high_fp,
            s.connectors_per_edge,
            radius,
            s.connector_edge_margin,
        )

        normal = Vector((0.0, 0.0, 0.0))
        normal[axis_index] = 1.0

        for n, center in enumerate(centers):
            add_dowel_pair(
                low, high, center, normal,
                radius, depth, s.connector_tolerance,
                f"{axis_index}_{round(pos, 2)}_{pair_index}_{n}",
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
        axes.append((0, Vector((1, 0, 0)), s.bed_x))
    if s.cut_y:
        axes.append((1, Vector((0, 1, 0)), s.bed_y))
    if s.cut_z:
        axes.append((2, Vector((0, 0, 1)), s.bed_z))

    s.progress_text = "Cutting mesh..."
    s.failed_caps = 0
    for axis_index, normal, span in axes:
        next_pieces = []
        for piece in pieces:
            parent_faces = cut_faces.pop(piece, [])
            min_v, max_v = world_bounds(piece)
            positions = plane_positions(min_v, max_v, axis_index, span, s.border_clearance)
            current = piece
            current_faces = parent_faces
            for pos in positions:
                plane_co = Vector(min_v)
                plane_co[axis_index] = pos
                kept_low, kept_high, ok = bisect_object(current, plane_co, normal, close_cut=s.close_cut)
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

                    centers = find_safe_connector_centers(
                        low, high,
                        axis_index, pos, other_axes,
                        low_fp, high_fp,
                        s.connectors_per_edge,
                        radius,
                        s.connector_edge_margin,
                    )

                    for n, center in enumerate(centers):
                        normal = Vector((0.0, 0.0, 0.0))
                        normal[axis_index] = 1.0
                        add_dowel_pair(
                            low, high, center, normal,
                            radius, depth, s.connector_tolerance,
                            f"{axis_index}_{round(pos, 2)}_{n}",
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
        self._generator = cut_generator(context, s, obj)

        s.is_running = True
        s.cancel_requested = False
        s.progress = 0.0
        s.progress_text = "Starting..."

        wm = context.window_manager
        self._timer = wm.event_timer_add(0.01, window=context.window)
        wm.modal_handler_add(self)
        return {'RUNNING_MODAL'}

    def finish(self, context):
        s = context.scene.cutter_settings
        wm = context.window_manager
        wm.event_timer_remove(self._timer)
        s.is_running = False
        s.cancel_requested = False
        s.progress = 1.0
        s.progress_text = "Done"

    def cancel(self, context):
        s = context.scene.cutter_settings
        wm = context.window_manager
        wm.event_timer_remove(self._timer)
        s.is_running = False
        s.cancel_requested = False
        s.progress = 0.0
        s.progress_text = ""


class OBJECT_OT_modular_cut_cancel(bpy.types.Operator):
    bl_idname = "object.modular_cut_cancel"
    bl_label = "Cancel Cut"
    bl_description = "Stop the cut currently in progress"

    def execute(self, context):
        context.scene.cutter_settings.cancel_requested = True
        return {'FINISHED'}



class OBJECT_OT_origin_to_geometry(bpy.types.Operator):
    bl_idname = "object.modular_origin_to_geometry"
    bl_label = "Origin to Geometry"
    bl_description = "Move the origin of the selected object(s) to their geometry center"
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
# UI Panel
# ---------------------------------------------------------------------------

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

        box = layout.box()
        box.label(text="Model Size", icon='MESH_DATA')
        obj = context.active_object
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

        box = layout.box()
        box.label(text="3D Printer")
        box.prop(s, "bed_x")
        box.prop(s, "bed_y")
        box.prop(s, "bed_z")
        box.prop(s, "border_clearance")
        box.prop(s, "cut_chamfer")
        box.prop(s, "close_cut")

        box = layout.box()
        box.label(text="Axial Cut (which axes to split)")
        row = box.row()
        row.prop(s, "cut_x", toggle=True)
        row.prop(s, "cut_y", toggle=True)
        row.prop(s, "cut_z", toggle=True)

        box = layout.box()
        box.label(text="OBJECT", icon='OBJECT_DATA')
        row = box.row()
        row.scale_y = 1.25
        row.operator(
            "object.modular_origin_to_geometry",
            text="ORIGIN TO GEOMETRY",
            icon='PIVOT_MEDIAN'
        )

        box = layout.box()
        box.label(text="VIEW", icon='VIEW3D')
        row = box.row(align=True)
        row.operator("view3d.view_selected", text="Frame Selected", icon='ZOOM_SELECTED')
        row.operator("view3d.view_all", text="Frame All", icon='HOME')

        box = layout.box()
        box.label(text="✂ CUT MODEL", icon='MOD_BOOLEAN')
        box.label(text="Cut first. Connector work is separate and faster.")
        row = box.row()
        row.scale_y = 1.5
        row.operator("object.modular_cut", icon='MOD_BOOLEAN', text="CUT MODEL TO BED")

        box = layout.box()
        box.label(text="🕳️ DOWEL HOLES", icon='MESH_CYLINDER')
        box.prop(s, "connectors_per_edge", text="Dowels Per Connection")
        box.label(
            text=f"{s.connectors_per_edge} hole(s) on each mating connection",
            icon='INFO'
        )
        box.prop(s, "connector_depth_ratio", text="Depth Ratio")
        box.prop(s, "connector_size", text="Size")
        box.prop(s, "connector_tolerance", text="Tolerance")
        box.prop(s, "connector_edge_margin", text="Edge Margin")

        row = box.row()
        row.scale_y = 1.35
        row.operator(
            "object.modular_make_all_holes",
            icon='MESH_CYLINDER',
            text="AUTO ADD HOLES - ALL PARTS"
        )

        row = box.row()
        row.scale_y = 1.25
        row.operator(
            "object.modular_make_selected_holes",
            icon='RESTRICT_SELECT_OFF',
            text="MAKE HOLES BETWEEN SELECTED"
        )

        box.separator()
        row = box.row()
        row.scale_y = 1.25
        row.operator(
            "object.modular_create_master_dowel",
            icon='MESH_CYLINDER',
            text="CREATE MASTER DOWEL"
        )

        box.label(text="Select 2+ cut parts for the selected-parts tool.")

        box = layout.box()
        box.label(text="Mesh Repair", icon='MODIFIER')
        box.prop(s, "auto_mesh_repair")
        col = box.column()
        col.enabled = s.auto_mesh_repair
        col.prop(s, "repair_merge_distance")

        if s.is_running:
            box = layout.box()
            pct = int(s.progress * 100)
            try:
                # UILayout.progress() is only available in Blender 4.0+
                box.progress(factor=s.progress, type='BAR', text=f"{s.progress_text} {pct}%")
            except AttributeError:
                box.label(text=f"{s.progress_text} {pct}%")
                row = box.row()
                filled = int(pct / 5)
                row.label(text="[" + "#" * filled + "-" * (20 - filled) + "]")
            box.operator("object.modular_cut_cancel", icon='CANCEL', text="Cancel")
        else:
            layout.operator("object.modular_cut", icon='MOD_BOOLEAN')


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
    OBJECT_OT_make_all_holes,
    OBJECT_OT_make_selected_holes,
    OBJECT_OT_create_master_dowel,
    OBJECT_OT_origin_to_geometry,
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
    _start_viewport_defaults()


def unregister():
    _stop_license_countdown()
    _stop_viewport_defaults()
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)
    del bpy.types.Scene.cutter_settings


if __name__ == "__main__":
    register()
