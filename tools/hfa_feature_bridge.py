#!/usr/bin/env python3
import copy

V1 = "com.hfa.patch/v1"
V2 = "com.hfa.feature/v2"


class BridgeError(ValueError):
    pass


def v1_to_v2(pkg):
    if not isinstance(pkg, dict) or pkg.get("schema") != V1:
        raise BridgeError("input-not-v1")
    out = {
        "schema": V2,
        "name": pkg.get("name", ""),
        "offsetSemantics": "preferred-mach-o-vmaddr",
        "package": copy.deepcopy(pkg.get("package", {})),
        "targets": copy.deepcopy(pkg.get("targets", {})),
        "features": [],
    }
    for feature in pkg.get("features", []):
        out["features"].append({
            "id": feature["id"],
            "title": feature["title"],
            "group": feature["group"],
            "control": {
                "kind": "toggle",
                "default": bool(feature.get("defaultEnabled", False)),
            },
            "execution": {
                "kind": "bytePatch",
                "patches": copy.deepcopy(feature.get("patches", [])),
            },
        })
    return out


def v2_bytepatch_to_v1(pkg, feature_ids=None):
    if not isinstance(pkg, dict) or pkg.get("schema") != V2:
        raise BridgeError("input-not-v2")
    wanted = set(feature_ids or [])
    selected = []
    found = set()
    for feature in pkg.get("features", []):
        fid = feature.get("id")
        if wanted and fid not in wanted:
            continue
        execution = feature.get("execution", {})
        control = feature.get("control", {})
        if execution.get("kind") != "bytePatch":
            raise BridgeError(f"unsupported-execution-kind:{fid}:{execution.get('kind')}")
        if control.get("kind") != "toggle":
            raise BridgeError(f"bytepatch-control-not-toggle:{fid}:{control.get('kind')}")
        selected.append({
            "id": fid,
            "title": feature.get("title", ""),
            "group": feature.get("group", "Imported"),
            "defaultEnabled": bool(control.get("default", False)),
            "patches": copy.deepcopy(execution.get("patches", [])),
        })
        found.add(fid)
    missing = wanted - found
    if missing:
        raise BridgeError("feature-id-not-found:" + ",".join(sorted(missing)))
    if not selected:
        raise BridgeError("no-bytepatch-features-selected")
    return {
        "schema": V1,
        "name": pkg.get("name", ""),
        "package": copy.deepcopy(pkg.get("package", {})),
        "targets": copy.deepcopy(pkg.get("targets", {})),
        "features": selected,
    }
