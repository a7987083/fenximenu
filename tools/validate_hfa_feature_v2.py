#!/usr/bin/env python3
import argparse
import json
import math
import re
import sys
from pathlib import Path

V1 = "com.hfa.patch/v1"
V2 = "com.hfa.feature/v2"
HEX_RE = re.compile(r"^0x[0-9A-Fa-f]+$")
BYTE_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


class ValidationError(ValueError):
    pass


def _require(cond, msg):
    if not cond:
        raise ValidationError(msg)


def _is_number(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(float(v))


def _hex_offset(v, where):
    _require(isinstance(v, str) and HEX_RE.fullmatch(v), f"{where}: invalid offset")


def _hex_bytes(v, where):
    _require(isinstance(v, str) and len(v) > 0 and len(v) % 2 == 0 and BYTE_HEX_RE.fullmatch(v),
             f"{where}: invalid byte hex")


def _validate_patch(patch, targets, where):
    _require(isinstance(patch, dict), f"{where}: patch must be object")
    for key in ("target", "offset", "original", "enabled"):
        _require(key in patch, f"{where}: missing {key}")
    target = patch["target"]
    _require(isinstance(target, str) and target in targets, f"{where}: unknown target {target!r}")
    _hex_offset(patch["offset"], f"{where}.offset")
    _hex_bytes(patch["original"], f"{where}.original")
    _hex_bytes(patch["enabled"], f"{where}.enabled")
    _require(len(patch["original"]) == len(patch["enabled"]), f"{where}: byte lengths differ")
    _require(patch["original"].lower() != patch["enabled"].lower(), f"{where}: original == enabled")


def validate_v1(pkg):
    _require(pkg.get("schema") == V1, "v1: schema mismatch")
    for key in ("name", "package", "targets", "features"):
        _require(key in pkg, f"v1: missing {key}")
    _require(isinstance(pkg["targets"], dict) and pkg["targets"], "v1: targets missing")
    for key, target in pkg["targets"].items():
        _require(isinstance(key, str) and key, "v1: invalid target key")
        _require(isinstance(target, dict) and isinstance(target.get("image"), str) and target["image"],
                 f"v1: invalid target {key}")
    _require(isinstance(pkg["features"], list) and pkg["features"], "v1: features missing")
    ids = set()
    for i, feature in enumerate(pkg["features"]):
        where = f"v1.features[{i}]"
        _require(isinstance(feature, dict), f"{where}: not object")
        for key in ("id", "title", "group", "defaultEnabled", "patches"):
            _require(key in feature, f"{where}: missing {key}")
        _require(isinstance(feature["id"], str) and feature["id"], f"{where}: invalid id")
        _require(feature["id"] not in ids, f"{where}: duplicate id")
        ids.add(feature["id"])
        _require(isinstance(feature["title"], str) and feature["title"], f"{where}: invalid title")
        _require(isinstance(feature["group"], str) and feature["group"], f"{where}: invalid group")
        _require(isinstance(feature["defaultEnabled"], bool), f"{where}: defaultEnabled must be bool")
        _require(isinstance(feature["patches"], list) and feature["patches"], f"{where}: patches missing")
        for j, patch in enumerate(feature["patches"]):
            _validate_patch(patch, pkg["targets"], f"{where}.patches[{j}]")
    return pkg


def _validate_control(control, where):
    _require(isinstance(control, dict), f"{where}: control must be object")
    kind = control.get("kind")
    _require(isinstance(kind, str) and kind, f"{where}: control.kind missing")
    if kind == "toggle":
        _require(isinstance(control.get("default"), bool), f"{where}: toggle.default must be bool")
    elif kind in ("number", "slider"):
        value_type = control.get("valueType")
        _require(value_type in {"int32", "int64", "uint32", "uint64", "float32", "float64"},
                 f"{where}: invalid numeric valueType")
        _require(_is_number(control.get("default")), f"{where}: numeric default required")
        for k in ("min", "max", "step"):
            if k in control:
                _require(_is_number(control[k]), f"{where}: {k} must be number")
        if "min" in control and "max" in control:
            _require(control["min"] <= control["max"], f"{where}: min > max")
    elif kind in ("button", "action"):
        _require("default" not in control, f"{where}: one-shot control must not have default")
    elif kind == "text":
        _require(isinstance(control.get("default"), str), f"{where}: text.default must be string")
    elif kind in ("choice", "multiChoice"):
        options = control.get("options")
        _require(isinstance(options, list) and options, f"{where}: options required")
        for idx, opt in enumerate(options):
            _require(isinstance(opt, dict) and isinstance(opt.get("id"), str) and opt["id"],
                     f"{where}.options[{idx}]: invalid option")
        _require("default" in control, f"{where}: choice default required")
    else:
        _require(isinstance(control.get("provider"), str) and control["provider"],
                 f"{where}: unknown control kind requires provider")


def _validate_state_def(state, where):
    _require(isinstance(state, dict), f"{where}: state must be object")
    t = state.get("type")
    _require(t in {"bool", "int32", "int64", "uint32", "uint64", "float32", "float64", "string"},
             f"{where}: invalid state type")
    _require("default" in state, f"{where}: missing default")
    d = state["default"]
    if t == "bool":
        _require(isinstance(d, bool), f"{where}: bool default required")
    elif t == "string":
        _require(isinstance(d, str), f"{where}: string default required")
    else:
        _require(_is_number(d), f"{where}: numeric default required")


def _validate_runtime_graph(name, graph, targets):
    where = f"runtimeGraphs.{name}"
    _require(isinstance(graph, dict), f"{where}: graph must be object")
    bootstrap = graph.get("bootstrap", "once")
    _require(bootstrap in {"once", "onDemand"}, f"{where}: invalid bootstrap")
    state = graph.get("state", {})
    _require(isinstance(state, dict), f"{where}.state: must be object")
    for key, value in state.items():
        _require(isinstance(key, str) and key, f"{where}.state: invalid key")
        _validate_state_def(value, f"{where}.state.{key}")
    stores = graph.get("stores", {})
    _require(isinstance(stores, dict), f"{where}.stores: must be object")
    for key, store in stores.items():
        _require(isinstance(store, dict) and isinstance(store.get("kind"), str),
                 f"{where}.stores.{key}: invalid store")
    hooks = graph.get("hooks", [])
    _require(isinstance(hooks, list), f"{where}.hooks: must be array")
    hook_ids = set()
    for idx, hook in enumerate(hooks):
        hw = f"{where}.hooks[{idx}]"
        _require(isinstance(hook, dict), f"{hw}: hook must be object")
        for key in ("id", "target", "offset", "original", "behavior"):
            _require(key in hook, f"{hw}: missing {key}")
        _require(isinstance(hook["id"], str) and hook["id"], f"{hw}: invalid id")
        _require(hook["id"] not in hook_ids, f"{hw}: duplicate id")
        hook_ids.add(hook["id"])
        _require(hook["target"] in targets, f"{hw}: unknown target")
        _hex_offset(hook["offset"], f"{hw}.offset")
        _hex_bytes(hook["original"], f"{hw}.original")
        _require(isinstance(hook["behavior"], dict) and isinstance(hook["behavior"].get("kind"), str),
                 f"{hw}.behavior: kind required")


def _validate_execution(execution, control, pkg, where):
    _require(isinstance(execution, dict), f"{where}: execution must be object")
    kind = execution.get("kind")
    _require(isinstance(kind, str) and kind, f"{where}: execution.kind missing")
    targets = pkg["targets"]
    graphs = pkg.get("runtimeGraphs", {})
    if kind == "bytePatch":
        patches = execution.get("patches")
        _require(isinstance(patches, list) and patches, f"{where}: bytePatch.patches required")
        for idx, patch in enumerate(patches):
            _validate_patch(patch, targets, f"{where}.patches[{idx}]")
    elif kind == "runtimeState":
        graph = execution.get("graph")
        binding = execution.get("binding")
        _require(isinstance(graph, str) and graph in graphs, f"{where}: unknown graph")
        _require(isinstance(binding, str) and binding, f"{where}: binding required")
        state = graphs[graph].get("state", {})
        _require(binding in state, f"{where}: binding not defined in graph state")
    elif kind == "runtimeGraph":
        graph = execution.get("graph")
        _require(isinstance(graph, str) and graph in graphs, f"{where}: unknown graph")
    elif kind == "nativeCall":
        target = execution.get("target")
        _require(isinstance(target, str) and target in targets, f"{where}: nativeCall target invalid")
        _hex_offset(execution.get("offset"), f"{where}.offset")
        if "arguments" in execution:
            _require(isinstance(execution["arguments"], list), f"{where}: arguments must be array")
    else:
        _require(isinstance(execution.get("provider"), str) and execution["provider"],
                 f"{where}: unknown execution kind requires provider")


def validate_v2(pkg):
    _require(pkg.get("schema") == V2, "v2: schema mismatch")
    for key in ("name", "package", "targets", "features"):
        _require(key in pkg, f"v2: missing {key}")
    _require(pkg.get("offsetSemantics", "preferred-mach-o-vmaddr") == "preferred-mach-o-vmaddr",
             "v2: unsupported offsetSemantics")
    _require(isinstance(pkg["targets"], dict) and pkg["targets"], "v2: targets missing")
    for key, target in pkg["targets"].items():
        _require(isinstance(key, str) and key, "v2: invalid target key")
        _require(isinstance(target, dict) and isinstance(target.get("image"), str) and target["image"],
                 f"v2: invalid target {key}")
    graphs = pkg.get("runtimeGraphs", {})
    _require(isinstance(graphs, dict), "v2: runtimeGraphs must be object")
    for name, graph in graphs.items():
        _require(isinstance(name, str) and name, "v2: invalid runtime graph name")
        _validate_runtime_graph(name, graph, pkg["targets"])
    features = pkg["features"]
    _require(isinstance(features, list) and features, "v2: features missing")
    ids = set()
    for idx, feature in enumerate(features):
        where = f"v2.features[{idx}]"
        _require(isinstance(feature, dict), f"{where}: feature must be object")
        for key in ("id", "title", "group", "control", "execution"):
            _require(key in feature, f"{where}: missing {key}")
        fid = feature["id"]
        _require(isinstance(fid, str) and fid, f"{where}: invalid id")
        _require(fid not in ids, f"{where}: duplicate id")
        ids.add(fid)
        _require(isinstance(feature["title"], str) and feature["title"], f"{where}: invalid title")
        _require(isinstance(feature["group"], str) and feature["group"], f"{where}: invalid group")
        _validate_control(feature["control"], f"{where}.control")
        _validate_execution(feature["execution"], feature["control"], pkg, f"{where}.execution")
    return pkg


def validate_package(pkg):
    _require(isinstance(pkg, dict), "root must be object")
    schema = pkg.get("schema")
    if schema == V1:
        return validate_v1(pkg)
    if schema == V2:
        return validate_v2(pkg)
    raise ValidationError(f"unsupported schema: {schema!r}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate HFA v1/v2 feature packages")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv)
    failed = False
    for name in args.files:
        path = Path(name)
        try:
            pkg = json.loads(path.read_text())
            validate_package(pkg)
            print(f"PASS {path} schema={pkg.get('schema')}")
        except Exception as exc:
            failed = True
            print(f"FAIL {path}: {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
