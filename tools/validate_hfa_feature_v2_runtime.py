#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from validate_hfa_feature_v2 import ValidationError, _hex_bytes, _hex_offset, _require, validate_package


def validate_runtime_subset(pkg):
    validate_package(pkg)
    _require(pkg.get("schema") == "com.hfa.feature/v2", "runtime: package must be com.hfa.feature/v2")
    graphs = pkg.get("runtimeGraphs", {})
    for graph_name, graph in graphs.items():
        stores = graph.get("stores", {})
        for name, store in stores.items():
            _require(store.get("kind") == "pointerSet", f"runtimeGraphs.{graph_name}.stores.{name}: only pointerSet supported")
            max_entries = store.get("maxEntries", 64)
            _require(isinstance(max_entries, int) and not isinstance(max_entries, bool) and 1 <= max_entries <= 64,
                     f"runtimeGraphs.{graph_name}.stores.{name}: maxEntries must be 1..64")

        for i, hook in enumerate(graph.get("hooks", [])):
            where = f"runtimeGraphs.{graph_name}.hooks[{i}]"
            behavior = hook.get("behavior", {})
            kind = behavior.get("kind")
            _require(kind in {"captureFieldPointer", "conditionalPipeline"},
                     f"{where}: unsupported runtime hook behavior {kind!r}")
            if kind == "captureFieldPointer":
                _require(behavior.get("baseRegister") == "x0", f"{where}: capture baseRegister must be x0")
                _hex_offset(behavior.get("fieldOffset"), f"{where}.behavior.fieldOffset")
                _require(behavior.get("store") in stores, f"{where}: capture store missing")
            else:
                _require(behavior.get("subjectRegister") == "x0", f"{where}: subjectRegister must be x0")
                _require(behavior.get("valueRegister") == "x1", f"{where}: valueRegister must be x1")
                _require(behavior.get("protectedStore") in stores, f"{where}: protectedStore missing")
                _require(behavior.get("fallback") == "callOriginal", f"{where}: fallback must be callOriginal")
                rules = behavior.get("rules")
                _require(isinstance(rules, list) and len(rules) == 3, f"{where}: exactly three pipeline rules required")
                seen = set()
                for r, rule in enumerate(rules):
                    rw = f"{where}.behavior.rules[{r}]"
                    all_conditions = rule.get("when", {}).get("all")
                    actions = rule.get("do")
                    _require(isinstance(all_conditions, list) and len(all_conditions) == 2, f"{rw}: two conditions required")
                    _require(isinstance(actions, list) and len(actions) == 1 and isinstance(actions[0], dict),
                             f"{rw}: one action required")
                    protection = next((x for x in all_conditions if isinstance(x, str)), None)
                    state_condition = next((x for x in all_conditions if isinstance(x, dict)), None)
                    _require(protection in {"subjectIsProtected", "subjectIsNotProtected"}, f"{rw}: protection condition unsupported")
                    _require(isinstance(state_condition, dict) and isinstance(state_condition.get("state"), str),
                             f"{rw}: state condition required")
                    action = actions[0]
                    action_kind = action.get("kind")
                    state_name = action.get("state", state_condition.get("state"))
                    _require(state_name in graph.get("state", {}), f"{rw}: state is not defined")
                    if action_kind == "return":
                        _require(protection == "subjectIsProtected" and state_condition.get("equals") is True,
                                 f"{rw}: return requires protected + equals true")
                        _require(graph["state"][state_name].get("type") == "bool", f"{rw}: return state must be bool")
                        seen.add("return")
                    elif action_kind == "divideIntegerArgument":
                        _require(protection == "subjectIsProtected" and action.get("register") == "x1" and
                                 state_condition.get("notEquals") == 1,
                                 f"{rw}: divide rule must be protected x1 notEquals 1")
                        seen.add("divide")
                    elif action_kind == "multiplyIntegerArgument":
                        _require(protection == "subjectIsNotProtected" and action.get("register") == "x1" and
                                 state_condition.get("notEquals") == 1,
                                 f"{rw}: multiply rule must be unprotected x1 notEquals 1")
                        seen.add("multiply")
                    else:
                        raise ValidationError(f"{rw}: action unsupported {action_kind!r}")
                _require(seen == {"return", "divide", "multiply"}, f"{where}: required pipeline rules missing")

    for i, feature in enumerate(pkg.get("features", [])):
        execution = feature.get("execution", {})
        kind = execution.get("kind")
        where = f"features[{i}].execution"
        if kind == "nativeCall":
            _require(feature.get("control", {}).get("kind") == "button", f"{where}: nativeCall requires button control")
            _require(execution.get("abi", "void()") == "void()", f"{where}: only void() ABI is supported")
            if "original" in execution:
                _hex_bytes(execution["original"], f"{where}.original")
        elif kind == "runtimeState":
            _require(feature.get("control", {}).get("kind") in {"toggle", "number", "slider"},
                     f"{where}: runtimeState control unsupported")
        elif kind in {"bytePatch", "runtimeGraph"}:
            pass
        else:
            _require("provider" in execution, f"{where}: unknown runtime execution requires provider")
    return pkg


def main():
    ap = argparse.ArgumentParser(description="Validate the built-in HFA v2 runtime-executor subset")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()
    failed = False
    for name in args.files:
        try:
            pkg = json.loads(Path(name).read_text())
            validate_runtime_subset(pkg)
            print(f"PASS-RUNTIME {name}")
        except Exception as exc:
            failed = True
            print(f"FAIL-RUNTIME {name}: {exc}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
