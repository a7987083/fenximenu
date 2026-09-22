#!/usr/bin/env python3
"""Summarize HFAMap analysis logs and correlate exact menu binaries."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _load_triage():
    path = ROOT / "tools" / "hfamap_macho_triage.py"
    spec = importlib.util.spec_from_file_location("hfamap_macho_triage", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _binary_index(binary_root: Path | None) -> dict[str, list[Path]]:
    result: dict[str, list[Path]] = {}
    if binary_root is None:
        return result
    for path in binary_root.rglob("*"):
        if path.is_file():
            result.setdefault(path.name, []).append(path)
    return result


def build_matrix(log_dir: Path, binary_root: Path | None = None) -> dict[str, Any]:
    if not log_dir.is_dir():
        raise FileNotFoundError(f"log directory does not exist: {log_dir}")
    if binary_root is not None and not binary_root.is_dir():
        raise FileNotFoundError(f"binary root does not exist: {binary_root}")
    triage = _load_triage() if binary_root is not None else None
    binaries = _binary_index(binary_root)
    games: list[dict[str, Any]] = []
    for path in sorted(log_dir.glob("*_HFAMap_Analysis.json")):
        analysis = json.loads(path.read_text(encoding="utf-8"))
        candidate = analysis.get("candidate") or {}
        image = candidate.get("image")
        matches = []
        for binary in binaries.get(image, []):
            try:
                record = triage.analyze(binary)
                matches.append({
                    "path": str(binary),
                    "uuid": record.get("uuid"),
                    "family": record.get("family"),
                    "uuidMatchesLog": record.get("uuid") == candidate.get("menuUUID"),
                })
            except Exception as exc:  # Keep malformed/unrelated files visible.
                matches.append({"path": str(binary), "error": str(exc), "uuidMatchesLog": False})
        buttons = []
        for record in analysis.get("registry") or []:
            descriptor_evidence = record.get("descriptorEvidence") or []
            buttons.append({
                "name": record.get("name"),
                "identifier": record.get("identifier"),
                "type": record.get("type"),
                "sourceClass": record.get("sourceClass"),
                "descriptorCount": len(descriptor_evidence),
                "descriptorClasses": sorted({
                    item.get("class") for item in descriptor_evidence if item.get("class")
                }),
            })
        unresolved = analysis.get("unresolved") or []
        games.append({
            "game": path.name.removesuffix("_HFAMap_Analysis.json"),
            "status": analysis.get("status"),
            "bundleID": candidate.get("hostBundleID"),
            "hostVersion": candidate.get("hostVersion"),
            "hostBuild": candidate.get("hostBuild"),
            "menuImage": image,
            "menuUUID": candidate.get("menuUUID"),
            "family": candidate.get("family"),
            "buttons": buttons,
            "validatedPatchCount": len(analysis.get("features") or []),
            "unresolvedReasons": dict(Counter(item.get("reason") for item in unresolved)),
            "binaryMatches": matches,
        })
    return {
        "schema": "com.hfa.log-matrix/v1",
        "gameCount": len(games),
        "buttonCount": sum(len(game["buttons"]) for game in games),
        "validatedPatchCount": sum(game["validatedPatchCount"] for game in games),
        "games": games,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("log_dir", type=Path)
    parser.add_argument("--binary-root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    matrix = build_matrix(args.log_dir, args.binary_root)
    text = json.dumps(matrix, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
