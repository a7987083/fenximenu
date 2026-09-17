#!/usr/bin/env python3
"""Bounded, read-only Mach-O menu candidate triage.

This is the host-side implementation of the same rules used by the iOS probe.
It deliberately reads only load commands and named string sections; it never
loads or executes the candidate binary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x80000018
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_COMMANDS = 4096
MAX_SECTION_BYTES = 32 * 1024 * 1024

TOKENS = {
    "menu-ui": {
        b"addButtonWithTitle:": 22,
        b"customSwitch": 20,
        b"iOSGods": 12,
        b"IGMenu 1.0": 12,
        b"APMenuControl": 18,
    },
    "legacy-descriptor": {
        b"APPatchItem": 30,
        b"APSubpatchManager": 24,
        b"IGSecretInt": 16,
        b"IGSecretData": 16,
        b"IGCodePatch": 18,
    },
    "jailpatch": {
        b"JailpatchConfigValidator": 32,
        b"Jailpatch runtime table": 28,
        b"OffsetInstruction": 18,
        b"OffsetType": 14,
        b".app-key-metadata-": 24,
    },
}


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    segment: str
    name: str
    offset: int
    size: int


def _cstr(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _slice(data: bytes, off: int, size: int, what: str) -> bytes:
    if off < 0 or size < 0 or off + size > len(data):
        raise ParseError(f"{what} outside file: off={off} size={size}")
    return data[off : off + size]


def parse_macho(data: bytes) -> tuple[list[Section], list[str], str | None]:
    if len(data) < 32:
        raise ParseError("file shorter than mach_header_64")
    magic, _, _, _, ncmds, sizeofcmds, _, _ = struct.unpack_from("<8I", data)
    if magic != MH_MAGIC_64:
        raise ParseError(f"unsupported Mach-O magic 0x{magic:08X}")
    if ncmds > MAX_COMMANDS or sizeofcmds > len(data) - 32:
        raise ParseError("unreasonable load-command table")
    sections: list[Section] = []
    dylibs: list[str] = []
    uuid: str | None = None
    cursor = 32
    command_end = 32 + sizeofcmds
    for index in range(ncmds):
        if cursor + 8 > command_end:
            raise ParseError(f"load command {index} truncated")
        cmd, cmdsize = struct.unpack_from("<II", data, cursor)
        if cmdsize < 8 or cursor + cmdsize > command_end:
            raise ParseError(f"load command {index} has invalid size")
        if cmd == LC_SEGMENT_64:
            if cmdsize < 72:
                raise ParseError("LC_SEGMENT_64 truncated")
            segname = _cstr(data[cursor + 8 : cursor + 24])
            nsects = struct.unpack_from("<I", data, cursor + 64)[0]
            if 72 + nsects * 80 > cmdsize:
                raise ParseError("section table exceeds segment command")
            for i in range(nsects):
                base = cursor + 72 + i * 80
                sectname = _cstr(data[base : base + 16])
                section_seg = _cstr(data[base + 16 : base + 32]) or segname
                size = struct.unpack_from("<Q", data, base + 40)[0]
                offset = struct.unpack_from("<I", data, base + 48)[0]
                if size and offset and offset + size <= len(data):
                    sections.append(Section(section_seg, sectname, offset, size))
        elif cmd == LC_UUID and cmdsize >= 24:
            raw = data[cursor + 8 : cursor + 24]
            h = raw.hex().upper()
            uuid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB) and cmdsize >= 24:
            name_off = struct.unpack_from("<I", data, cursor + 8)[0]
            if 0 < name_off < cmdsize:
                dylibs.append(_cstr(data[cursor + name_off : cursor + cmdsize]))
        cursor += cmdsize
    return sections, dylibs, uuid


def analyze(path: Path) -> dict:
    started = time.monotonic()
    stat = path.stat()
    if stat.st_size > MAX_FILE_BYTES:
        raise ParseError(f"file exceeds {MAX_FILE_BYTES} byte budget")
    data = path.read_bytes()
    sections, dylibs, uuid = parse_macho(data)
    searchable = [s for s in sections if s.name in {"__cstring", "__objc_methname", "__const"}]
    evidence: list[dict] = []
    group_scores = {name: 0 for name in TOKENS}
    scanned = 0
    for section in searchable:
        if scanned >= MAX_SECTION_BYTES:
            break
        size = min(section.size, MAX_SECTION_BYTES - scanned)
        blob = _slice(data, section.offset, size, f"{section.segment},{section.name}")
        scanned += len(blob)
        for group, tokens in TOKENS.items():
            for token, weight in tokens.items():
                if token in blob and not any(item["token"] == token.decode() for item in evidence):
                    group_scores[group] += weight
                    evidence.append({"group": group, "token": token.decode(), "weight": weight})
    ui = group_scores["menu-ui"]
    legacy = group_scores["legacy-descriptor"]
    jail = group_scores["jailpatch"]
    family = "unknown"
    if ui >= 30 and legacy >= 30 and legacy > jail:
        family = "legacy-ap"
    elif ui >= 30 and jail >= 28:
        family = "jailpatch"
    elif ui >= 30:
        family = "runtime-menu"
    score = min(100, ui + min(max(legacy, jail), 35)) if family != "unknown" else 0
    return {
        "schema": "com.hfa.macho-triage/v2",
        "path": str(path),
        "image": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "uuid": uuid,
        "family": family,
        "score": score,
        "scores": group_scores,
        "evidence": sorted(evidence, key=lambda x: (-x["weight"], x["token"])),
        "dependencies": dylibs,
        "limits": {
            "fileBytes": MAX_FILE_BYTES,
            "sectionBytes": MAX_SECTION_BYTES,
            "loadCommands": MAX_COMMANDS,
        },
        "metrics": {
            "sections": len(sections),
            "searchableSections": len(searchable),
            "scannedBytes": scanned,
            "elapsedMs": round((time.monotonic() - started) * 1000, 3),
        },
    }


def iter_inputs(values: Iterable[str]) -> Iterable[Path]:
    for value in values:
        path = Path(value)
        if path.is_dir():
            yield from sorted(p for p in path.iterdir() if p.is_file())
        else:
            yield path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", help="Mach-O files or directories")
    parser.add_argument("--json", action="store_true", help="emit one JSON document")
    args = parser.parse_args()
    results, errors = [], []
    for path in iter_inputs(args.inputs):
        try:
            results.append(analyze(path))
        except (OSError, ParseError) as exc:
            errors.append({"path": str(path), "error": str(exc)})
    results.sort(key=lambda item: (-item["score"], item["image"]))
    root = {"schema": "com.hfa.macho-triage-report/v2", "results": results, "errors": errors}
    if args.json:
        json.dump(root, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        for item in results:
            print(f"{item['score']:3d} {item['family']:14s} {item['image']} {item['uuid'] or '-'}")
        for item in errors:
            print(f"ERR {item['path']}: {item['error']}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
