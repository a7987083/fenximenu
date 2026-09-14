# HFAMap Roadmap

## Current phase

v1.9.33 — 5 MB runtime confirmed / unified 15 MB-compatible export pending

## Completed milestone: legacy AP / ~15 MB

v1.9.28 is runtime-confirmed with 12 valid mappings and successful patch-package export.

Formal stable baseline remains:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestone: 5 MB runtime-record execution chain

- v1.9.29: runtime-record object graph and stable selector surface established.
- v1.9.30: selector descriptor and offset/patch-wrapper association device-confirmed.
- v1.9.31: image-local decrypt fingerprint resolver built.
- v1.9.32: crash-safe Full Scan confirmed; generic decrypt reached `matches=1 / rc=0`; 8/8 mappings valid.
- v1.9.33: original-byte acquisition produced a complete 3-feature / 8-static-patch package for the tested runtime-record sample.

## Completed milestone: 5 MB iGMM runtime path

The independent iGMM path is runtime-confirmed with four runtime-definition features and successful JSON export under its current representation.

## Current milestone: unified export contract

Runtime success is not sufficient for project completion. The final consumer-facing JSON must be deliberately normalized against the canonical 15 MB package.

Required work:

1. Obtain the exact canonical 15 MB `.hfapatch.json`.
2. Diff both 5 MB outputs against it:
   - root keys / schema version;
   - target identity model;
   - feature IDs/titles/groups/types;
   - static patch representation;
   - runtime-definition representation;
   - menu-family/extensions metadata;
   - consumer execution semantics.
3. Define one canonical cross-family contract.
4. Add an adapter/unified exporter on a new branch.
5. Device-regression all three paths:
   - legacy 15 MB;
   - runtime-record 5 MB;
   - iGMM 5 MB.
6. Only after parity/compatibility passes should the project be called closed.

## Build checkpoint

- Branch: `feature/hfamap-v1933-original-byte-resolver`.
- Build-tested code commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`.
- CI run: `34799869649` — success.
- Artifact ID: `10330589684`.
- Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`.
- SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.
- Device validation: passed for both supplied 5 MB runtime paths.
- Unified 15 MB/5 MB JSON parity: pending.
