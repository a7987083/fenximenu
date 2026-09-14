# HFAMap Handoff

## Current branch

`feature/hfamap-v1933-original-byte-resolver`

## Current build

- Build-tested code commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`.
- GitHub Actions run: `34799869649` — success.
- Artifact: `HFAMapUniversal-v1.9.33-OriginalByteResolver` (ID `10330589684`).
- Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175616` bytes.
- SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.

## Confirmed runtime checkpoints

### Legacy AP / ~15 MB

v1.9.28 remains runtime-confirmed with 12 valid mappings and successful `.hfapatch.json` export.

### Jailpatch runtime-record / ~5 MB

v1.9.33 confirms the supplied runtime-record sample can complete:

`semantic menu discovery`
→ `selector descriptor`
→ `secret-wrapper association`
→ `generic decrypt`
→ `8/8 valid mappings`
→ `3 features / 8 static patches exported`.

### iGMM / WayOfKings ~5 MB

v1.9.33 also confirms the independent iGMM path exports four runtime-definition features and no longer crashes during Full Scan.

## Critical remaining gap: unified JSON contract

The two 5 MB exporters currently produce different representations, and cross-family equivalence with the canonical 15 MB JSON has not been established.

- Runtime-record 5 MB currently exports static patch entries (`target/offset/original/enabled`).
- iGMM 5 MB currently exports runtime-definition features (`runtime/config/backend/...`) with empty static `patches` arrays.
- The user requires the final 5 MB output to be compatible with the 15 MB formal JSON format/semantics.

Therefore v1.9.33 is **runtime-confirmed**, but the project is **not cross-family export-complete**.

Do not use phrases such as "final closure" or "5 MB project complete" until the canonical 15 MB package is explicitly diffed against both 5 MB package types and a unified consumer contract passes device regression.

## Required next work

1. Retrieve the exact canonical 15 MB `.hfapatch.json` used as the compatibility target.
2. Diff root keys, target model, feature schema, patch schema, menu-family metadata, runtime metadata, and consumer semantics against both 5 MB outputs.
3. Decide the canonical schema; prefer an adapter/unified exporter instead of deleting evidence-rich backend data.
4. Implement on a new branch.
5. Regression-test legacy 15 MB, runtime-record 5 MB, and iGMM 5 MB before promoting completion.

## Verification discipline

- v1.9.33 5 MB runtime behavior: confirmed.
- v1.9.33 runtime-record package internal completeness: confirmed (3 features / 8 patches).
- v1.9.33 iGMM package internal completeness: confirmed for its current runtime-definition representation.
- 15 MB ↔ 5 MB JSON contract parity: **not confirmed**.
- v1.9.33 itself on 15 MB: not device-regression-tested.
