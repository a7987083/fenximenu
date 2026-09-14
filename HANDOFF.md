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

v1.9.33 is now the confirmed checkpoint for the supplied runtime-record sample.

Confirmed device chain:

`AUTO-MENU-CANDIDATE source=jailpatch-feature-array`
→ `AUTO-TRAVERSAL-END`
→ `AUTO-SCAN`
→ `MAP-DECRYPT-RESOLVE mode=text-fingerprint matches=1`
→ `MAP-DECRYPT rc=0`
→ `FULL-SCAN-END groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`
→ successful `.hfapatch.json` export.

The exported package contains:

- feature `0`: 1 patch;
- feature `1`: 6 patches;
- feature `2`: 1 patch;
- total: 3 features / 8 patches.

Every patch has complete `target`, `offset`, `original`, and `enabled` fields. Original/enabled lengths match and contents differ.

All eight original-byte recoveries used `source=vm-read status=ok`. The `memcpy` and cryptid-aware Mach-O file fallbacks remain CI/build-verified but were not exercised in this device run.

### iGMM / WayOfKings ~5 MB

v1.9.33 preserves the independent iGMM path. Device output still reaches semantic menu early-stop and exports four runtime-definition features. Empty `patches` arrays are expected for this backend because implementation metadata, not static byte patches, represents the behavior.

## Regression discipline

- Do not rewrite historical v1.9.28–v1.9.33 branches for new experiments.
- Treat v1.9.33 as the confirmed 5 MB selector/decrypt/package checkpoint.
- Any future resolver change should start on a new branch and preserve:
  - crash-safe semantic Full Scan;
  - selector descriptor fingerprinting;
  - generic secret decrypt resolution;
  - 3-feature / 8-patch runtime-record package output;
  - 4-feature iGMM runtime-definition export;
  - legacy 15 MB exporter behavior.

## Remaining validation gap

v1.9.33 itself has not yet been re-injected into the legacy ~15 MB target. The legacy path is still runtime-confirmed under v1.9.28, and CI preserves it, but do not claim a v1.9.33-on-15MB runtime regression pass until such a device run exists.
