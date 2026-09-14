# HFAMap Roadmap

## Current phase

v1.9.33 OriginalByteResolver — complete runtime-record package aggregation

## Completed milestone: legacy AP / ~15 MB

v1.9.28 remains runtime-confirmed with 12 valid mappings and successful `.hfapatch.json` export.

Formal regression baseline:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestones: 5 MB runtime-record path

- v1.9.29: runtime-record structure, feature arrays, selector surface and secret wrappers confirmed.
- v1.9.30: selector descriptor and offset/patch-wrapper association confirmed.
- v1.9.31: generic image-local decrypt resolver implemented.
- v1.9.32: Full Scan crash fixed and device-confirmed on both supplied 5 MB games.
- v1.9.32 runtime-record sample: generic decrypt confirmed with `matches=1`, `rc=0`, and 8/8 valid mappings across 3 feature groups.
- v1.9.32 WayOfKings sample: semantic iGMM scan remains stable and its four-feature package export remains working.

## Current remaining gap

The runtime-record sample has eight valid mappings, but v1.9.32 package aggregation exported only one patch. Seven valid mappings were omitted because original bytes were unavailable to the strict package writer.

The mapping resolver itself is no longer the blocker.

## Current milestone: v1.9.33 OriginalByteResolver

Policy:

- Preserve v1.9.32 crash-safe scan exactly.
- Preserve v1.9.31 generic decrypt exactly.
- Preserve the package schema/writer safety rule: every patch requires trustworthy original bytes.
- Add multiple original-byte sources: live VM read, readable direct memory, then cryptid-aware Mach-O file mapping.
- Refuse on-disk fallback when the requested bytes overlap active FairPlay encryption.
- Emit `[PACKAGE-ORIGINAL]` evidence for every valid mapping.
- Do not hardcode current game/image/feature names or observed addresses.

## Build checkpoint

- Branch: `feature/hfamap-v1933-original-byte-resolver`.
- Build-tested code commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`.
- CI run: `34799869649` — success.
- Artifact ID: `10330589684`.
- Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`.
- SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.
- v1.9.32 Full Scan regression: passed.
- v1.9.31 decrypt regression: passed.
- package writer regression: passed.
- original-byte resolver invariants: passed.
- v1.9.33 device validation: pending.

## Next task

Run v1.9.33 on the runtime-record 5 MB game and require:

`[AUTO-MENU-CANDIDATE]` → `[AUTO-TRAVERSAL-END]` → `[AUTO-SCAN]`

plus the already-confirmed decrypt/mapping chain, then inspect `[PACKAGE-ORIGINAL]` for all 8 mappings. The preferred completion criterion is a package with 3 semantic features containing all 8 patch records.

After that, retest WayOfKings once to preserve its four-feature iGMM package regression checkpoint.
