# HFAMap Roadmap

## Current phase

v1.9.33 OriginalByteResolver — 5 MB runtime milestone complete

## Completed milestone: legacy AP / ~15 MB

v1.9.28 is runtime-confirmed with 12 valid mappings and successful patch-package export.

Formal stable baseline remains:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestone: Jailpatch runtime-record / ~5 MB

Progression:

- v1.9.29: runtime-record object graph and stable selector surface established.
- v1.9.30: selector descriptor and offset/patch-wrapper association device-confirmed.
- v1.9.31: image-local decrypt fingerprint resolver built; unrelated Full Scan crash blocked runtime validation.
- v1.9.32: semantic crash-safe Full Scan confirmed on both supplied games; generic decrypt reached `matches=1 / rc=0`; runtime-record sample produced 8/8 valid mappings, but only one patch entered the package.
- v1.9.33: package original-byte acquisition completed the runtime-record path.

Current confirmed runtime-record result:

`semantic menu discovery`
→ `selector descriptor`
→ `secret wrapper association`
→ `image-local decrypt fingerprint`
→ `rc=0 plaintext`
→ `3 groups / 8 valid mappings`
→ `8 trusted original-byte reads`
→ `3 features / 8 patches exported`.

## Completed milestone: iGMM / WayOfKings ~5 MB

The independent iGMM path remains runtime-confirmed under v1.9.33 with four runtime-definition features and successful package export. `patches=[]` is expected for this representation.

## Build checkpoint

- Branch: `feature/hfamap-v1933-original-byte-resolver`.
- Build-tested code commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`.
- CI run: `34799869649` — success.
- Artifact ID: `10330589684`.
- Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`.
- SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.
- Device validation: passed for both supplied 5 MB paths.

## Next work

Do not extend v1.9.33 in place. Use a new branch for any new work.

Priorities:

1. Optional v1.9.33-on-15MB device regression to promote the current binary, not only v1.9.28, on the legacy family.
2. Additional 5 MB samples to test how broadly the selector/decrypt/original-byte strategy generalizes beyond the two supplied games.
3. Exercise the `memcpy` and cryptid-aware Mach-O original-byte fallbacks on a sample where live `vm-read` is insufficient; they are currently build-verified but not runtime-confirmed.
