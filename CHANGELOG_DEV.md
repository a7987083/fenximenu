# Development Changelog

## v1.9.33 OriginalByteResolver — device runtime confirmed

Branch: `feature/hfamap-v1933-original-byte-resolver`
Build-tested commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`
Successful CI run: `34799869649`
Artifact ID: `10330589684`
Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`
Binary size: `175616` bytes
Binary SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`

### Runtime result

v1.9.33 was device-tested on both supplied ~5 MB games.

Runtime-record sample:

- `AUTO-MENU-CANDIDATE source=jailpatch-feature-array` reached `AUTO-TRAVERSAL-END` and `AUTO-SCAN` without a crash.
- `MAP-DECRYPT-RESOLVE` selected `mode=text-fingerprint matches=1`.
- `MAP-DECRYPT` returned `rc=0`.
- `FULL-SCAN-END` reported `groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`.
- All eight `PACKAGE-ORIGINAL` records reported `source=vm-read status=ok`.
- The generated package contains exactly 3 features with patch counts `1 + 6 + 1 = 8`.
- Each patch contains `target`, `offset`, `original`, and `enabled`; original/enabled byte lengths match and the byte sequences differ.

This closes the v1.9.32 package gap where seven valid mappings were skipped for missing original bytes.

WayOfKings/iGMM sample:

- `AUTO-MENU-CANDIDATE source=igmm-feature-array` reached `AUTO-TRAVERSAL-END` / `AUTO-SCAN` without a crash.
- The iGMM package still exports 4 runtime-definition features.
- `patches=[]` is expected for the iGMM runtime-definition backend; behavior is represented through runtime implementation metadata rather than static byte patches.

### Important scope note

The v1.9.33 fallback implementations (`readable memcpy` and cryptid-aware Mach-O file mapping) compiled and passed CI invariants, but this device run did not need them: all eight originals were recovered by the primary `vm-read` path. Therefore those fallback branches are build-verified, not runtime-confirmed.

## Earlier checkpoints

- v1.9.32: fixed the common Full Scan crash on both supplied 5 MB games; confirmed generic decrypt and 8/8 valid runtime-record mappings, but package aggregation was incomplete.
- v1.9.31: generic image-local decrypt resolver built; Full Scan crash prevented runtime validation.
- v1.9.30: selector/secret-wrapper bridge device-confirmed; fixed decrypt locator failed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB AP/IGSecret path runtime-confirmed with 12 valid mappings and successful package export.
