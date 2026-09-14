# Development Changelog

## v1.9.33 OriginalByteResolver — compiled / awaiting device validation

Branch: `feature/hfamap-v1933-original-byte-resolver`
Build-tested commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`
Successful CI run: `34799869649`
Artifact ID: `10330589684`
Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`
Binary size: `175616` bytes
Binary SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`

### New v1.9.32 device evidence

Two ~5 MB games were retested with v1.9.32.

WayOfKings/iGMM path:
- `[AUTO-MENU-CANDIDATE] source=igmm-feature-array` appeared.
- `[AUTO-TRAVERSAL-END]` and `[AUTO-SCAN]` completed without a crash.
- `com.TornadoBear.WayOfKings_1.4.0_165.hfapatch.json` exported successfully with four iGMM features.

Runtime-record/Jailpatch path:
- `[AUTO-MENU-CANDIDATE] source=jailpatch-feature-array` appeared.
- `[AUTO-TRAVERSAL-END]` and `[AUTO-SCAN]` completed without a crash.
- Eight selector descriptors were recovered across three visible features.
- Generic decrypt resolution selected the image-local text fingerprint with `matches=1`.
- Offset and patch-data decrypt calls returned `rc=0`.
- `[FULL-SCAN-END]` reported `groups=3 mappings=8 valid=8 unresolved=0`.
- `HFAMap_Mapping.log` contains all eight valid mappings.

This runtime evidence confirms both the v1.9.32 Full Scan crash fix and the v1.9.31 generic secret-decrypt resolver.

### Remaining v1.9.32 package gap

The runtime-record scan exported only one package feature/patch even though all eight mappings were valid. Seven mappings logged:

`[PACKAGE-SKIP] ... reason=identity-or-original-unavailable`

The stable package path requires original bytes before a patch entry is emitted. The historical reader only attempted `vm_read_overwrite(slide + vmaddr)`, with no fallback. One mapping produced original bytes; seven did not.

### Added in v1.9.33

- `.github/scripts/hfamap_v1933_original_bytes.py`
  - Preserves v1.9.32 crash-safe scan behavior and v1.9.31 decrypt behavior.
  - Adds a multi-source original-byte resolver: live `vm_read_overwrite`, bounded readable `memcpy`, then Mach-O file translation.
  - File fallback parses Mach-O segments and refuses file bytes that overlap an active FairPlay encryption range.
  - If live bytes already equal the enabled patch, an available unencrypted file original may replace them.
  - Adds `[PACKAGE-ORIGINAL]` evidence including module, offset, byte count, image index, source, cryptid and status.
  - Does not remove the existing requirement for trustworthy original bytes.
- `.github/scripts/apply_hfamap_v1933_chain.py`
  - Replays the complete historical patch chain deterministically and snapshots the v1.9.32 generated sources before applying v1.9.33.
- `.github/workflows/theos-hfamap-v1933-original-byte-resolver.yml`
  - Verifies v1.9.32 `run_full_scan`, v1.9.31 decrypt functions, and package writer remain unchanged.
  - Verifies original-byte resolver invariants and rejects current-sample hardcoding.
  - Builds/signs arm64, checks SHA256, and uploads the artifact.

### Verification

- Historical patch chain: passed.
- v1.9.32 crash-safe Full Scan regression: passed.
- v1.9.31 decrypt resolver regression: passed.
- Package writer regression: passed.
- Original-byte resolver invariants: passed.
- Sample hardcode deny-list: passed.
- Compiled/linked/signed: yes, arm64.
- GitHub Actions: success (`34799869649`).
- Artifact uploaded: yes (`10330589684`).
- Artifact independently downloaded and re-hashed: passed.
- v1.9.33 device tested: no.

## Earlier checkpoints

- v1.9.32: both supplied 5 MB Full Scans are now device-stable; runtime-record generic decrypt is runtime-confirmed with 8/8 valid mappings; WayOfKings 4-feature iGMM package export remains working.
- v1.9.31: generic secret-decrypt resolver introduced; Full Scan regression prevented runtime validation until v1.9.32.
- v1.9.30: selector/secret-wrapper bridge device-confirmed; fixed decrypt locator failed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB AP/IGSecret path runtime-confirmed with 12 valid mappings and successful package export.
