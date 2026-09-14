# HFAMap Roadmap

## Current phase

v1.9.36 ArchitectureTruth — compiled / CI passed / awaiting device validation

## Completed foundations

- Legacy ~15 MB static patch path remains runtime-confirmed under v1.9.28.
- 5 MB runtime-record menu discovery/decrypt/mapping is runtime-confirmed.
- 5 MB iGMM semantic/runtime-implementation discovery is runtime-confirmed.
- The canonical consumer contract is the 15 MB-style `com.hfa.patch/v1` static package.
- v1.9.34 device-tested the canonical structure gate and diagnostic-only iGMM separation.
- v1.9.35 device-confirmed real `MH_EXECUTE` main resolution and correct original-byte acquisition on the Dragons sample.

## v1.9.35 device result

The runtime-record path now resolves `main` to the actual game executable, not dyld index 0. The identity sidecar UUID matches the supplied target Mach-O, and all eight exported originals match that same file exactly at their preferred VM addresses.

One metadata defect remained: package `architectures` was still derived from `_dyld_get_image_header(0)` and reported `arm64e` while the actual target identity is `arm64 / cpusubtype=0`.

## Current milestone: v1.9.36 ArchitectureTruth

Policy:

- canonical package architecture comes from the actual resolved canonical targets;
- every target must resolve and be ARM64;
- all targets in one package must agree on one architecture;
- unresolved, non-ARM64 or mixed target architecture fails closed;
- preserve v1.9.35 main-image truth and all previous runtime evidence.

Implementation:

- remove the final package-writer dependency on dyld image index 0;
- derive `arm64` / `arm64e` from each target header resolved through `HFAImageIndexForName`;
- log `[PACKAGE-ARCH]` success/failure evidence;
- leave the actual patch bytes, offsets, target identity sidecar, decrypt and iGMM behavior unchanged.

## Build checkpoint

- Branch: `feature/hfamap-v1936-architecture-truth`.
- Base commit: `9556c223646c4dda12d566a1e65b8a4394bbb59d`.
- Build-tested code commit: `75f94da37221343b6839465ad365ddec2679e63a`.
- Successful CI run: `34832916059`.
- Artifact ID: `10343305875`.
- Artifact digest: `sha256:db31af9643b24861fbb10a5408fa8605d5bc1812d47565450ac541a8fc6dcb4d`.
- Binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`.
- Binary size: `175664` bytes.
- SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.
- v1.9.36 device validation: pending.

## Next validation

Clear stale generated outputs, then run Dragons/runtime-record.

Required evidence:

1. `MAIN-IMAGE-RESOLVE` still identifies the actual `MH_EXECUTE` game image.
2. All eight `PACKAGE-ORIGINAL` records still use that image and `filetype=2`.
3. `CANONICAL-CHECK` remains 3 features / 8 patches.
4. `PACKAGE-ARCH` reports `status=pass architecture=arm64 source=canonical-targets`.
5. `package.architectures` is `["arm64"]`, matching the identity sidecar.
6. Identity UUID/cpusubtype/textVM remains unchanged and all eight originals still match the same-UUID file.

Then regression-test WayOfKings and confirm diagnostic-only output remains unchanged.

After both 5 MB paths pass, device-regression the current binary on the legacy 15 MB family. Final project closure still requires those runtime gates and a consumer-level canonical playback test.
