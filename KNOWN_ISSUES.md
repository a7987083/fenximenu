# Known Issues

## v1.9.36 ArchitectureTruth

### v1.9.36 target-derived package architecture

Status: resolved on the supplied runtime-record 5 MB sample.

Device evidence now shows `PACKAGE-ARCH status=pass architecture=arm64 targets=1 source=canonical-targets`, and the persisted package contains `architectures=["arm64"]`. This matches the identity sidecar's `arm64 / cpusubtype=0` target. The v1.9.35 architecture metadata defect is closed for this sample.

### Runtime-record canonical truth on the supplied 5 MB sample

Status: resolved for current validation scope.

v1.9.36 device testing confirms:

- real `MH_EXECUTE` main image resolution;
- 3 semantic groups / 8 valid mappings;
- all 8 originals from the real executable using `vm-read`;
- canonical structure pass for 3 features / 8 patches;
- UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`;
- package architecture `arm64` from canonical targets;
- exact patch records otherwise unchanged from v1.9.35, where the 8 original values were independently verified against the same-UUID supplied Mach-O.

### iGMM runtime features remain non-canonical static patches

Status: intentional / regression-confirmed under v1.9.36.

The supplied iGMM sample still exports only `com.hfa.igmm.runtime/v1` diagnostics. Damage and Defence are `numericRuntimeModifier`; God Mode and Button are `nativeHook`. All remain `canonicalEligible=false`, and no new iGMM `.hfapatch.json` is generated.

A feature may enter `com.hfa.patch/v1` only after a real portable static equivalent is proven.

### Consumer playback has not yet been validated

Status: open / primary static-package gate.

A package can now satisfy structure, target identity, byte truth and architecture truth, but final consumer behavior still needs direct validation. The next static-package gate is to load/apply/revert the v1.9.36 runtime-record package with the intended consumer against the matching target identity.

### v1.9.36 has not been runtime-regression-tested on ~15 MB

Status: open / primary cross-family gate.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28 with 12 features. The exact v1.9.36 binary still needs to be injected into that family before the current build can be promoted as a cross-family runtime checkpoint.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks remain compiled and CI-verified. Current successful Dragons evidence used the primary `vm-read` path for all eight originals.

### Canonical structural validity alone is insufficient

Status: permanent verification rule.

A trusted static package requires all of the following:

1. canonical JSON structure;
2. resolved target identity consistent with the declared image;
3. original bytes from that target;
4. package architecture consistent with the target Mach-O;
5. consumer playback validation.

The first four are now confirmed for the supplied runtime-record sample under v1.9.36; the fifth remains open.

### Stale generated files can confuse validation

Status: test-environment hazard.

Before each regression or playback test, delete or move old `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files.

### Generalization beyond supplied samples

Status: open / future validation.

Current evidence covers one runtime-record 5 MB sample, one iGMM/native-hook 5 MB sample, and the historical 15 MB family. Additional menu generations are still required before claiming universal Jailpatch coverage.

### CI delivery

Status: verified build.

Current binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`, successful run `34832916059`, artifact `10343305875`, SHA256 `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.
