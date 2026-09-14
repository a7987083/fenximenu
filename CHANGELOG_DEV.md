# Development Changelog

## v1.9.36 ArchitectureTruth — device-confirmed on both supplied 5 MB samples

Branch: `feature/hfamap-v1936-architecture-truth`
Base: `feature/hfamap-v1935-main-image-truth @ 9556c223646c4dda12d566a1e65b8a4394bbb59d`
Build-tested commit: `75f94da37221343b6839465ad365ddec2679e63a`
Successful CI run: `34832916059`
Artifact ID: `10343305875`
Artifact digest: `sha256:db31af9643b24861fbb10a5408fa8605d5bc1812d47565450ac541a8fc6dcb4d`
Binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`
Binary size: `175664` bytes
Binary SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`

### Runtime-record / Dragons device result

v1.9.36 preserved the proven scan/decrypt/mapping/main-image/original-byte path and fixed the remaining package architecture metadata defect.

- `MAIN-IMAGE-RESOLVE`: real bundle executable, dyld image index 1, `Dragons-prod-remote-nocheat`, `MH_EXECUTE`.
- All 8 `PACKAGE-ORIGINAL` records: real game executable, `filetype=2`, `source=vm-read`, `status=ok`.
- `FULL-SCAN-END`: `groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`.
- `CANONICAL-CHECK`: pass for 3 features / 8 patches / 1 target.
- `TARGET-IDENTITY`: UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`.
- `PACKAGE-ARCH`: `status=pass architecture=arm64 targets=1 source=canonical-targets`.
- Persisted package `architectures=["arm64"]`.
- Exact canonical keysets remain intact: root `schema/name/package/targets/features`; feature `id/title/group/defaultEnabled/patches`; patch `target/offset/original/enabled`.
- 3 features / 8 patch records are otherwise identical to v1.9.35. The only formal package delta is `architectures: arm64e -> arm64`.
- The 8 originals remain the same values previously verified byte-for-byte against the same-UUID supplied Mach-O.

This closes the v1.9.35 architecture metadata defect on the supplied runtime-record sample.

### iGMM / WayOfKings regression

v1.9.36 preserved diagnostic-only behavior:

- 4 runtime features emitted to `com.hfa.igmm.runtime/v1`;
- Damage / Defence: `numericRuntimeModifier`;
- God Mode / Button: `nativeHook`;
- all `canonicalEligible=false`;
- no new iGMM `.hfapatch.json` generated.

### Remaining gates

- v1.9.36 has not yet been injected into the legacy ~15 MB target.
- Consumer-level playback of the v1.9.36 static package is still pending.
- iGMM runtime primitives remain non-canonical until a real portable static equivalent is proven.

## v1.9.35 MainImageTruth — device-tested / main and original-byte truth passed / architecture metadata failed

v1.9.35 fixed real `MH_EXECUTE` target resolution and restored correct originals. Eight of eight exported originals were independently verified against the same-UUID supplied Mach-O. Its remaining `package.architectures=["arm64e"]` defect is resolved by v1.9.36.

## v1.9.34 CanonicalTruthGate — device tested / partial pass

- iGMM diagnostic isolation: passed.
- runtime-record scan/decrypt/mapping and canonical structure: passed.
- main target identity/original-byte truth: failed due to historical dyld-index-0 assumption.

## Earlier checkpoints

- v1.9.33: runtime-record 5 MB reached 3 features / 8 structurally complete static patches.
- v1.9.32: fixed the common 5 MB Full Scan crash and confirmed generic decrypt + 8/8 mappings.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
