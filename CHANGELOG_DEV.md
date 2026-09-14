# Development Changelog

## v1.9.36 ArchitectureTruth — static cross-family runtime regression confirmed

Branch: `feature/hfamap-v1936-architecture-truth`
Base: `feature/hfamap-v1935-main-image-truth @ 9556c223646c4dda12d566a1e65b8a4394bbb59d`
Build-tested commit: `75f94da37221343b6839465ad365ddec2679e63a`
Successful CI run: `34832916059`
Artifact ID: `10343305875`
Artifact digest: `sha256:db31af9643b24861fbb10a5408fa8605d5bc1812d47565450ac541a8fc6dcb4d`
Binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`
Binary size: `175664` bytes
Binary SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`

### Legacy ~15 MB regression / Earn to Die Rogue

The exact v1.9.36 binary was run against `com.notdoppler.earntodierogue1 1.28.251`.

- `FULL-SCAN-END`: `groups=12 mappings=18 valid=18 unresolved=0 packageFeatures=12`.
- `CANONICAL-CHECK`: pass for 12 features / 18 patches / 1 target.
- `TARGET-IDENTITY`: `UnityFramework`, UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x0`, `cryptid=0`.
- `PACKAGE-ARCH`: `status=pass architecture=arm64 targets=1 source=canonical-targets`.
- `PACKAGE-EXPORT`: success for 12 features / 1 target.
- Full recursive JSON comparison against the previously supplied canonical v1.9.28 package found exactly one changed value: `package.architectures[0]` changed from the historical `arm64e` metadata to the target-derived `arm64` value.
- All 12 feature definitions and all 18 patch records (`target/offset/original/enabled`) are otherwise byte-for-byte identical at the JSON value level.

The current 15 MB test archive did not include the matching `UnityFramework` Mach-O, so this validation does not newly claim 18/18 independent original-byte verification against the file. It is a canonical runtime regression/parity confirmation.

### Runtime-record / Dragons device result

v1.9.36 preserved the proven scan/decrypt/mapping/main-image/original-byte path and fixed the remaining package architecture metadata defect.

- `MAIN-IMAGE-RESOLVE`: real bundle executable, dyld image index 1, `Dragons-prod-remote-nocheat`, `MH_EXECUTE`.
- All 8 `PACKAGE-ORIGINAL` records: real game executable, `filetype=2`, `source=vm-read`, `status=ok`.
- `FULL-SCAN-END`: `groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`.
- `CANONICAL-CHECK`: pass for 3 features / 8 patches / 1 target.
- `TARGET-IDENTITY`: UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`.
- `PACKAGE-ARCH`: `status=pass architecture=arm64 targets=1 source=canonical-targets`.
- Persisted package `architectures=["arm64"]`.
- The 8 originals remain the same values previously verified byte-for-byte against the same-UUID supplied Mach-O.

### iGMM / WayOfKings regression

v1.9.36 preserved diagnostic-only behavior:

- 4 runtime features emitted to `com.hfa.igmm.runtime/v1`;
- Damage / Defence: `numericRuntimeModifier`;
- God Mode / Button: `nativeHook`;
- all `canonicalEligible=false`;
- no new iGMM `.hfapatch.json` generated.

### Additional v1.9.36 static samples

Two additional UnityFramework-target packages also completed canonical export under v1.9.36:

- `kr.co.dalcomsoft.superstar.i`: 2 features / 2 patches;
- `com.rapidfiregames.backpackbrawl`: 1 feature / 1 patch.

These provide extra current-build coverage but do not replace the legacy baseline parity test above.

### Remaining gate

- Consumer-level playback of a v1.9.36 canonical static package is still pending.
- iGMM runtime primitives remain non-canonical until a real portable static equivalent is proven.

Do not create a new implementation version merely because the 15 MB regression completed. Freeze v1.9.36 and proceed to consumer apply/revert validation; open a new branch only if playback exposes a concrete defect.

## Earlier checkpoints

- v1.9.35: fixed real `MH_EXECUTE` target resolution and original-byte truth; architecture metadata still wrong.
- v1.9.34: canonical structure and iGMM diagnostic isolation passed, but main-target byte truth exposed the dyld-index-0 defect.
- v1.9.33: runtime-record 5 MB reached 3 features / 8 structurally complete static patches.
- v1.9.32: fixed the common 5 MB Full Scan crash and confirmed generic decrypt + 8/8 mappings.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
