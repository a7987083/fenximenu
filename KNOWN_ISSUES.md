# Known Issues

## v1.9.36 ArchitectureTruth

### v1.9.36 target-derived package architecture

Status: resolved on the supplied runtime-record and legacy 15 MB static samples.

Device evidence shows `PACKAGE-ARCH status=pass architecture=arm64 source=canonical-targets`, and persisted packages contain `architectures=["arm64"]` consistent with their resolved target identity.

### Runtime-record canonical truth on the supplied 5 MB sample

Status: resolved for current validation scope.

v1.9.36 device testing confirms:

- real `MH_EXECUTE` main image resolution;
- 3 semantic groups / 8 valid mappings;
- all 8 originals from the real executable using `vm-read`;
- canonical structure pass for 3 features / 8 patches;
- UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`;
- package architecture `arm64` from canonical targets;
- the 8 original values were independently verified against the same-UUID supplied Mach-O.

A later archive also confirms the original Jailpatch menu executes an ON/OFF roundtrip for all three static features and all eight mappings: every mapping appears as `active=1` and later `active=0`, with each feature event ending `GROUP ... status=EXECUTED`.

### Legacy ~15 MB current-binary regression

Status: resolved for canonical parity / runtime export.

The exact v1.9.36 binary was run on `com.notdoppler.earntodierogue1 1.28.251` and exported 12 features / 18 patches with canonical validation and target-derived architecture pass.

Target identity:

- image: `UnityFramework`;
- UUID: `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`;
- architecture: `arm64`;
- cpusubtype: `0`;
- preferred `__TEXT` VM: `0x0`;
- cryptid: `0`.

A full recursive JSON comparison against the previously supplied historical canonical package found exactly one changed value: `package.architectures[0]` changed from `arm64e` to `arm64`. All 12 feature definitions and all 18 patch tuples (`target/offset/original/enabled`) are otherwise identical.

Evidence boundary: the current regression archive did not include the matching UnityFramework Mach-O. Therefore this pass does not newly establish 18/18 independent file-level original-byte verification; it establishes runtime export and old-vs-new canonical parity.

### iGMM runtime features remain non-canonical static patches

Status: intentional / regression-confirmed under v1.9.36.

The supplied iGMM sample still exports only `com.hfa.igmm.runtime/v1` diagnostics. Damage and Defence are `numericRuntimeModifier`; God Mode and Button are `nativeHook`. All remain `canonicalEligible=false`, and no new iGMM `.hfapatch.json` is generated.

A feature may enter `com.hfa.patch/v1` only after a real portable static equivalent is proven.

### Independent consumer playback has not yet been validated

Status: open / primary remaining static-package gate.

The source-menu ON/OFF roundtrip is **not** the same as consumer playback. It proves that the original Jailpatch menu's own execution path applies and reverts the same eight mappings, but it does not prove that an independent consumer can safely execute the generated package.

Required consumer evidence is still missing:

1. the consumer opens the generated `.hfapatch.json`;
2. verifies target identity before any write;
3. verifies current bytes equal every declared `original`;
4. writes each `enabled` value;
5. re-reads and verifies the enabled bytes;
6. confirms the intended game behavior;
7. writes back each `original`;
8. re-reads and verifies restoration;
9. confirms behavior restoration;
10. fails closed on identity, original, write or revert mismatch.

The runtime-record package should be tested first because its original bytes are independently verified against the matching target Mach-O. The 15 MB package should follow when its matching UnityFramework binary/identity is available for the same byte-level precondition check.

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
5. independent consumer playback validation.

The first four are confirmed for the runtime-record sample. The source-menu roundtrip additionally confirms the source menu's apply/revert semantics, but the fifth remains open. The legacy 15 MB sample is currently confirmed for runtime export, canonical parity and architecture/identity metadata, but did not include its target binary for a new file-level original-byte recheck.

### Stale generated files can confuse validation

Status: test-environment hazard.

Before each regression or playback test, delete or move old `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files.

### Generalization beyond supplied samples

Status: open / future validation.

Current evidence covers the runtime-record 5 MB sample, the iGMM/native-hook 5 MB sample, the historical/current 15 MB family, plus two additional v1.9.36 UnityFramework static exports (Superstar and Backpack Brawl). Additional menu generations are still required before claiming universal Jailpatch coverage.

### CI delivery

Status: verified build.

Current binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`, successful run `34832916059`, artifact `10343305875`, SHA256 `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.
