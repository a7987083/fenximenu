# HFAMap Handoff

## Current branch

`feature/hfamap-v1936-architecture-truth`

## Current build

- Base: `feature/hfamap-v1935-main-image-truth @ 9556c223646c4dda12d566a1e65b8a4394bbb59d`.
- Build-tested code commit: `75f94da37221343b6839465ad365ddec2679e63a`.
- GitHub Actions run: `34832916059` — success.
- Artifact: `HFAMapUniversal-v1.9.36-ArchitectureTruth` (ID `10343305875`).
- Artifact digest: `sha256:db31af9643b24861fbb10a5408fa8605d5bc1812d47565450ac541a8fc6dcb4d`.
- Binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`.
- Size: `175664` bytes.
- SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.

## Canonical contract

Formal `.hfapatch.json` remains the 15 MB static shape:

`schema/name/package/targets/features`
→ feature `id/title/group/defaultEnabled/patches`
→ patch `target/offset/original/enabled`.

Offsets are Mach-O preferred VM addresses. Binary identity, original bytes and package architecture must all come from the actual resolved target image.

## Current runtime checkpoint: v1.9.36

### Runtime-record / Dragons

Confirmed on device:

- real `MH_EXECUTE` main resolution;
- generic decrypt `matches=1 / rc=0`;
- 3 semantic groups / 8 valid mappings;
- all 8 originals read from the real executable;
- exact canonical structure for 3 features / 8 patches;
- UUID/cpusubtype/preferred-VM identity sidecar;
- `PACKAGE-ARCH status=pass architecture=arm64`;
- persisted package `architectures=["arm64"]`;
- all 8 original values previously static-file verified against the same-UUID target Mach-O.

### iGMM / WayOfKings

Regression-confirmed under v1.9.36:

- 4 runtime primitives exported to `com.hfa.igmm.runtime/v1`;
- Damage / Defence are `numericRuntimeModifier`;
- God Mode / Button are `nativeHook`;
- all remain `canonicalEligible=false`;
- no new canonical-looking iGMM `.hfapatch.json` is created.

### Legacy ~15 MB / Earn to Die Rogue

The exact v1.9.36 binary now has current-device regression evidence on `com.notdoppler.earntodierogue1 1.28.251`:

- `FULL-SCAN-END`: 12 groups / 18 mappings / 18 valid / 12 package features;
- `CANONICAL-CHECK`: pass for 12 features / 18 patches / 1 target;
- `TARGET-IDENTITY`: `UnityFramework`, UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, arm64, cpusubtype 0, preferred text VM `0x0`, cryptid 0;
- `PACKAGE-ARCH`: pass, arm64, canonical-target-derived;
- `PACKAGE-EXPORT`: success.

A full recursive JSON diff against the previously supplied v1.9.28 canonical package found exactly one changed value: `package.architectures[0]` is now `arm64` instead of the historical `arm64e`. All 12 feature definitions and all 18 patch tuples `target/offset/original/enabled` are identical.

Important evidence boundary: the current 15 MB archive contains logs/JSON/identity but not the matching `UnityFramework` binary, so this pass does not newly claim 18/18 independent original-byte verification against the Mach-O file.

### Additional current-build static coverage

- Superstar sample: 2 features / 2 patches, canonical export pass.
- Backpack Brawl sample: 1 feature / 1 patch, canonical export pass.

## What is still not closed

- Consumer-level playback of the canonical package is not yet validated.
- iGMM runtime hooks/modtext still have no proven portable static equivalent and remain non-canonical.
- Additional menu generations are still required before any universal Jailpatch claim.

## Next task

Freeze v1.9.36. Do not open a new implementation branch unless playback exposes a concrete defect.

Perform consumer-level playback first on the runtime-record package whose 8 originals are independently verified against the same target Mach-O:

1. resolve/verify target identity;
2. verify current bytes equal each `original` before apply;
3. apply each `enabled` patch;
4. verify intended game behavior;
5. restore each `original` patch;
6. verify behavior restoration;
7. record apply/revert failures fail-closed.

Then repeat the same consumer path on the legacy 15 MB package when the matching `UnityFramework` target binary/identity is available for independent original-byte verification.

## Verification discipline

- v1.9.36 source modified/committed: yes.
- compiled/linked/signed: yes.
- CI: passed.
- artifact independently re-hashed: passed.
- runtime-record 5 MB device test: passed.
- iGMM diagnostic-only regression: passed.
- legacy 15 MB current-binary canonical regression: passed.
- 15 MB old-vs-new package parity: 12/12 features and 18/18 patch records identical; architecture metadata corrected arm64e -> arm64.
- 15 MB 18/18 original bytes independently checked against Mach-O in this run: no, target binary absent from archive.
- consumer playback: no.
- project final closure: no.
