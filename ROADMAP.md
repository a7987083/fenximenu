# HFAMap Roadmap

## Current phase

v1.9.36 ArchitectureTruth — static cross-family runtime regression confirmed / independent consumer playback pending

## Completed foundations

- Legacy ~15 MB static patch path was historically runtime-confirmed under v1.9.28.
- 5 MB runtime-record discovery/decrypt/mapping is runtime-confirmed.
- 5 MB iGMM semantic/runtime-implementation discovery is runtime-confirmed.
- The canonical consumer contract is the 15 MB-style `com.hfa.patch/v1` static package.
- v1.9.34 device-confirmed strict canonical structure and diagnostic-only iGMM separation.
- v1.9.35 device-confirmed real `MH_EXECUTE` main resolution and correct original-byte acquisition.
- v1.9.36 device-confirmed target-derived package architecture metadata.
- The exact v1.9.36 binary has now also regression-exported the legacy 15 MB canonical package.
- The original Dragons Jailpatch menu has a device-confirmed ON/OFF roundtrip for all 3 static features / all 8 mappings under the same v1.9.36 instrumentation.

## Current static checkpoint: v1.9.36

### Runtime-record / Dragons

Passes current truth gates:

1. real `MH_EXECUTE` target resolution;
2. generic decrypt and 8/8 valid mappings;
3. originals read from the real target;
4. exact canonical JSON structure;
5. UUID/cpusubtype/preferred-VM identity sidecar;
6. package architecture derived from canonical targets;
7. persisted `architectures=["arm64"]` matching the actual target;
8. 8 original values independently static-file verified against the same-UUID Mach-O;
9. source-menu runtime roundtrip observed for every feature: active=1 then active=0 across all 1+6+1 mappings.

The source-menu roundtrip is not independent consumer playback. It confirms the original menu's semantics and apply/revert path, but the final gate requires a separate consumer to read and execute the generated `.hfapatch.json` with its own identity/original/write/revert verification.

### iGMM / WayOfKings

Remains deliberately non-canonical: four runtime primitives export only to `com.hfa.igmm.runtime/v1`, with no fabricated static `.hfapatch.json`.

### Legacy ~15 MB / Earn to Die Rogue

Current v1.9.36 device regression passed:

- 12 groups / 18 valid mappings / 12 package features;
- canonical check pass for 12 features / 18 patches;
- target `UnityFramework` identity resolved as UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, arm64, cpusubtype 0, preferred text VM `0x0`, cryptid 0;
- package architecture pass from canonical target;
- package export success.

Full recursive comparison against the previously supplied v1.9.28 canonical JSON found exactly one value difference: `package.architectures[0]` changed from `arm64e` to the correct target-derived `arm64`. All 12 feature definitions and all 18 patch records are otherwise identical.

The current 15 MB regression archive did not include the matching UnityFramework Mach-O, so a new 18/18 file-level original-byte verification was not performed in this pass.

### Additional v1.9.36 coverage

- Superstar: 2 features / 2 patches, canonical export pass.
- Backpack Brawl: 1 feature / 1 patch, canonical export pass.

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

## Next milestone: independent consumer playback

Do not alter v1.9.36 in place unless independent playback exposes a reproducible defect.

Validation order:

1. Use the intended consumer against the v1.9.36 runtime-record `.hfapatch.json` and matching target identity.
2. Require pre-apply byte verification against every `original`.
3. Apply the `enabled` bytes and re-read memory to verify the write.
4. Verify the intended game behavior.
5. Restore `original` bytes and re-read memory to verify restoration.
6. Verify behavior restoration.
7. Fail closed on identity, original-byte, write or revert mismatch.
8. Repeat the same consumer flow on the legacy 15 MB package when the matching UnityFramework binary/identity is available for independent byte verification.
9. Only after static playback passes should a separate branch investigate portable equivalents for individual iGMM runtime primitives.

## Final closure criteria

Project closure still requires:

- independent same-consumer canonical apply/revert playback for static packages;
- fail-closed identity/original validation in the consumer;
- no fabricated static representation for unresolved iGMM runtime primitives;
- additional cross-sample validation before any universal Jailpatch claim.
