# HFAMap Roadmap

## Current phase

v1.9.36 ArchitectureTruth — 5 MB device-confirmed / 15 MB regression and consumer playback pending

## Completed foundations

- Legacy ~15 MB static patch path remains runtime-confirmed under v1.9.28.
- 5 MB runtime-record discovery/decrypt/mapping is runtime-confirmed.
- 5 MB iGMM semantic/runtime-implementation discovery is runtime-confirmed.
- The canonical consumer contract is the 15 MB-style `com.hfa.patch/v1` static package.
- v1.9.34 device-confirmed strict canonical structure and diagnostic-only iGMM separation.
- v1.9.35 device-confirmed real `MH_EXECUTE` main resolution and correct original-byte acquisition.
- v1.9.36 device-confirmed target-derived package architecture metadata.

## Current confirmed 5 MB checkpoint: v1.9.36

Runtime-record / Dragons now passes all current truth gates:

1. real `MH_EXECUTE` target resolution;
2. generic decrypt and 8/8 valid mappings;
3. original bytes read from the real target;
4. exact canonical JSON structure;
5. UUID/cpusubtype/preferred-VM identity sidecar;
6. package architecture derived from canonical targets;
7. persisted `architectures=["arm64"]` matching the actual target;
8. unchanged 3-feature / 8-patch data from v1.9.35, whose originals were static-file verified 8/8 against the same UUID.

WayOfKings/iGMM also remains correctly separated: four runtime primitives export only to `com.hfa.igmm.runtime/v1`, with no canonical `.hfapatch.json` fabricated for unresolved hooks/modifiers.

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
- v1.9.36 supplied 5 MB device validation: passed.

## Next milestone

Do not alter the proven v1.9.36 5 MB truth path in place.

Next validation order:

1. Inject the exact v1.9.36 binary into the legacy ~15 MB target.
2. Confirm its historical 12-feature canonical package still exports correctly under the current binary.
3. Perform consumer-level playback of the v1.9.36 runtime-record static package and verify patch application/reversion behavior against the same target identity.
4. Only after those pass, consider a new branch for portable-equivalent research on individual iGMM runtime primitives.

## Final closure criteria

Project closure still requires:

- current-binary 15 MB runtime regression;
- same-consumer canonical playback for static packages;
- no fabricated static representation for unresolved iGMM runtime primitives;
- additional cross-sample validation before any universal Jailpatch claim.
