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

## v1.9.36 device result

### Runtime-record / Dragons

Confirmed on device:

- `MAIN-IMAGE-RESOLVE` identifies `Dragons-prod-remote-nocheat` as the real bundle `MH_EXECUTE` image at dyld index 1.
- Generic secret decrypt remains `matches=1 / rc=0`.
- Full Scan remains 3 semantic groups / 8 valid mappings.
- All 8 `PACKAGE-ORIGINAL` records use the real game executable with `filetype=2`, `source=vm-read`, `status=ok`.
- `CANONICAL-CHECK` passes for 3 features / 8 patches / 1 target.
- Identity sidecar reports UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`.
- `PACKAGE-ARCH` reports `status=pass architecture=arm64 targets=1 source=canonical-targets`.
- Persisted package contains `architectures=["arm64"]`.
- Formal root/feature/patch keysets exactly match the canonical contract.
- 3 features / 8 patch records are otherwise identical to v1.9.35; only architecture metadata changed from arm64e to arm64.
- The 8 original values are unchanged from v1.9.35, where they were independently verified 8/8 against the supplied same-UUID Mach-O.

Conclusion: the supplied runtime-record 5 MB sample is now device-confirmed for structure, target identity, original-byte truth and architecture metadata under v1.9.36.

### iGMM / WayOfKings

Also regression-confirmed under v1.9.36:

- 4 runtime primitives exported to `com.hfa.igmm.runtime/v1`;
- Damage / Defence are `numericRuntimeModifier`;
- God Mode / Button are `nativeHook`;
- all remain `canonicalEligible=false`;
- no new canonical-looking iGMM `.hfapatch.json` is created.

## What is still not closed

- v1.9.36 itself has not been regression-tested on the legacy ~15 MB family; the historical 15 MB runtime confirmation remains v1.9.28.
- Consumer-level playback of a v1.9.36 static package is still pending.
- iGMM runtime hooks/modtext still have no proven portable static equivalent and must remain non-canonical.
- Additional menu generations are required before universal Jailpatch coverage can be claimed.

## Next task

Keep v1.9.36 unchanged as the current confirmed 5 MB checkpoint. Next inject this exact binary into the legacy ~15 MB target and verify its existing 12-feature canonical package. After that, perform consumer-level playback of the v1.9.36 runtime-record package.

## Verification discipline

- v1.9.36 source modified/committed: yes.
- compiled/linked/signed: yes.
- CI: passed.
- artifact independently re-hashed: passed.
- v1.9.36 runtime-record 5 MB device test: passed.
- v1.9.36 iGMM diagnostic-only regression: passed.
- v1.9.36 package architecture metadata: passed (`arm64`).
- v1.9.36 15 MB runtime regression: no.
- consumer playback: no.
- project final closure: no.
