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
- Architecture: arm64 Mach-O dylib.
- Size: `175664` bytes.
- SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.

## Canonical contract

Formal `.hfapatch.json` remains the 15 MB static shape:

`schema/name/package/targets/features`
→ feature `id/title/group/defaultEnabled/patches`
→ patch `target/offset/original/enabled`.

Offsets are Mach-O preferred VM addresses. Binary identity and architecture must agree with the actual resolved target image.

## Latest device result: v1.9.35

### Runtime-record / Dragons

Confirmed:

- semantic scan / selector / generic decrypt remain stable;
- 3 groups / 8 valid mappings;
- strict canonical structural check passes for 3 features / 8 patches;
- `main` resolves to `Dragons-prod-remote-nocheat` at dyld image index 1, filetype `MH_EXECUTE`;
- identity sidecar reports UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM `0x100000000`, `cryptid=0`;
- the UUID matches the supplied target Mach-O;
- all eight exported `original` byte strings match that same file exactly at their preferred VM addresses.

Therefore v1.9.35 fixed the main-image and original-byte truth problem exposed by v1.9.34.

Still wrong in v1.9.35:

- `package.architectures` reported `arm64e` even though target identity is `arm64`.
- Source inspection found `HFAWritePatchPackage` still used `_dyld_get_image_header(0)` solely for architecture metadata.

### iGMM / WayOfKings

The v1.9.34 diagnostic-only policy remains device-confirmed: runtime primitives export to `com.hfa.igmm.runtime/v1`, with no new canonical-looking iGMM `.hfapatch.json`.

## v1.9.36 ArchitectureTruth

Only the package architecture source changes.

- Resolve every canonical target through the existing v1.9.35 image resolver.
- Derive `arm64` vs `arm64e` from each resolved target Mach-O header.
- Require all canonical targets to agree on one ARM64 architecture.
- Fail closed on unresolved, non-ARM64, or mixed target architectures.
- Emit `[PACKAGE-ARCH]` evidence.

The main-image resolver, original-byte readers, canonical validator, iGMM diagnostic writer, decrypt path and crash-safe Full Scan are CI-protected unchanged.

## Required device validation

Clear old generated outputs, then test Dragons/runtime-record first. Require:

`[MAIN-IMAGE-RESOLVE]` → actual game executable
→ all 8 `[PACKAGE-ORIGINAL]` records remain on that executable with `filetype=2`
→ `[CANONICAL-CHECK] status=pass features=3 patches=8`
→ `[PACKAGE-ARCH] status=pass architecture=arm64 targets=1 source=canonical-targets`
→ identity sidecar remains UUID/cpusubtype/textVM-correct
→ package `architectures` becomes `["arm64"]`
→ all 8 originals remain byte-identical to the same-UUID target Mach-O.

Then regression-test WayOfKings diagnostic-only behavior. A current-binary 15 MB device regression is still required before cross-family promotion.

## Verification discipline

- v1.9.35 device-tested: yes.
- v1.9.35 main target identity: passed.
- v1.9.35 original-byte truth: passed and independently static-file verified 8/8.
- v1.9.35 package architecture metadata: failed.
- v1.9.36 source modified/committed: yes.
- v1.9.36 compiled/linked/signed: yes.
- v1.9.36 CI: passed.
- v1.9.36 artifact independently re-hashed: passed.
- v1.9.36 device-tested: no.
- v1.9.36 15 MB runtime regression: no.
- project final closure: no.
