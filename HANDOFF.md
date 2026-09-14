# HFAMap Handoff

## Current branch

`feature/hfamap-v1935-main-image-truth`

## Current build

- Base: `feature/hfamap-v1934-unified-canonical-exporter @ 7dd64cdafc45cf0017b9fb99a87b4bae84ee7758`.
- Build-tested code commit: `9b88d83919c824e371ebc3c21b70138a165b2ee5`.
- GitHub Actions run: `34830471085` — success.
- Artifact: `HFAMapUniversal-v1.9.35-MainImageTruth` (ID `10341533093`).
- Artifact digest: `sha256:3426aad904df4e0bb2a7a9510a6eb0d8d97593041abe01e29c6606be044d0a83`.
- Binary: `HFAMapUniversal_v1.9.35_MainImageTruth.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175664` bytes.
- SHA256: `93c3670206bea50278a9e78e8b14d6aa96abea830818fecc022d15168cf9cf3f`.

## Canonical contract

The formal `.hfapatch.json` contract remains the static 15 MB shape:

`schema/name/package/targets/features`
→ feature `id/title/group/defaultEnabled/patches`
→ patch `target/offset/original/enabled`.

Canonical offsets are Mach-O preferred VM addresses. Runtime addresses and file offsets are not written into this field.

## What v1.9.34 device testing proved

### Runtime-record / Dragons

Passed:

- crash-safe semantic scan;
- selector descriptor discovery;
- generic secret decrypt (`matches=1`, `rc=0`);
- 3 groups / 8 valid mappings;
- strict canonical structural check for 3 features / 8 patches.

Failed:

- `@main` identity resolved to the injected `systemhook.dylib` rather than the actual `MH_EXECUTE` game image;
- preferred text VM address was therefore reported as `0x0` instead of the game executable's preferred VM;
- original-byte acquisition inherited the same `main -> dyld index 0` assumption and produced unrelated bytes, including ASCII-like data at statically confirmed executable offsets.

Conclusion: the v1.9.34 runtime-record package is structurally canonical but not byte-truthworthy and must not be promoted.

### iGMM / WayOfKings

Passed:

- semantic menu discovery and scan stability;
- per-feature execution-primitive classification;
- diagnostic-only `com.hfa.igmm.runtime/v1` output;
- no new canonical-looking `.hfapatch.json` from the iGMM fallback.

The iGMM path remains deliberately non-canonical until a real portable static equivalent is proven for an individual runtime primitive.

## v1.9.35 MainImageTruth

The main-image resolver no longer assumes dyld image index 0.

Resolution policy:

1. obtain `NSBundle.mainBundle.executablePath`;
2. inspect loaded Mach-O images with `filetype == MH_EXECUTE`;
3. prefer the executable whose path or basename matches the bundle executable;
4. otherwise use a unique `MH_EXECUTE` only;
5. fail closed on no match or ambiguity.

Both `main` and `@main` use this resolver. Named dylib/framework targets keep their existing name-based resolution.

The corrected image index feeds the unchanged v1.9.33 original readers and the v1.9.34 identity writer. Canonical export also refuses `@main` unless it resolves to `MH_EXECUTE`.

## Required device validation

Delete or move old generated `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files before testing.

Test the runtime-record sample first. Require:

`[MAIN-IMAGE-RESOLVE] status=resolved`
→ resolved image is the actual game executable and filetype is `MH_EXECUTE`
→ each `[PACKAGE-ORIGINAL]` for module `main` reports that same executable and filetype `2`
→ `[CANONICAL-CHECK] status=pass`
→ identity sidecar resolves `@main` to the actual executable, not an injected dylib
→ for the supplied Dragons sample, preferred `__TEXT` VM address should be `0x100000000`
→ exported originals at the eight known executable offsets must be instruction bytes, not the prior unrelated ASCII-like values.

Only after this passes, regression-test WayOfKings and confirm it still produces `.hfamap.igmm.json` without an iGMM `.hfapatch.json`.

A later 15 MB run is still required before promoting v1.9.35 as the cross-family runtime candidate.

## Verification discipline

- v1.9.34 device-tested: yes.
- v1.9.34 iGMM diagnostic isolation: passed.
- v1.9.34 runtime-record scan/decrypt/mapping: passed.
- v1.9.34 canonical structure: passed.
- v1.9.34 main target identity/original-byte truth: failed.
- v1.9.35 source modified/committed: yes.
- v1.9.35 compiled/linked/signed: yes.
- v1.9.35 CI: passed on run `34830471085`.
- v1.9.35 artifact independently re-hashed: passed.
- v1.9.35 device-tested: no.
- v1.9.35 15 MB runtime regression: no.
- project final closure: no.
