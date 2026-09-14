# Known Issues

## v1.9.36 ArchitectureTruth

### v1.9.36 target-derived package architecture is not yet device-confirmed

Status: open / primary validation gate.

The candidate removes the last known dyld-index-0 dependency from formal package metadata. `package.architectures` is now derived from the resolved canonical targets, with fail-closed handling for unresolved, non-ARM64 or mixed target architectures. CI passes, but device evidence is still required.

### v1.9.35 package architecture metadata was wrong

Status: confirmed defect / fixed in v1.9.36 candidate.

v1.9.35 device testing proved the real target is `arm64 / cpusubtype=0`, while the generated package still declared `architectures=["arm64e"]`. Source inspection found `HFAWritePatchPackage` still used `_dyld_get_image_header(0)` for this field. This did not corrupt the now-correct patch bytes, but it made package metadata inconsistent with target identity.

### v1.9.35 main target identity/original-byte truth is confirmed

Status: resolved for the supplied Dragons sample.

All eight runtime-record mappings used `image=Dragons-prod-remote-nocheat filetype=2`. The identity sidecar UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8` matches the supplied target Mach-O, and all eight exported `original` values match that file byte-for-byte at their preferred VM addresses.

This supersedes the v1.9.34 defect where `main/@main` resolved to an injected dylib through dyld image index 0 and produced unrelated bytes.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device behavior confirmed under v1.9.34.

The supplied iGMM sample uses runtime numeric/native-hook behavior. It exports to `com.hfa.igmm.runtime/v1` diagnostics and does not produce a canonical-looking iGMM `.hfapatch.json`. A feature may enter `com.hfa.patch/v1` only after a real portable static equivalent is proven.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A trusted static package requires all of the following:

1. canonical JSON structure;
2. resolved target identity consistent with the declared image;
3. original bytes read from that target;
4. package architecture consistent with the target Mach-O;
5. consumer playback validation.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing v1.9.36, delete or move old `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks remain compiled and CI-verified. Current successful Dragons evidence used the primary `vm-read` path for all eight originals.

### v1.9.36 has not been runtime-regression-tested on ~15 MB

Status: open.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28. A current-binary 15 MB device regression remains required before cross-family promotion.

### Generalization beyond supplied samples

Status: open / future validation.

Current evidence covers one runtime-record 5 MB sample, one iGMM/native-hook 5 MB sample, and the legacy 15 MB family. Additional menu generations are still required before claiming universal Jailpatch coverage.

### CI delivery

Status: intentional.

Verified candidate binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`, successful run `34832916059`, artifact `10343305875`, SHA256 `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`.
