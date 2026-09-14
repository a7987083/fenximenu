# Development Changelog

## v1.9.35 MainImageTruth — compiled / CI passed / awaiting device validation

Branch: `feature/hfamap-v1935-main-image-truth`
Base: `feature/hfamap-v1934-unified-canonical-exporter @ 7dd64cdafc45cf0017b9fb99a87b4bae84ee7758`
Build-tested commit: `9b88d83919c824e371ebc3c21b70138a165b2ee5`
Successful CI run: `34830471085`
Artifact ID: `10341533093`
Binary: `HFAMapUniversal_v1.9.35_MainImageTruth.dylib`
Binary size: `175664` bytes
Binary SHA256: `93c3670206bea50278a9e78e8b14d6aa96abea830818fecc022d15168cf9cf3f`

### Device evidence that forced v1.9.35

v1.9.34 was tested on both supplied ~5 MB families.

Runtime-record sample:

- Full Scan stayed stable and retained the proven selector/decrypt/mapping chain.
- `FULL-SCAN-END` reported `groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`.
- `CANONICAL-CHECK` reported `status=pass` for 3 features / 8 patches.
- However, the identity sidecar declared `@main` while resolving the target to `systemhook.dylib`, with preferred `__TEXT` VM address `0x0`.
- Source inspection confirmed the historical resolver returned dyld image index 0 for `main`, and the v1.9.34 identity writer independently hardcoded index 0 for `@main`.
- The same wrong index fed the original-byte reader. Exported originals at known executable code points included `4531454E53395F31` and `70726F706F736564`, which decode as unrelated ASCII-like data rather than ARM64 instructions.

Therefore v1.9.34 proved the structural contract gate but failed binary identity/original-byte truth for main-executable targets. Its runtime-record `.hfapatch.json` must not be treated as trusted canonical output.

WayOfKings/iGMM sample:

- semantic discovery and Full Scan remained stable;
- all four features were classified as runtime primitives;
- `com.hfa.igmm.runtime/v1` diagnostic output was generated;
- no new iGMM `.hfapatch.json` was created.

This part of v1.9.34 passed device validation.

### v1.9.35 fix

`main` and `@main` no longer mean dyld image index 0.

`HFAMainExecutableImageIndex` now:

1. reads `NSBundle.mainBundle.executablePath`;
2. scans loaded images for `filetype == MH_EXECUTE`;
3. prefers the MH_EXECUTE image whose path/basename matches the bundle executable;
4. otherwise accepts only a unique loaded MH_EXECUTE image;
5. fails closed if the executable cannot be established unambiguously.

The corrected resolver is shared by:

- runtime-record module resolution;
- original-byte acquisition;
- canonical target validation;
- identity-sidecar generation.

`PACKAGE-ORIGINAL` logging now records the resolved source image and Mach-O filetype, and canonical export refuses an `@main` target that does not resolve to `MH_EXECUTE`.

The v1.9.33 multi-source original readers themselves are byte-preserved; only the image-index source is corrected.

### Verification

- First v1.9.35 CI run `34830298479`: failed before compilation because the patch script attached one preflight anchor at the wrong v1.9.34 source location. This was an implementation-script anchor issue, not a compiler/runtime result.
- Corrected run `34830471085`: passed historical replay, protected-function regressions, MainImageTruth invariants, v1.9.34 truth-gate preservation, arm64 compile/link/sign, distributable validation and artifact upload.
- Artifact was independently downloaded and re-hashed; SHA256 matched CI.
- v1.9.35 device validation: pending.

## v1.9.34 CanonicalTruthGate — device tested / partial pass, byte truth failed

- iGMM diagnostic isolation: passed on device.
- runtime-record scan/decrypt/mapping: passed on device.
- canonical structural contract: passed on device.
- `@main` binary identity: failed because dyld image index 0 was not the app executable in the injected environment.
- original-byte truth for main target: failed for the same reason.
- canonical runtime-record package: not trusted.

## Earlier checkpoints

- v1.9.33: runtime-record 5 MB reached 3 features / 8 structurally complete static patches; later v1.9.34 truth instrumentation exposed the inherited main-image-index assumption in original acquisition.
- v1.9.32: fixed the common 5 MB Full Scan crash and confirmed generic decrypt + 8/8 mappings.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
