# HFAMap Roadmap

## Current phase

v1.9.35 MainImageTruth — compiled / CI passed / awaiting device validation

## Completed foundations

- Legacy ~15 MB static patch path remains runtime-confirmed under v1.9.28.
- 5 MB runtime-record menu discovery/decrypt/mapping is runtime-confirmed.
- 5 MB iGMM semantic/runtime-implementation discovery is runtime-confirmed.
- The canonical consumer contract is the 15 MB-style `com.hfa.patch/v1` static package.
- v1.9.34 device-tested the canonical structure gate and diagnostic-only iGMM separation.

## v1.9.34 device result

The iGMM half passed its intended truth policy: runtime primitives were exported only to `com.hfa.igmm.runtime/v1`, with no new canonical-looking iGMM `.hfapatch.json`.

The runtime-record half exposed a deeper historical defect. Although scan/decrypt/mapping and the canonical structural validator passed, `@main` was resolved through dyld image index 0. In the tested injection environment index 0 was an injected dylib, not the app executable. The identity sidecar therefore identified the wrong binary, and the same index contaminated original-byte reads. Some exported originals were unrelated ASCII-like data at statically confirmed code offsets.

Therefore v1.9.34 is not a trusted runtime-record canonical-package baseline.

## Current milestone: v1.9.35 MainImageTruth

Policy:

- `main` / `@main` must resolve to the real app `MH_EXECUTE`, never to a positional dyld index assumption.
- Prefer `NSBundle.mainBundle.executablePath` matched against loaded `MH_EXECUTE` images.
- Fall back only to a unique loaded `MH_EXECUTE`.
- Fail closed if main image identity is ambiguous or unresolved.
- Preserve preferred-Mach-O-VM-address offset semantics.
- Preserve v1.9.34 canonical structural gate and iGMM diagnostic isolation.
- Preserve v1.9.33 original-byte reader implementations; change only which image they read.

## Build checkpoint

- Branch: `feature/hfamap-v1935-main-image-truth`.
- Base commit: `7dd64cdafc45cf0017b9fb99a87b4bae84ee7758`.
- Build-tested code commit: `9b88d83919c824e371ebc3c21b70138a165b2ee5`.
- Successful CI run: `34830471085`.
- Artifact ID: `10341533093`.
- Artifact digest: `sha256:3426aad904df4e0bb2a7a9510a6eb0d8d97593041abe01e29c6606be044d0a83`.
- Binary: `HFAMapUniversal_v1.9.35_MainImageTruth.dylib`.
- Binary size: `175664` bytes.
- SHA256: `93c3670206bea50278a9e78e8b14d6aa96abea830818fecc022d15168cf9cf3f`.
- v1.9.35 device validation: pending.

## Next validation

First clear stale generated output files, then run the runtime-record/Dragons sample.

Required evidence:

1. `[MAIN-IMAGE-RESOLVE]` resolves to the actual game `MH_EXECUTE` image.
2. All `PACKAGE-ORIGINAL` records for `module=main` report that executable and filetype `2`.
3. Canonical validation still reports 3 features / 8 patches.
4. The identity sidecar resolves `@main` to the game executable and, for the supplied sample, reports preferred `__TEXT` VM address `0x100000000`.
5. Original bytes at the eight patch locations are plausible target code bytes and no longer reproduce the unrelated ASCII values observed under v1.9.34.

Then regression-test the WayOfKings/iGMM path and verify diagnostic-only behavior is unchanged.

After the two 5 MB paths pass, device-regression the legacy 15 MB family with the current binary. Final closure still requires all of those runtime gates; CI alone is insufficient.
