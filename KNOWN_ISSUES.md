# Known Issues

## v1.9.35 MainImageTruth

### v1.9.35 main-executable resolver is not yet device-confirmed

Status: open / primary validation gate.

The candidate replaces all known `main -> dyld image index 0` assumptions with an `NSBundle.mainBundle.executablePath` + `MH_EXECUTE` resolver, and CI verifies the historical index-0 patterns are absent from the generated source. The dylib compiles, signs and passes regression checks, but device evidence is still required before the fix can be called runtime-confirmed.

### v1.9.34 main target identity/original bytes were wrong

Status: confirmed defect / fixed in v1.9.35 candidate / device validation pending.

v1.9.34 device testing showed that `@main` resolved to `systemhook.dylib` because the identity writer hardcoded dyld image index 0. Source inspection also found the older `HFAImageIndexForName("main") -> 0` assumption, so runtime-record original-byte acquisition used the same wrong loaded image.

The exported package consequently contained unrelated bytes at statically confirmed executable patch offsets, including `4531454E53395F31` and `70726F706F736564`. Therefore the v1.9.34 runtime-record package is structurally canonical but not trusted as a byte-correct package.

v1.9.35 routes both `main` and `@main` through the real `MH_EXECUTE` resolver and fails closed if the executable cannot be identified unambiguously.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device behavior confirmed under v1.9.34.

The supplied iGMM sample uses runtime numeric/native-hook behavior. v1.9.34 correctly exported four features only to `com.hfa.igmm.runtime/v1` diagnostics and produced no new iGMM `.hfapatch.json`. v1.9.35 preserves that policy.

A future feature can enter `com.hfa.patch/v1` only after a real portable static `target/offset/original/enabled` equivalent is proven. Runtime hook metadata must not be converted into fabricated patch bytes.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

v1.9.34 demonstrated that a package can satisfy exact JSON keys, valid hex lengths and known target IDs while still reading bytes from the wrong Mach-O. Canonical acceptance therefore requires both:

1. structural contract validation; and
2. resolved target binary identity consistent with the declared target.

For `@main`, the resolved image must be `MH_EXECUTE`.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing v1.9.35, delete or move old generated `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files. Otherwise a v1.9.34 package can be mistaken for the new candidate's output.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks from v1.9.33 remain compiled and CI-verified. The new v1.9.35 change does not rewrite those readers; it corrects the loaded-image index supplied to them. Their fallback branches still need dedicated runtime evidence if `vm-read` is insufficient on a future sample.

### v1.9.35 has not been runtime-regression-tested on ~15 MB

Status: open.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28. A current-binary 15 MB device regression is still required before v1.9.35 can be promoted as the cross-family runtime candidate.

### Generalization beyond supplied samples

Status: open / future validation.

The architecture is currently grounded in one runtime-record 5 MB sample, one iGMM/native-hook 5 MB sample, and the legacy 15 MB family. Additional menu generations are still needed before claiming universal Jailpatch coverage.

### CI delivery

Status: intentional.

Verified candidate binary: `HFAMapUniversal_v1.9.35_MainImageTruth.dylib`, successful run `34830471085`, artifact `10341533093`, SHA256 `93c3670206bea50278a9e78e8b14d6aa96abea830818fecc022d15168cf9cf3f`.

The earlier v1.9.35 run `34830298479` failed before compilation because of a patch-script anchor mismatch and is not the authoritative build.
