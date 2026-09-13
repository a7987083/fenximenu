# Known Issues

## v1.9.32 CrashSafeFullScan

### v1.9.31 Auto Detect / Full Scan crashed on both supplied ~5 MB games

Status: root cause narrowed / mitigation built / v1.9.32 device validation pending.

The two v1.9.31 logs share the same failure shape: the actual semantic menu target was found in window index 0, but Full Scan continued into unrelated windows and terminated before `[AUTO-TRAVERSAL-END]` and `[AUTO-SCAN]`. One crashing game had `records=0`, so generic secret-decrypt invocation cannot be the common cause.

Historical source review found an unsafe scan path inherited from v1.9.24: `igmm_probe_target` could deep-traverse every custom control target and enumerate object ivars through UIKit/framework superclasses. Objective-C `@try/@catch` cannot catch an `EXC_BAD_ACCESS` caused by invalid raw object graph traversal.

v1.9.32 removes that deep probe from Auto Detect, uses semantic feature-array confirmation for early stop, and bounds superclass ivar traversal at framework classes. This is compiled and CI-verified but not yet device-confirmed.

### Generic 5 MB decrypt resolution is still not runtime-confirmed

Status: open / deferred until scan stability is proven.

v1.9.31 added image-local `__TEXT,__text` fingerprint resolution for the secret decrypt routine. The two Full Scan crashes happened before scan finalization, and one sample never entered the runtime-record decrypt path at all. Therefore the crash does not invalidate the decrypt resolver, but it also did not validate it. v1.9.32 preserves `HFAResolveSecretDecrypt` and `HFADecryptWrapper` byte-for-byte.

After Full Scan is stable, require `[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1` and `[MAP-DECRYPT] rc=0` before declaring decrypt success.

### Historical deep iGMM probe remains in source as inactive diagnostic code

Status: intentionally inactive.

The old `igmm_probe_target` implementation is retained for historical/diagnostic reference but is marked unused and is not called from Auto Detect. CI explicitly fails if `igmm_probe_target(o);` reappears in the generated Full Scan path.

### Semantic early stop depends on a populated feature array

Status: expected design constraint.

The crash-safe early stop only fires after the original menu has populated its feature array. Open the original menu before running `Auto Detect / Full Scan`. If no semantic feature array exists yet, the scan can continue looking for one.

### Two ~5 MB menu paths remain supported

Status: understood / regression requirement.

One supplied sample uses runtime records and the selector/decrypt path. Another supplied sample also exposes the stricter iGMM feature array and has previously generated a `.hfapatch.json` package through the existing iGMM implementation/target-chain exporter. v1.9.32 preserves `HFAWriteIGMMPackage` byte-for-byte and still calls `HFARegisterIGMMFeatureArray` when semantic iGMM validation succeeds.

### Patch-data candidate inference requires uniqueness

Status: intentionally conservative / confirmed for previously observed runtime records.

The selector resolver registers patch data only when exactly one remaining `secret` wrapper exists after excluding `offset` and `signature`. Ambiguous cases remain evidence-only.

### Important Jailpatch object ivars use stripped type metadata

Status: understood / handled.

Relevant object ivars may be declared as `@"?"`. Current discovery relies on semantic selectors, live object behavior, and bounded runtime structure rather than declared class names.

### v1.9.32 has not been runtime-regression-tested on ~15 MB

Status: open / low priority.

The legacy 15 MB architecture remains runtime-confirmed under v1.9.28. CI preserves the legacy mapping/exporter and v1.9.31 decrypt functions, but v1.9.32 itself has not been injected into a 15 MB target; do not claim a v1.9.32-on-15MB runtime regression pass.

### CI first attempt failed on inactive-function warning

Status: resolved.

Run `34790683599` passed behavior/invariant checks but failed compilation because removing the old Auto Detect call made `igmm_probe_target` an unused static function under `-Werror`. The function was marked `__attribute__((unused))` without reactivating it. Final run `34790789928` passed compile/link/sign/hash/artifact upload.

### CI delivery remains artifact-only

Status: resolved / intentional.

The repository Actions token has read-only Contents permission. Verified binaries are distributed through GitHub Actions artifacts rather than workflow pushes back into the branch.
