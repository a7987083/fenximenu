# Known Issues

## Current parser-only line: v1.9.36.4 JSONExport

### v1.9.36.4 WayOfKings/iGMM validation

Status: **passed / closed**.

Device archive `归档 6(1).zip` confirmed stable injection, Full Scan completion, 4-feature iGMM diagnostic export and normalized analysis export. It also confirmed:

- `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains preserved;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- `targetIdentities` resolves both `libpathofkings.dylib` and `UnityFramework` with the expected UUID/arm64/cryptid evidence;
- `JSON-EXPORT status=pass features=4 sources=1 targetIdentities=2`.

### Cross-family regression is still pending

Status: open / primary validation gate.

The current v1.9.36.4 parser has now passed the WayOfKings/iGMM family, but the same binary still must be regression-tested on:

- runtime-record/static 5 MB family;
- legacy ~15 MB family.

Do not claim universal/cross-family coverage until both current-line regressions pass.

### Target identities are analysis evidence, not execution authorization

Status: permanent rule.

Read-only UUID/architecture/filetype/preferred-`__TEXT`/cryptid records are for build matching and analysis quality only. They do not authorize hook installation or package execution.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device-confirmed.

WayOfKings uses runtime numeric/native-hook/block behavior. These records remain diagnostic and analysis-only and are not fabricated into `target/offset/original/enabled` static patches.

### v1.9.37 and v1.9.37.1 are retired from the parser mainline

Status: confirmed device startup failure / architecture reverted.

Those builds merged the independent playback/runtime consumer and Dobby into HFAMapUniversal. Both crashed immediately when injected. HFAMapUniversal remains a parser/exporter only.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing a new menu family, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs. A stale canonical package must never be mistaken for current output.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Runtime-record/static 5 MB regression

Status: open / next test.

The current v1.9.36.4 build must reproduce a trusted `com.hfa.patch/v1` package for the static 5 MB family. Required checks include real target identity, preferred VM offsets, original-byte truth and no stale-output contamination.

### Legacy ~15 MB regression

Status: open / follows the 5 MB static test.

The legacy AP/IGSecret family was previously runtime-confirmed on older parser versions. The current v1.9.36.4 binary must still prove that path has not regressed.

## Current CI delivery

Authoritative candidate:

- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
- run: `34907671999`
- artifact: `10372928333`
- binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`
- WayOfKings/iGMM device validation: passed
- cross-family regression: pending
