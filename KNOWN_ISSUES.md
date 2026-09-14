# Known Issues

## Current parser-only line: v1.9.36.4 JSONExport

### v1.9.36.4 device validation is pending

Status: open / primary validation gate.

v1.9.36.4 is built from the frozen v1.9.36 parser path and passed CI, compile/link/sign and no-Dobby checks. It only adds analysis-layer normalization. Device validation is still required before v1.9.36.4 can be called runtime-confirmed.

### v1.9.36.3 WayOfKings is device-confirmed

Status: passed.

The supplied device archive confirmed stable injection, Full Scan completion, iGMM diagnostic export and normalized analysis export with four features. It also confirmed:

- Debug Menu `kTypeButton -> button`;
- raw `executionPrimitive = nativeHook` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction` for the observed `buttonBlock`;
- target identity resolution for both `libpathofkings.dylib` and `UnityFramework` with the expected UUIDs and arm64/cryptid evidence.

### Raw and normalized canonical reasons intentionally coexist

Status: fixed in v1.9.36.4 / device confirmation pending.

v1.9.36.3 correctly preserved the raw iGMM classifier evidence, but that meant Debug Menu still carried raw `canonicalReason = runtime-hook-requires-portable-equivalent` even though the normalized primitive was `runtimeAction`. v1.9.36.4 does not overwrite the raw field; it adds `normalizedCanonicalReason`. The observed button block becomes `runtime-action-not-static-bytes` in the normalized layer.

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

Before testing a new parser version, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Current parser has not yet been regression-tested across all menu families

Status: open.

- WayOfKings/iGMM: v1.9.36.3 device-confirmed; v1.9.36.4 pending.
- Runtime-record/static 5 MB family: current-line regression pending.
- Legacy ~15 MB family: current-line regression pending.

Do not claim universal coverage until the current parser-only line passes all three families.

## Current CI delivery

Authoritative candidate:

- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
- run: `34907671999`
- artifact: `10372928333`
- binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`
