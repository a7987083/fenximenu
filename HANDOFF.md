# HFAMap Handoff

## Current branch

`feature/hfamap-v19361-json-export`

## Current direction

HFAMapUniversal is a **parser/exporter only**:

`original menu -> parser -> evidence -> normalized JSON`

The runtime-consumer/Dobby merge from v1.9.37 and v1.9.37.1 is retired after both builds crashed on device injection. The parser baseline is frozen v1.9.36 ArchitectureTruth commit `75f94da37221343b6839465ad365ddec2679e63a`. JSONExport versions must preserve the v1.9.36 constructor, `run_full_scan()` and resolver core.

## Device-confirmed checkpoint: v1.9.36.3

WayOfKings device archive confirmed:

- stable injection / no startup crash;
- Full Scan reached completion;
- `com.hfa.igmm.runtime/v1` was generated;
- `com.hfa.menu.analysis/v1` was generated;
- 4 features were exported;
- `Damage Multiplier`: `number`, default `1`;
- `Defence Multiplier`: `number`, default `1`;
- `God Mode`: `toggle`;
- `Debug Menu`: `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` stayed visible;
- normalized Debug Menu primitive = `runtimeAction`.

Target identity output was also device-confirmed:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`.

Observed implementation evidence remains diagnostic only:

- Damage/Defence/God share handler evidence around `libpathofkings.dylib + 0x4128`, with trampoline evidence toward `UnityFramework + 0x3BF6D94`;
- Debug Menu has `buttonBlock` evidence at `libpathofkings.dylib + 0x66B0`, nested handler `+0x66C4`, resolving to `UnityFramework + 0x3DEC9A0`.

## Current build: v1.9.36.4 JSONExport

- Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`.
- GitHub Actions run: `34907671999` — success.
- Artifact: `HFAMapUniversal-v1.9.36.4-JSONExport` (ID `10372928333`).
- Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`.
- Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`.
- Architecture: arm64 Mach-O dylib, NOUNDEFS.
- Size: `192432` bytes.
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

### v1.9.36.4 delta

v1.9.36.3 exposed one analysis-layer wording mismatch: Debug Menu was correctly normalized to `runtimeAction`, but the raw source `canonicalReason` still described the source classifier's `nativeHook` result. v1.9.36.4 preserves the raw field and adds a parallel normalized field:

- raw `canonicalReason`: unchanged source evidence;
- `normalizedCanonicalReason`: interpretation consistent with `normalizedExecutionPrimitive`;
- observed button block -> `runtime-action-not-static-bytes`.

No resolver, startup, hook or execution behavior is added.

## Output contract

Normal scan outputs may include:

- `HFAMap_Learn.log`
- `HFAMap_MenuMap.jsonl`
- `HFAMap_JailpatchMap.jsonl`
- canonical `*.hfapatch.json` only when true static byte patches are proven
- `*.hfapatch.identity.json` for canonical identity when available
- `*.hfamap.igmm.json` for iGMM runtime diagnostics
- `*.hfamap.analysis.json` for normalized analysis-only descriptions

The normalized schema remains `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Next device test

Test `HFAMapUniversal_v1.9.36.4_JSONExport.dylib` on WayOfKings. Require all v1.9.36.3 evidence to remain stable and additionally require Debug Menu:

- raw `canonicalReason` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`.

Then regression-test the runtime-record/static 5 MB family and legacy ~15 MB family.

## Verification discipline

- v1.9.36 parser baseline: frozen/reference.
- v1.9.36.1 WayOfKings startup/scan/export: passed.
- v1.9.36.3 WayOfKings startup/scan/normalized controls/target identities: **device passed**.
- v1.9.36.4 compile/link/sign: passed.
- v1.9.36.4 CI: passed on run `34907671999`.
- v1.9.36.4 artifact re-hash: passed.
- v1.9.36.4 device validation: pending.
- v1.9.37/v1.9.37.1 runtime merge: failed on device / retired.
