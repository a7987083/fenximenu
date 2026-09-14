# HFAMap Handoff

## Current branch

`feature/hfamap-v19361-json-export`

## Current direction

HFAMapUniversal is a **parser/exporter only**:

`original menu -> parser -> evidence -> normalized JSON`

The runtime-consumer/Dobby merge from v1.9.37 and v1.9.37.1 is retired after both builds crashed on device injection. The frozen parser baseline is v1.9.36 ArchitectureTruth commit `75f94da37221343b6839465ad365ddec2679e63a`. JSONExport versions must preserve the v1.9.36 constructor, `run_full_scan()` and resolver core.

## Current build: v1.9.36.4 JSONExport

- Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`.
- GitHub Actions run: `34907671999` — success.
- Artifact: `HFAMapUniversal-v1.9.36.4-JSONExport` (ID `10372928333`).
- Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`.
- Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`.
- Architecture: arm64 Mach-O dylib, NOUNDEFS.
- Size: `192432` bytes.
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

## WayOfKings / iGMM device validation: PASSED

Device archive `归档 6(1).zip` confirms v1.9.36.4 itself on device:

- injection stayed stable; no startup crash;
- Full Scan reached completion;
- `com.hfa.igmm.runtime/v1` regenerated;
- `com.hfa.menu.analysis/v1` regenerated;
- `IGMM-RUNTIME-EXPORT` reported `features=4`;
- `JSON-EXPORT` reported `status=pass features=4 sources=1 targetIdentities=2`.

Normalized controls:

- `Damage Multiplier`: `number`, default `1`;
- `Defence Multiplier`: `number`, default `1`;
- `God Mode`: `toggle`;
- `Debug Menu`: source `kTypeButton` -> normalized `button`.

Evidence-preserving primitive/reason handling is now device-confirmed:

- Debug Menu raw `executionPrimitive = nativeHook` remains visible;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction`;
- Debug Menu raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains visible;
- Debug Menu `normalizedCanonicalReason = runtime-action-not-static-bytes`.

Other normalized reasons also remain consistent:

- Damage / Defence -> `dynamic-numeric-state-not-static-bytes`;
- God Mode -> `runtime-hook-requires-portable-equivalent`.

Target identities remain correct on device:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype `6`, preferred `__TEXT` VM `0x0`, cryptid `0`.

Observed implementation evidence remains diagnostic only:

- Damage/Defence/God share handler evidence around `libpathofkings.dylib + 0x4128`, with trampoline evidence toward `UnityFramework + 0x3BF6D94`;
- Debug Menu has `buttonBlock` evidence at `libpathofkings.dylib + 0x66B0`, nested handler `+0x66C4`, resolving to `UnityFramework + 0x3DEC9A0`.

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

## Next validation

WayOfKings tuning is complete for this parser line. Do not keep changing the iGMM normalizer without new contradictory evidence.

Next use the **same v1.9.36.4 dylib** for cross-family regression:

1. runtime-record/static 5 MB family: require correct canonical `com.hfa.patch/v1`, target identity, preferred VM offsets, and original-byte truth;
2. legacy ~15 MB family: require the historical static patch path to remain functional;
3. compare normalized analysis output across all three families.

## Verification discipline

- v1.9.36 parser baseline: frozen/reference.
- v1.9.36.1 WayOfKings startup/scan/export: passed.
- v1.9.36.3 WayOfKings controls/target identities: device passed.
- v1.9.36.4 compile/link/sign: passed.
- v1.9.36.4 CI: passed on run `34907671999`.
- v1.9.36.4 artifact re-hash: passed.
- v1.9.36.4 WayOfKings device validation: **passed**.
- runtime-record/static 5 MB current-line regression: pending.
- legacy ~15 MB current-line regression: pending.
- v1.9.37/v1.9.37.1 runtime merge: failed on device / retired.
