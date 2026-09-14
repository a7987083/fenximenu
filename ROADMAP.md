# HFAMap Roadmap

## Current phase

v1.9.36.4 JSONExport — pure parser/exporter, CI passed, awaiting device validation.

## Product direction

HFAMapUniversal stays focused on:

`original menu -> parser -> evidence -> normalized JSON`

The runtime execution engine is not part of the parser mainline. v1.9.37/v1.9.37.1 merged playback/Dobby into the parser and crashed on device startup, so that direction is retired.

## Stable foundation

- Frozen parser baseline: v1.9.36 ArchitectureTruth, commit `75f94da37221343b6839465ad365ddec2679e63a`.
- Preserve constructor, `run_full_scan()` and resolver/decrypt/original-byte core exactly.
- Canonical static patches remain `com.hfa.patch/v1` with preferred Mach-O VM addresses.
- iGMM runtime behavior remains diagnostic-only under `com.hfa.igmm.runtime/v1`.
- Normalized cross-family analysis uses `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Device-confirmed checkpoint: v1.9.36.3

WayOfKings device archive confirmed:

- stable injection;
- Full Scan completion;
- four iGMM features;
- iGMM diagnostic JSON generation;
- normalized analysis JSON generation;
- Debug Menu correctly normalized as `button`;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction` while the raw primitive remains preserved;
- read-only identities for `libpathofkings.dylib` and `UnityFramework` match the expected UUID/arm64/cryptid evidence.

## Current milestone: v1.9.36.4

Completed in code/CI:

- preserve raw `executionPrimitive`;
- preserve raw `canonicalReason`;
- keep `normalizedExecutionPrimitive`;
- add `normalizedCanonicalReason` so normalized action semantics and normalized reason are consistent;
- observed `buttonBlock/runtimeAction` -> `runtime-action-not-static-bytes`;
- preserve read-only `targetIdentities`;
- no new constructor;
- no Dobby;
- no HFAPatchConsumer;
- no command polling;
- no runtime takeover.

Build checkpoint:

- branch: `feature/hfamap-v19361-json-export`;
- build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`;
- CI run: `34907671999` — success;
- artifact ID: `10372928333`;
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`;
- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`;
- size: `192432` bytes;
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

## Next validation: WayOfKings

Inject v1.9.36.4 and run the same Full Scan. Require:

1. no crash at injection/startup;
2. HFA floating window appears;
3. Full Scan completes;
4. `.hfamap.igmm.json` and `.hfamap.analysis.json` regenerate;
5. Debug Menu remains `control.kind = button`;
6. raw source primitive/reason remain visible;
7. `normalizedExecutionPrimitive = runtimeAction`;
8. `normalizedCanonicalReason = runtime-action-not-static-bytes`;
9. target identities remain identical to v1.9.36.3 evidence.

## Following validation

After WayOfKings passes:

1. regression-test the runtime-record/static 5 MB family and confirm canonical byte-patch export is unchanged;
2. regression-test the legacy ~15 MB family;
3. compare normalized analysis output across all three families;
4. only then consider this parser/exporter line a cross-family candidate.

## Deferred work

Execution of generated JSON remains a separate project/module. Do not merge it back into HFAMapUniversal without a separately device-validated integration design.
