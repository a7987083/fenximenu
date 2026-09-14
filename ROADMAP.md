# HFAMap Roadmap

## Current phase

v1.9.36.4 JSONExport — pure parser/exporter, CI passed, **WayOfKings/iGMM device validation passed**, cross-family regression next.

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

## Current milestone: v1.9.36.4

Build checkpoint:

- branch: `feature/hfamap-v19361-json-export`;
- build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`;
- CI run: `34907671999` — success;
- artifact ID: `10372928333`;
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`;
- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`;
- size: `192432` bytes;
- SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`.

## WayOfKings/iGMM validation: COMPLETE

Device archive `归档 6(1).zip` confirmed:

- stable injection / no startup crash;
- Full Scan completion;
- 4-feature iGMM diagnostic export;
- normalized analysis export with `status=pass`;
- `Damage Multiplier -> number`, default `1`;
- `Defence Multiplier -> number`, default `1`;
- `God Mode -> toggle`;
- `Debug Menu: kTypeButton -> button`;
- raw Debug Menu primitive/reason preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- target identities for `libpathofkings.dylib` and `UnityFramework` remain correct.

The iGMM path should now be treated as a completed regression checkpoint for this parser line unless new contradictory device evidence appears.

## Next validation: runtime-record/static 5 MB family

Use the same v1.9.36.4 binary. Required evidence:

1. no startup crash;
2. Full Scan completes;
3. canonical `com.hfa.patch/v1` is generated only after the existing truth gates pass;
4. the target image is the intended executable/dylib, not an injected module;
5. target identity UUID/architecture/preferred `__TEXT` values are consistent with the tested binary;
6. every exported `original` byte sequence matches the real target code at the preferred Mach-O VM address;
7. no stale package from a previous run is mistaken for current output;
8. normalized `com.hfa.menu.analysis/v1` reflects the canonical features without changing the static patch contract.

## Following validation: legacy ~15 MB family

After the static 5 MB family passes:

1. run the same v1.9.36.4 parser on the legacy AP/IGSecret-style sample;
2. confirm the historically working static package path still exports correctly;
3. compare control/patch/identity normalization across the 15 MB, static 5 MB and iGMM families;
4. only then promote this parser/exporter line as a cross-family candidate.

## Deferred work

Execution of generated JSON remains a separate project/module. Do not merge it back into HFAMapUniversal without a separately device-validated integration design.
