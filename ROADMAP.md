# HFAMap Roadmap

## v2.1.0 first-pass analyzer

Implemented on `feature/hfamap-v2-bounded-universal-analyzer`: short main-thread snapshot, worker-side bounded descriptor analysis, Objective-C family structure evidence, and live detailed diagnostics. Local unit tests and the 11-dylib family regression pass.

Next gates:

1. arm64 Theos CI compile/link/sign;
2. Legacy AP device scan with all diagnostic outputs;
3. Jailpatch device scan and external `loadConfig:` owner evidence;
4. only then add a selected-image-only observer for the verified configuration boundary.

## Current phase — v1.9.37.10 Earn to Die Rogue completion

Branch: `feature/hfamap-v193710-unified-feature-model`

Baseline commit: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`

Verified-profile implementation commit:
`13fff6fd49d84348c618cc7845527e0b5c8413fa`

The `com.notdoppler.earntodierogue` `1.28.251 (1)` scan originally exported
12 canonical features and treated Fuel/Boost as runtime-observed records with
empty patch arrays. Matching IL2CPP metadata and ARM64 data-flow analysis now
prove both are static depletion sites in `Car.FixedUpdate()`.

Current milestone:

- append `Unlimited Fuel` at `UnityFramework + 0x2D98AC8`;
- append `Unlimited Boost` at `UnityFramework + 0x2D9887C`;
- replace only the relevant `fsub` with ARM64 `nop` (`1F2003D5`);
- require exact bundle version, arm64 architecture, UnityFramework UUID and
  original-byte matches before either patch is exported;
- preserve generic resolver behavior for every other title/build.

Next tasks:

1. run a clean device scan and require 14 canonical features / 20 patches;
2. enable Fuel and Boost separately before depletion and verify values/HUD;
3. disable both and verify original-byte restoration;
4. reproduce and resolve the existing Posters/Prestige overlap at
   `UnityFramework + 0x2E25904`.

CI checkpoint:

- run: `35170319783` — success;
- artifact: `10476488771`;
- artifact digest:
  `sha256:3d64e19af748115b1b968ce98a99320948fbeb97d6b28cba4fb364546701b1d4`;
- dylib SHA-256:
  `afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`.

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
# v2 bounded analyzer roadmap

1. ~~Pass arm64 Theos compile/link/sign CI on the new branch.~~ Completed in run `35186351403`.
2. Validate correct dylib selection and bounded completion on one 14 MiB legacy-ap sample.
3. Validate the same on one 5.75 MiB Jailpatch sample.
4. Use process logs to identify the exact registration/decryption boundary only for families whose descriptors remain runtime-generated.
5. Add a manual candidate picker for legitimate score ties.
6. Promote only after canonical records are independently checked against the target image bytes.

Current next task: add a selected-image-only, read-only observer at the verified `loadConfig:` / runtime-table
boundary. The v2.0.1 five-device matrix completed without hangs or truncation and selected the intended payloads,
but every target still exported zero static descriptors. First fix the pre-policy `selected` event label, then
capture registration arguments and table ownership without invoking unknown getters or scanning process-wide state.
