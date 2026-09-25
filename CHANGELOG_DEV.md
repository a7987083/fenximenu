# Development Changelog

## HFARuntimeAnalyzer v0.3.3 — StaticParity AutoBackend

Branch: `feature/hfaruntime-v0.3.3-static-parity-autobackend`

Base: `cb04586dba45e1f57df4d1a2a76a54385d864066` (`v0.3.2 AutoBackend`)

Implementation commits:
- `160b939232727e3d9c99c4bd29bb57bb61622199` — static parity + Runtime State diagnostics;
- `e15f3226b48ca09d0fd2bb419e18836aee98bd49` — schema normalization fix;
- `806957d0ebe3ef13559d72809295bb6eeb69de09` — successful CI build wiring.

GitHub Actions run: `36161672792` — **success**

Artifact ID: `10876640401`

Artifact ZIP digest:
`sha256:3256b0704686508f411056593c9b1c68d31494a63ff502796e35a7138a8ee371`

Binary: `HFARuntimeAnalyzer-v0.3.3-StaticParity.dylib`

Binary size: `264992` bytes

Binary SHA-256:
`ed381292a594b3865194622141abcce29918e16d88092405c667d78519da6cca`

### Changed

- Aligned on-device descriptor discovery with the offline simulator's binary-first model: structural `length/flags/family` records are retained before plaintext/decrypt success is known.
- Changed the descriptor walk to the simulator-compatible 8-byte record alignment.
- Removed the v0.3.2 hard stop when `HFAV02ResolveDecrypt()` cannot resolve a decrypt routine.
- Added a unique-match static decrypt fingerprint fallback using the simulator signature; unresolved decrypt now records evidence instead of discarding all descriptors.
- Added per-record `decryptStatus` so structural discovery and plaintext confidence are kept separate.
- Preserved the universal second-button chain: selected menu dylib -> family parser -> AutoBackend.
- Added read-only `hookReturnEvidence` and `staticOverrideCandidates` for Runtime State backends. These are explicitly `diagnostic-only`; RogueLegend/MeChat are not promoted to canonical patches without additional device/binary evidence.
- Added `HFAMap_RuntimeAnalyzer_v033.json` while retaining compatibility outputs.
- Preserved per-app output routing through `HFAOutputPath()` under `Documents/HFAMap_<CFBundleIdentifier>/`; direct `Documents/HFAMap_*` output is rejected by CI.

### Verification

- generation chain: passed;
- v0.3.3 source marker and structural-parity gates: passed;
- universal AutoBackend entry gate: passed;
- bundle-folder output regression gate: passed;
- direct Documents output audit: passed;
- arm64 compile/link/strip/sign: passed;
- final binary marker inspection: passed;
- artifact upload/re-hash: passed;
- device runtime validation: **pending**.

### Next device matrix

1. Duck Survival / Path of Kings / Random Dice 2 / Heavenfall / PopIsland / WhisperCastle: require `V033-DECRYPT`, `V033-SCAN-END`, and `HFAMap_RuntimeAnalyzer_v033.json` for every selected dylib.
2. RogueLegend / MeChat: collect `hookReturnEvidence` and any `staticOverrideCandidates`; keep them unresolved unless semantics and original bytes close the evidence chain.
3. Earn to Die Rogue / Rise of Berk / ZombieCatchers / HelloKittyMyDreamStore / Legend of Survivors: no-regression reference set.

## v1.9.37.10 — verified Earn to Die Rogue Fuel/Boost profile

Branch: `feature/hfamap-v193710-unified-feature-model`

Baseline: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`

Implementation commit: `13fff6fd49d84348c618cc7845527e0b5c8413fa`

Build commit: `5db1f384c49a4a4cd243b722881083f0893692e5`

GitHub Actions run: `35170319783` — success

Artifact ID: `10476488771`

Artifact digest:
`sha256:3d64e19af748115b1b968ce98a99320948fbeb97d6b28cba4fb364546701b1d4`

Binary SHA-256:
`afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`

### Changed

- Added a post-v1.9.37.10 generation step that appends two exact-build static
  features only after bundle/version/architecture/UUID/original-byte checks.
- Added `Fuel`: RVA `0x2D98AC8`, original `0038211E`, enabled `1F2003D5`.
- Added `Boost`: RVA `0x2D9887C`, original `0038281E`, enabled `1F2003D5`.
- Added the binary/metadata evidence report and a machine-readable profile
  fixture.
- Added GitHub Actions assertions for the profile, UUID, RVAs, byte sequences
  and final binary markers.

### Verification

- GitHub remote branch/base commit check: passed;
- matching metadata pair: byte-identical, version 31;
- IL2CPP `Car.FixedUpdate()` mapping: passed;
- ARM64 disassembly/data-flow review: passed;
- existing canonical original bytes: `18/18` matched;
- new Fuel/Boost original bytes: `2/2` matched;
- full local generation chain: passed;
- generated-source fixture assertions: passed;
- Python syntax / JSON syntax / workflow YAML parse: passed;
- `git diff --check`: passed;
- iOS compile/link/sign: passed;
- downloaded artifact ZIP integrity/re-hash: passed;
- built arm64 Mach-O and profile marker inspection: passed;
- device runtime/regression: pending.

## v1.9.36.4 JSONExport — CI passed / WayOfKings device passed

Branch: `feature/hfamap-v19361-json-export`
Parser baseline: `v1.9.36 ArchitectureTruth @ 75f94da37221343b6839465ad365ddec2679e63a`
Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`
Successful CI run: `34907671999`
Artifact ID: `10372928333`
Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
Binary size: `192432` bytes
Binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`

### v1.9.36.4 device result

WayOfKings device archive `归档 6(1).zip` confirmed:

- injection did not crash;
- Full Scan completed;
- `com.hfa.igmm.runtime/v1` regenerated with 4 features;
- `com.hfa.menu.analysis/v1` regenerated;
- `JSON-EXPORT` reported `status=pass features=4 sources=1 targetIdentities=2`.

Normalized controls and evidence:

- Damage Multiplier: `modtext -> number`, default `1`;
- Defence Multiplier: `modtext -> number`, default `1`;
- God Mode: `customSwitch -> toggle`;
- Debug Menu: `kTypeButton -> button`;
- Debug Menu raw `executionPrimitive = nativeHook` preserved;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction`;
- Debug Menu raw `canonicalReason = runtime-hook-requires-portable-equivalent` preserved;
- Debug Menu `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- Damage/Defence normalized reason = `dynamic-numeric-state-not-static-bytes`;
- God Mode normalized reason = `runtime-hook-requires-portable-equivalent`.

Target identities remained stable:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype 6, text VM `0x0`, cryptid 0;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype 6, text VM `0x0`, cryptid 0.

Conclusion: the v1.9.36.4 WayOfKings/iGMM path is device-confirmed. No further WayOfKings normalizer changes are required without new contradictory evidence.

### Verification

- baseline constructor preserved: PASS;
- baseline `run_full_scan()` preserved: PASS;
- baseline trace/resolver core preserved: PASS;
- WayOfKings normalization fixture: PASS;
- analysis-only invariants: PASS;
- arm64 compile/link/strip/sign: PASS;
- no Dobby symbols in final binary: PASS;
- artifact upload/re-hash: PASS;
- v1.9.36.4 WayOfKings device validation: PASS;
- runtime-record/static 5 MB current-line regression: PENDING;
- legacy ~15 MB current-line regression: PENDING.

### v1.9.36.3 JSONExport — device passed on WayOfKings

- Added evidence-preserving `normalizedExecutionPrimitive`.
- Added read-only `targetIdentities`.
- Device archive confirmed stable startup, scan, button normalization and target identity output.

### v1.9.36.2 JSONExport — CI passed

- Added exact `kTypeButton -> button` normalization.

### v1.9.36.1 JSONExport — device tested on WayOfKings

- Rebased onto the stable v1.9.36 parser.
- Added analysis-only serializer after Full Scan.
- Device archive proved stable injection and JSON export, and exposed the `kTypeButton` gap.

## Retired experiment: v1.9.37 / v1.9.37.1

- Combined parser, dynamic JSON UI, playback consumer, Dobby and runtime takeover into one dylib.
- CI/build succeeded, but both device injections crashed at startup.
- Combined architecture abandoned for the HFAMapUniversal parser mainline.

## Earlier parser checkpoints

- v1.9.36: ArchitectureTruth frozen parser baseline.
- v1.9.35: MainImageTruth.
- v1.9.34: CanonicalTruthGate.
- v1.9.33: multi-source original-byte resolver.
- v1.9.32: crash-safe Full Scan.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
