# Development Changelog

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

## v1.9.36.3 JSONExport — device passed on WayOfKings

- Added evidence-preserving `normalizedExecutionPrimitive`.
- Added read-only `targetIdentities`.
- Device archive confirmed stable startup, scan, button normalization and target identity output.

## v1.9.36.2 JSONExport — CI passed

- Added exact `kTypeButton -> button` normalization.

## v1.9.36.1 JSONExport — device tested on WayOfKings

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
# v2.0.0-dev — bounded universal analyzer

- Replaced the compiled legacy/generator chain with four explicit v2 modules.
- Removed recursive app-directory scanning, whole-file mapping, process-wide class scans, unknown getter invocation and broad runtime hooks from the active path.
- Added loaded-image, named-section menu discovery with hard image/byte/time limits.
- Added multi-evidence family classification and ambiguity rejection.
- Added same-descriptor name/offset/patch extraction plus unique executable-range and live-byte validation.
- Split canonical, analysis and process-log outputs.
- Added a read-only host triage tool, synthetic parser tests and a 10-sample SHA/family regression manifest.
- Fixed four Objective-C++ pointer conversions reported by the first macOS build.
- GitHub Actions run `35186351403`: host tests, invariants, arm64 compile/link and artifact upload passed.
- Built binary SHA-256: `d6605ec4b3c36bd3daa7d944d9cd24f230dc4905d33ac67ab5659557b6d57413`.
- Device runtime validation remains pending.
# v2.0.1-dev — first device-log corrections

- Parsed five nested device archives from input SHA-256 `2f92bfc64b37c47a57cfcf42b9e5b84594f401d5cb10877d23f1c67a74f65855`.
- Confirmed bounded scans completed quickly and did not hang.
- Raised the dyld image cap from 512 to 2048 after three runs exhausted the old cap before reaching late-loaded menu images.
- Added descriptor-strength tie-breaking for a generic legacy shell (`97`) versus a full Jailpatch payload (`89`, Jailpatch evidence `116`).
- Stopped recursively turning UIKit/Foundation implementation objects into duplicate `missing-offset` features.
- Confirmed the 5 MB Jailpatch family still needs an evidenced `loadConfig:`/runtime-table observer; no static patch was claimed.
