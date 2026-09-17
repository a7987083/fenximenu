# Development Changelog

## v1.9.38.0 Stage 1 — Universal Mutation IR

Branch: `feature/universal-mutation-refactor`

Baseline: `feature/hfamap-v193710-unified-feature-model @ 9fe759fe8519bfcaa90c2461a256c18a4d6c2080`

Build-tested implementation: `a26cab49985fbb675e76378899eeb02052e7f2c6`

GitHub Actions run: `35194007919` — success

Artifact ID: `10484872379`

Artifact digest:
`sha256:d3ff65db4470250f008134a180ae01c866e410cc13b4e6bff258069355ac9876`

Binary SHA-256:
`09f04e942d6f571048f26fe728e6a51974bb8c2aeeba29a06878befd28a5ea16`

### Changed

- Added provider-neutral `HFACanonicalMutation.h/.m`.
- Added schema `com.hfa.mutation/v1`.
- Added validation for feature/target/offset/original/enabled byte tuples.
- Added canonical mutation deduplication by feature + target + offset + enabled bytes.
- Added provider evidence aggregation without embedding provider-specific framework names in the IR core.
- Added `.github/scripts/hfamap_v19380_canonical_mutation_ir.py` to bridge truth-gated `exportFeatures/exportTargets` after the historical generation chain.
- Added dedicated CI workflow for `feature/universal-mutation-refactor`.
- Preserved the existing `com.hfa.patch/v1` package and its original-byte/target truth gates.
- Added `docs/UNIVERSAL_MUTATION_REFACTOR.md`.

### Verification

- historical generation chain: passed;
- mutation IR integration assertions: passed;
- provider-specific name exclusion from IR core: passed;
- existing original-byte truth gates: preserved;
- first CI run exposed one local syntax error in the new logging expression;
- first real compiler error fixed without changing architecture;
- arm64 compile: passed;
- link: passed;
- strip: passed;
- sign: passed;
- final binary schema/log markers: passed;
- artifact upload: passed;
- device runtime: pending;
- five-pair cross-family regression: pending.

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

## Historical parser checkpoints

- v1.9.36.4 JSONExport: CI passed / WayOfKings device passed.
- v1.9.36.3 JSONExport: device passed on WayOfKings.
- v1.9.36.2 JSONExport: CI passed.
- v1.9.36.1 JSONExport: first stable analysis-only serializer validation.
- v1.9.36: ArchitectureTruth frozen parser baseline.
- v1.9.35: MainImageTruth.
- v1.9.34: CanonicalTruthGate.
- v1.9.33: multi-source original-byte resolver.
- v1.9.32: crash-safe Full Scan.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.

## Retired experiment: v1.9.37 / v1.9.37.1

- Combined parser, dynamic JSON UI, playback consumer, Dobby and runtime takeover into one dylib.
- CI/build succeeded, but both device injections crashed at startup.
- Combined architecture remains retired from the parser mainline.
