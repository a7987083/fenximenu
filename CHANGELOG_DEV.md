# Development Changelog

## v1.9.30 JailpatchSelectorResolver — compiled / awaiting selector-bridge device validation

Branch: `feature/hfamap-v1930-jailpatch-selector-resolver`
Base: `feature/hfamap-v1929-jailpatch-runtime-profiler` @ `0ddbac96ddae0a0162711ce4d7e979d7d1b95438`
Build-tested commit: `786a26eb66a3aa22d1f1c1ef7a94910e7f8b6f42`
Successful CI run: `34785200383`
Artifact ID: `10326735655`
Binary SHA256: `6c716180e7e5a2659cfb538e6ca6ee217773a0ce583741f9d1e43f0f140f9d14`

### New runtime evidence received from v1.9.29

- The ~5 MB runtime-record family is now device-profiled rather than merely probe-detected.
- A populated three-feature definition array and per-feature runtime-record arrays were recovered on-device.
- The runtime record class retains stable semantic selectors despite randomized class/ivar names: `identifier`, `type`, `architecture`, `active`, `offset`, `signature`, `range`, `searchDirection`, and `setActive:`.
- The important object ivars still use stripped Objective-C type metadata `@"?"`, confirming that declared-class fingerprints are not reliable for this family.
- Record objects contain a stable `<identifier>-switch` key string, the feature identifier, module text such as `main`, secret-wrapper objects, and nested runtime objects.
- Cross-sample static inspection of both supplied ~5 MB dylibs confirmed the same semantic property/selector set and compatible secret-wrapper `secret` interface while obfuscated names differ.
- A second ~5 MB sample (WayOfKings path) did not expose the same populated runtime-record arrays in the profiler capture, but the existing iGMM path successfully generated `com.TornadoBear.WayOfKings_1.4.0_165.hfapatch.json`. This existing path remains a regression requirement.

### Added in v1.9.30

- `hfamap/src/HFAMapJailpatchSelectorResolver.m`
  - Recognizes jailpatch descriptors by stable selector fingerprint rather than randomized class or ivar names.
  - Reads semantic getters for identifier/type/architecture/active/offset/signature/range/searchDirection.
  - Enumerates runtime object ivars to collect strings and objects exposing the stable `secret` interface even when declared type metadata is stripped.
  - Bridges `offset` to the existing descriptor pipeline as the offset wrapper.
  - Excludes `offset` and `signature` from patch-data candidates; only when exactly one other secret-wrapper remains is it registered as patch data.
  - Falls back to evidence-only logging instead of forcing an ambiguous mapping.
  - Reuses the mature `HFARegisterPatchObject`, `HFARegisterPatchSecret`, `HFARegisterPatchString`, `setActive:` hook, decrypt, mapping, and package-export pipeline.
  - Emits `[JAILPATCH-SELECTOR-DESCRIPTOR]` and structured `jailpatch-selector-descriptor` JSON records.
- `.github/scripts/hfamap_v1930_jailpatch_selector.py`
  - Integrates the selector resolver into each v1.9.29-discovered runtime record while preserving the structural profiler.
- `hfamap/Makefile`
  - Compiles the new selector resolver source.
- `.github/workflows/theos-hfamap-v1930-jailpatch-selector.yml`
  - Replays the full historical patch chain, verifies previous exporters remain byte-identical, enforces selector/integration invariants, rejects sample-specific names/modules/RVAs, builds/signs the arm64 dylib, verifies SHA256, and uploads the artifact.

### Verification

- Historical patch chain: passed.
- Previous behavior regression checks: passed.
- Legacy/iGMM exporter byte-identity checks: passed.
- Jailpatch selector resolver invariants: passed.
- Explicit current-sample feature/class/module/RVA hardcode deny-list: passed.
- Compiled/linked/signed: yes, arm64.
- GitHub Actions: success (`34785200383`).
- Artifact uploaded: yes (`10326735655`).
- SHA256 independently rechecked after artifact download: yes.
- v1.9.30 device tested: no.

## v1.9.29 JailpatchRuntimeProfiler — device evidence checkpoint

CI run: `34783065857`
Binary SHA256: `8b76b62424c9152a8e09b2e68dfccc09a590f6526403271b07c7056b1f8b0c3e`

The v1.9.29 capture successfully recovered enough runtime-record structure and stable semantic selectors to promote the ~5 MB path from generic profiling to a selector-based resolver design. It did not itself prove the final offset/patch-data bridge; that is the specific v1.9.30 device-validation target.

## v1.9.28 GenericMenuResolver — runtime checkpoint

CI run: `34781824064`
Binary SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`

The legacy ~15 MB AP/IGSecret path remains runtime-confirmed with 12 valid feature mappings and successful patch-package export.
