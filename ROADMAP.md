# HFAMap Roadmap

## Current phase — HFARuntimeAnalyzer v0.3.3 StaticParity device validation

Branch: `feature/hfaruntime-v0.3.3-static-parity-autobackend`

Baseline: v0.3.2 `cb04586dba45e1f57df4d1a2a76a54385d864066`

Successful CI build commit: `806957d0ebe3ef13559d72809295bb6eeb69de09`

CI run: `36161672792` — success

Artifact: `HFARuntimeAnalyzer-v0.3.3-StaticParity` (`10876640401`)

Binary SHA256: `ed381292a594b3865194622141abcce29918e16d88092405c667d78519da6cca`

### Goal

Make the on-device analyzer follow the same evidence order as the offline simulator:

`current menu Mach-O bytes -> structural descriptor records -> XREF/backend -> optional decrypt/plaintext evidence -> target semantics`

Decrypt/plaintext availability must no longer decide whether a structurally valid descriptor exists.

### Implemented in v0.3.3

- simulator-compatible 8-byte descriptor alignment;
- binary-first retention of target/patch family records;
- no hard return when runtime decrypt resolution fails;
- unique static decrypt fingerprint fallback;
- per-record `decryptStatus`;
- universal selected-dylib AutoBackend entry preserved;
- Runtime State `hookReturnEvidence` and diagnostic-only `staticOverrideCandidates`;
- new `HFAMap_RuntimeAnalyzer_v033.json`;
- per-App output directory preserved as `Documents/HFAMap_<CFBundleIdentifier>/`;
- direct Documents-root HFAMap output rejected by CI.

### Device milestone A — previously missing AutoBackend samples

Test in this order:

1. Duck Survival;
2. Path of Kings;
3. Random Dice 2;
4. Heavenfall;
5. PopIsland;
6. WhisperCastle.

Acceptance for each:

- selected menu dylib is correct;
- `[V033-DECRYPT]` exists;
- `[V033-SCAN-END]` exists;
- `HFAMap_RuntimeAnalyzer_v033.json` exists in that App's independent folder;
- structural descriptors/backends are present even if decrypt status is unresolved;
- no stale file from another App appears in the folder.

### Device milestone B — Runtime State completion

RogueLegend and MeChat already reach Runtime State but have no v0.3.2 field offsets. For v0.3.3:

1. inspect `hookReturnEvidence`;
2. inspect any `staticOverrideCandidates`;
3. confirm target image/UUID/RVA and original bytes;
4. only promote a patch if the semantic path is unique and independently proven;
5. otherwise keep the result unresolved/diagnostic rather than fabricating a canonical patch.

### Device milestone C — no-regression set

Recheck known-good v0.3.2 samples:

- Earn to Die Rogue: expected reference 19 Backend = 18 Static + 1 Runtime State, derived 2;
- Rise of Berk: 15 Static;
- ZombieCatchers: 4 Static;
- HelloKittyMyDreamStore: 6 Static;
- Legend of Survivors: 16 Static.

Do not promote v0.3.3 as the new stable analyzer until milestones A-C are supported by saved per-bundle logs/JSON.

## Previous phase — v1.9.37.10 Earn to Die Rogue completion

Branch: `feature/hfamap-v193710-unified-feature-model`

Baseline commit: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`

Verified-profile implementation commit:
`13fff6fd49d84348c618cc7845527e0b5c8413fa`

The `com.notdoppler.earntodierogue` `1.28.251 (1)` scan originally exported
12 canonical features and treated Fuel/Boost as runtime-observed records with
empty patch arrays. Matching IL2CPP metadata and ARM64 data-flow analysis prove
both are static depletion sites in `Car.FixedUpdate()`.

Verified exact-build sites:

- Fuel: `UnityFramework + 0x2D98AC8`, `0038211E -> 1F2003D5`;
- Boost: `UnityFramework + 0x2D9887C`, `0038281E -> 1F2003D5`.

The profile remains exact-build only and does not weaken generic truth gates.

## Stable parser/exporter checkpoint

v1.9.36.4 JSONExport remains the device-confirmed WayOfKings/iGMM parser checkpoint. The v1.9.37/v1.9.37.1 combined playback/Dobby architecture remains retired after device startup crashes.

Core rules remain:

- preserve evidence instead of forcing every runtime behavior into a static patch;
- canonical static patches require target identity and original-byte truth;
- preferred Mach-O VM addresses define static offsets;
- runtime-only/ambiguous evidence stays diagnostic;
- generated outputs must be attributable to the current App and current scan.
