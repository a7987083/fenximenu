# HFAMap Handoff

## Active work — HFARuntimeAnalyzer v0.3.3 StaticParity

- repository: `a7987083/fenximenu`;
- branch: `feature/hfaruntime-v0.3.3-static-parity-autobackend`;
- base v0.3.2 commit: `cb04586dba45e1f57df4d1a2a76a54385d864066`;
- successful build commit: `806957d0ebe3ef13559d72809295bb6eeb69de09`;
- GitHub Actions run: `36161672792` — success;
- artifact ID: `10876640401`;
- binary: `HFARuntimeAnalyzer-v0.3.3-StaticParity.dylib`;
- size: `264992` bytes;
- SHA256: `ed381292a594b3865194622141abcce29918e16d88092405c667d78519da6cca`;
- artifact ZIP digest: `3256b0704686508f411056593c9b1c68d31494a63ff502796e35a7138a8ee371`.

### What v0.3.3 changes

v0.3.2 mixed structural descriptor discovery with plaintext/decrypt success. The offline simulator first discovers descriptors from current Mach-O bytes, while the device analyzer previously returned early when decrypt resolution failed and discarded records when decrypt/plaintext validation failed.

v0.3.3 changes that order:

1. select the menu dylib;
2. retain structurally valid descriptor records (`length/flags/family`) using the simulator-compatible 8-byte alignment;
3. resolve decrypt with the existing runtime resolver, then a unique static fingerprint fallback;
4. attach plaintext/decrypt status as evidence instead of using it as a prerequisite for descriptor existence;
5. build AutoBackend from the retained structural records;
6. export `HFAMap_RuntimeAnalyzer_v033.json`.

The second button remains the single universal entry: family parser -> `HFAAnalyzerV02ScanSelectedImage()` AutoBackend. This must be exercised for every selected sample.

### Output-directory contract

All analyzer outputs continue through `HFAOutputDirectory()` / `HFAOutputPath()` and therefore live under:

`Documents/HFAMap_<CFBundleIdentifier>/`

CI rejects direct `Documents/HFAMap_*` output paths. Do not regress this to shared Documents-root files.

### Runtime State boundary

Known v0.3.2 results:

- Earn to Die Rogue: 19 Backend = 18 Static + 1 Runtime State, with 2 field-dataflow derived patches;
- RogueLegend: 3 Backend = 2 Static + 1 Runtime State, no field offsets / no derived patch;
- MeChat: 8 Backend = 7 Static + 1 Runtime State, no field offsets / no derived patch.

v0.3.3 adds read-only `hookReturnEvidence` and optional `staticOverrideCandidates` to distinguish constant-return hooks from other stateful semantics. These records are `diagnostic-only`; they are not canonical patches until target semantics, uniqueness and original bytes are proven.

### Next device validation

Priority set:

1. Duck Survival;
2. Path of Kings;
3. Random Dice 2;
4. Heavenfall;
5. PopIsland;
6. WhisperCastle.

For every one, require `[V033-DECRYPT]`, `[V033-SCAN-END]` and `HFAMap_RuntimeAnalyzer_v033.json` in its per-bundle folder. Then test RogueLegend and MeChat and inspect `hookReturnEvidence` / `staticOverrideCandidates`. Finally regress Earn / Rise / Zombie / HelloKitty / Legend against their known-good v0.3.2 counts.

## Previous active work — v1.9.37.10

- repository: `a7987083/fenximenu`;
- branch: `feature/hfamap-v193710-unified-feature-model`;
- product version: `v1.9.37.10 UnifiedFeatureModel`;
- previous build commit: `2306e7121f507b663f157a172cdfb9c4aa5bdc46`;
- verified-profile implementation: `13fff6fd49d84348c618cc7845527e0b5c8413fa`.

## Earn to Die Rogue conclusion

Target identity:

```text
bundle       com.notdoppler.earntodierogue
version      1.28.251
build        1
architecture arm64
image        UnityFramework
UUID         8654D76C-B760-34FC-BEE0-FE70AE8C95C8
```

Missing canonical patches:

```text
Fuel  UnityFramework+0x2D98AC8  0038211E -> 1F2003D5
Boost UnityFramework+0x2D9887C  0038281E -> 1F2003D5
```

Both sites belong to `Assembly-CSharp.dll!com.notdoppler.ETDR.Car.FixedUpdate()`
at RVA `0x2D9827C`. Fuel is `_fuelAmount` at object offset `0xB8`; Boost is
`_boostAmount` at `0xBC`. The original instructions subtract per-frame
consumption and the replacement is one ARM64 `nop`.

The original v1.9.37.10 result was incomplete because the shared Objective-C
action (`AaNfXa -ddktmnuyvBoEK:`, `EarntoDieRogue.dylib+0x397098`) was treated
as evidence of a runtime-only implementation. All 14 controls share that menu
dispatcher, including the 12 already-proven static features, so that inference
was invalid. The exact-build profile repairs Fuel/Boost without weakening the
generic truth gates.

Implementation files:

- `.github/scripts/hfamap_v193710_earntodie_verified_profile.py`;
- `.github/workflows/theos-hfamap-v193710-unified-feature-model.yml`;
- `tests/earntodie_rogue_1.28.251_verified_profile.json`;
- `docs/EARN_TO_DIE_ROGUE_1.28.251_ANALYSIS.md`.

Runtime acceptance requires bundle/version/build, arm64, exact UnityFramework
UUID and both original-byte checks. No address is reused on another build.

## Verification boundary

Static verification, the complete local generation chain and GitHub Actions
compile/link/sign passed. Build run `35170319783` produced artifact
`10476488771`; the downloaded arm64 dylib is 247824 bytes with SHA-256
`afc4ab46bff54bb1eef35f81d3cde65cedb557257c913b858844de4c1ea79c58`.
Device enable/disable regression remains pending. Enabling the patch stops
further depletion but does not refill a value that was already zero.

The pre-existing package also has an unresolved overlap at
`UnityFramework+0x2E25904`: Posters writes `08E0BF12`, while Prestige writes
`20008052C0035FD6`. Resolve or explicitly arbitrate that conflict before calling
the full 14-button package conflict-free.

## Legacy parser/exporter checkpoint

The frozen parser baseline remains v1.9.36 ArchitectureTruth commit `75f94da37221343b6839465ad365ddec2679e63a`. WayOfKings/iGMM device validation passed on v1.9.36.4. v1.9.37/v1.9.37.1 playback/Dobby merged experiments are retired after device startup crashes.

The normalized schemas remain evidence-preserving; runtime-only behavior must not be fabricated into canonical static bytes.
