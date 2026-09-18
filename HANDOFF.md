# HFAMap Handoff

## v2.1.0 first-pass implementation

Active branch: `feature/hfamap-v2-bounded-universal-analyzer`.

The first-pass implementation now uses a 350 ms main-thread UI/target snapshot and performs descriptor traversal on the serial worker queue. It records Objective-C class-count evidence and the stable 160-byte descriptor signature, and writes live session diagnostics to `HFAMap_Diagnostics.jsonl` plus `HFAMap_Diagnostics.log`.

Local verification: Python unit tests 4/4 passed; the supplied archive classified all 11 dylibs into the expected Legacy AP/Jailpatch families. GitHub Actions run `35403381939` passed compile/link/sign for remote commit `3ad558978f8bd648fefa737bd80f6c5596507426`. Artifact ID `10570699914`; dylib SHA-256 `5903e172814bf9950ceceb55440adeff1747deffb2cbecec8755017517db6246`. Device verification is still required.

## Active work

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
# Current handoff: v2 bounded analyzer

Active branch: `feature/hfamap-v2-bounded-universal-analyzer`.

The active Makefile compiles only Entry/Core/ImageProbe/Resolver. Do not restore the historical generated
source chain into this branch. Run `python3 -m unittest -v tests/test_macho_triage_v2.py`, then test the
new workflow. On device, first open the target menu, press `Scan Menu`, and collect
`HFAMap_Patches.json`, `HFAMap_Analysis.json`, and `HFAMap_Process.jsonl`.

Acceptance requires one legacy-ap and one jailpatch sample to finish without blocking, select the correct
menu dylib, and either export byte-validated patches or explicit unresolved reasons. An empty canonical file
with honest unresolved evidence is preferable to a guessed patch.

CI checkpoint: run `35186351403`, commit `ac74cfaff43fa19ea3f83491c1e955a81946103c`, artifact
`10481758150`; arm64 binary SHA-256
`d6605ec4b3c36bd3daa7d944d9cd24f230dc4905d33ac67ab5659557b6d57413`.

First device archive proved stability but not extraction universality. One `libdragonfevertd.dylib` run selected
the correct payload and completed in about 114 ms, but produced zero canonical features. Do not treat the
58 `missing-offset` entries as features; they were traversal pollution and are filtered in v2.0.1. If the next
run still has no static descriptors, the next evidence boundary is the selected image's exact `loadConfig:` /
Jailpatch runtime-table initialization path, not a broad Objective-C hook.

The v2.0.1 five-device re-test is now complete. Archive SHA-256:
`91fbbfa901d3a75cb35d97dcde58d745a1a75e627532ff4242537f024a661b74`.
Every run inspected the full dyld image set (948–985) and completed in 86.8–137.0 ms. Candidate selection
and traversal filtering are device-confirmed. All runs still exported zero canonical features, so the next
implementation must observe only the selected image's evidenced configuration/runtime-table boundary.
Do not enable the historical process-wide profiler unchanged: its broad class/object traversal violates the
v2 bounded architecture and does not prove the runtime-table layout.
