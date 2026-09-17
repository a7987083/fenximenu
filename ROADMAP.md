# HFAMap Roadmap

## Current phase — v1.9.38.0 Stage 1 Universal Mutation IR

Branch: `feature/universal-mutation-refactor`

Baseline: `feature/hfamap-v193710-unified-feature-model @ 9fe759fe8519bfcaa90c2461a256c18a4d6c2080`

Build-tested implementation: `a26cab49985fbb675e76378899eeb02052e7f2c6`

CI run `35194007919`: **success**.

Stage 1 establishes a provider-neutral final truth model:

`Evidence Provider -> existing truth gate -> com.hfa.mutation/v1 -> export/regression`

Completed:

- added `HFACanonicalMutation.h/.m`;
- retained the existing original-byte/target truth gates;
- bridged truth-gated `exportFeatures/exportTargets` into the new IR;
- kept `com.hfa.patch/v1` unchanged for compatibility;
- verified the canonical core contains no AP/iGameGod/Jailpatch/5M framework names;
- built, linked, stripped and signed the arm64 dylib in GitHub Actions;
- uploaded artifact `10484872379`;
- binary SHA-256 `09f04e942d6f571048f26fe728e6a51974bb8c2aeeba29a06878befd28a5ea16`.

Next tasks:

1. Stage 2: capture provider-neutral memory/code mutations beneath the family adapters;
2. correlate feature context -> actual mutation -> target Mach-O -> preferred VM offset;
3. capture pre-write and post-write bytes before accepting a static mutation;
4. run the supplied five menu-dylib + host-binary pairs as one regression corpus;
5. require all proven static mutations to use the same `com.hfa.mutation/v1` contract;
6. keep runtime-only numeric/hook/button features analysis-only until a portable static mutation is independently proven;
7. perform device runtime validation of `HFAMap_CanonicalMutations.json`.

Do not call the parser fully universal until the five-pair cross-family regression and device validation pass.

## Previous phase — v1.9.37.10 Earn to Die Rogue completion

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

Previous next tasks:

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

## Stable foundation

- Frozen parser baseline: v1.9.36 ArchitectureTruth, commit `75f94da37221343b6839465ad365ddec2679e63a`.
- Preserve constructor, `run_full_scan()` and resolver/decrypt/original-byte core unless a regression test proves a required change.
- Canonical static patches remain `com.hfa.patch/v1` for compatibility while Stage 1 also emits `com.hfa.mutation/v1`.
- iGMM runtime behavior remains diagnostic-only under `com.hfa.igmm.runtime/v1`.
- Normalized cross-family analysis uses `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Device/regression checkpoints retained

- v1.9.36.4 WayOfKings/iGMM device validation: passed.
- v1.9.37.10 Earn to Die static Fuel/Boost analysis/build: passed; device regression pending.
- runtime-record/static 5 MB current-line regression: pending.
- legacy ~15 MB current-line regression: pending.
- Universal Mutation Stage 1 CI: passed; device/cross-family regression pending.

## Deferred work

Execution of generated JSON remains a separate project/module. Do not merge a playback/runtime consumer back into HFAMapUniversal without a separately device-validated integration design.
