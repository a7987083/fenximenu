# Known Issues

## Universal Mutation Refactor — Stage 1

### Provider-neutral discovery is not finished

Status: open / primary engineering task.

Stage 1 normalizes mutations that already passed the existing canonical truth gates. It does **not** yet generically discover arbitrary unknown menu implementations. Family-specific AP/IGCodePatch/Jailpatch/5M/iGMM code still participates in discovery before the final IR.

Required next step: add provider-neutral mutation capture beneath family adapters and prove it on the supplied five menu+host sample pairs.

### Device runtime validation is pending

Status: open.

CI run `35194007919` proves generation, arm64 compile, link, strip and sign. It does not prove injected-device behavior. Required device checks:

- no startup crash;
- Full Scan completes;
- `HFAMap_CanonicalMutations.json` is generated;
- mutation count matches trusted canonical static patches;
- target/offset/original/enabled fields agree with the actual target image;
- legacy `com.hfa.patch/v1` output remains unchanged.

### Five-pair cross-family regression is pending

Status: open.

Use the supplied sample corpus covering new ~14 MB AP/iGameGod-style menus and old ~5.75 MB Jailpatch-style menus. Do not claim universal coverage until the same `com.hfa.mutation/v1` contract works for all independently verified static mutations.

### Mutation IR currently models only proven static byte patches

Status: intentional Stage 1 limitation.

Dynamic numeric state, runtime hooks, button actions and unresolved dispatchers remain analysis evidence. They must not be fabricated into static `offset/original/enabled` records.

## Pre-existing issues retained

### Fuel/Boost device regression pending

Status: open.

Fuel/Boost are statically proven for `com.notdoppler.earntodierogue` `1.28.251 (1)` and build-tested, but independent on-device enable/disable/original-byte restoration is still pending.

### Already-depleted values are not refilled

Status: intentional behavior.

Fuel/Boost patches NOP the subtraction instructions. They stop future depletion but do not assign a full value.

### Exact-build Fuel/Boost profile only

Status: permanent safety gate.

The RVAs are valid only for the verified bundle/version/build/architecture/UnityFramework UUID/original bytes. A game update requires fresh binary and metadata analysis.

### Posters/Prestige patch overlap

Status: open / pre-existing.

Both features touch `UnityFramework+0x2E25904`. Posters writes `08E0BF12`; Prestige writes `20008052C0035FD6`. Conflict handling or an independent replacement site is still required.

### Generic observed-action classification can be broader than evidence

Status: open / mitigated by the new IR boundary.

A shared menu dispatcher must not by itself prove a runtime-only or static implementation. The Mutation IR accepts static records only after byte-level truth is already available.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source readers remain in the frozen parser core. Fallback branches still need dedicated runtime samples where the preferred read path is unavailable.

### Stale generated files can confuse validation

Status: test-environment hazard.

Archive/remove prior `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, `HFAMap_CanonicalMutations.json`, and old logs before comparing a new run.

## Current CI delivery

- branch: `feature/universal-mutation-refactor`
- build-tested implementation: `a26cab49985fbb675e76378899eeb02052e7f2c6`
- run: `35194007919` — success
- artifact: `10484872379`
- artifact digest: `sha256:d3ff65db4470250f008134a180ae01c866e410cc13b4e6bff258069355ac9876`
- binary: `HFAMapUniversal_UniversalMutationRefactor.dylib`
- binary SHA256: `09f04e942d6f571048f26fe728e6a51974bb8c2aeeba29a06878befd28a5ea16`
- device validation: pending
- cross-family regression: pending
