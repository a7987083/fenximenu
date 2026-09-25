# Known Issues

## HFARuntimeAnalyzer v0.3.3 StaticParity

### Device validation pending

Status: open / primary gate.

The v0.3.3 arm64 dylib is CI-built and artifact-rehashed, but has not yet been exercised on device. Do not mark the structural-parity changes device-passed until the new `V033-*` logs and per-bundle JSON are collected.

### Runtime State is not automatically a canonical patch

Status: intentional evidence gate.

RogueLegend and MeChat reach a Runtime State backend but expose no object `fieldOffsets` under the existing callback-field analysis. v0.3.3 exports `hookReturnEvidence` and may emit `staticOverrideCandidates`, but those entries remain `diagnostic-only`. They must not be promoted to final `offset/original/enabled` without a unique target semantic and original-byte proof.

### Static decrypt fallback is unique-match only

Status: intentional fail-closed behavior.

The simulator-compatible static fingerprint is used only when exactly one match exists. Zero or multiple matches are recorded as unresolved. Structural descriptor records are still retained, but plaintext-dependent conclusions remain unavailable.

### Cross-sample AutoBackend coverage must be rechecked on the latest build

Status: open.

Priority samples: Duck Survival, Path of Kings, Random Dice 2, Heavenfall, PopIsland and WhisperCastle. Each selected dylib must now reach `V033-DECRYPT` and `V033-SCAN-END`, regardless of whether plaintext decrypt succeeds.

### Output files must remain isolated per App

Status: permanent regression rule.

All outputs must use `HFAOutputDirectory()` / `HFAOutputPath()` and reside under `Documents/HFAMap_<CFBundleIdentifier>/`. Shared `Documents/HFAMap_*` root outputs are rejected by CI because they allow stale data from one App to contaminate another App's analysis.

## v1.9.37.10 Earn to Die Rogue profile

### Device runtime validation pending

Status: open.

Fuel/Boost are statically proven and generation-tested, but the new analyzer
binary has not yet been built by GitHub Actions or exercised on device. Required
checks are clean scan output, `14` canonical features, `20` patches, independent
Fuel/Boost enable/disable and original-byte restoration.

### Already-depleted values are not refilled

Status: intentional behavior.

The two patches NOP the subtraction instructions. They prevent additional
consumption but do not assign a full tank. Enable them before Fuel/Boost reaches
zero or start a new driving session.

### Exact-build profile only

Status: permanent safety gate.

The RVAs are valid only for `com.notdoppler.earntodierogue` `1.28.251 (1)`,
arm64, UnityFramework UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, with exact
original bytes. A game update requires fresh metadata and binary analysis.

### Posters/Prestige patch overlap

Status: open / pre-existing.

Both features touch `UnityFramework+0x2E25904`. Posters writes `08E0BF12`
(4 bytes), while Prestige writes `20008052C0035FD6` (8 bytes). Toggle order can
overwrite the shared first instruction. Fuel/Boost do not introduce this
conflict, but the package needs explicit conflict handling or a new independent
Prestige/Posters patch site.

### Generic observed-action classification remains too broad

Status: mitigated for the verified target only.

The generic v1.9.37.9/v1.9.37.10 logic can classify an observed action as
`runtimeAction` even when the action is only a shared menu dispatcher. The exact
Earn to Die profile corrects the two proven records; a future generic fix should
use `dispatcher-observed/unresolved` until independent write/hook/static-byte
evidence exists.

## Current parser-only line: v1.9.36.4 JSONExport

### v1.9.36.4 WayOfKings/iGMM validation

Status: **passed / closed**.

Device archive `归档 6(1).zip` confirmed stable injection, Full Scan completion, 4-feature iGMM diagnostic export and normalized analysis export. It also confirmed:

- `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains preserved;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- `targetIdentities` resolves both `libpathofkings.dylib` and `UnityFramework` with the expected UUID/arm64/cryptid evidence;
- `JSON-EXPORT status=pass features=4 sources=1 targetIdentities=2`.

### Cross-family regression is still pending

Status: open / primary validation gate.

The current v1.9.36.4 parser has now passed the WayOfKings/iGMM family, but the same binary still must be regression-tested on:

- runtime-record/static 5 MB family;
- legacy ~15 MB family.

Do not claim universal/cross-family coverage until both current-line regressions pass.

### Target identities are analysis evidence, not execution authorization

Status: permanent rule.

Read-only UUID/architecture/filetype/preferred-`__TEXT`/cryptid records are for build matching and analysis quality only. They do not authorize hook installation or package execution.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device-confirmed.

WayOfKings uses runtime numeric/native-hook/block behavior. These records remain diagnostic and analysis-only and are not fabricated into `target/offset/original/enabled` static patches.

### v1.9.37 and v1.9.37.1 are retired from the parser mainline

Status: confirmed device startup failure / architecture reverted.

Those builds merged the independent playback/runtime consumer and Dobby into HFAMapUniversal. Both crashed immediately when injected. HFAMapUniversal remains a parser/exporter only.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing a new menu family, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs. A stale canonical package must never be mistaken for current output.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Runtime-record/static 5 MB regression

Status: open / next test.

The current v1.9.36.4 build must reproduce a trusted `com.hfa.patch/v1` package for the static 5 MB family. Required checks include real target identity, preferred VM offsets, original-byte truth and no stale-output contamination.

### Legacy ~15 MB regression

Status: open / follows the 5 MB static test.

The legacy AP/IGSecret family was previously runtime-confirmed on older parser versions. The current v1.9.36.4 binary must still prove that path has not regressed.

## Current CI delivery

Authoritative v0.3.3 analyzer candidate:

- binary: `HFARuntimeAnalyzer-v0.3.3-StaticParity.dylib`
- run: `36161672792`
- artifact: `10876640401`
- binary SHA256: `ed381292a594b3865194622141abcce29918e16d88092405c667d78519da6cca`
- artifact ZIP digest: `sha256:3256b0704686508f411056593c9b1c68d31494a63ff502796e35a7138a8ee371`
- CI compile/link/sign: passed
- device validation: pending
