# Known Issues

## HFARuntimeAnalyzer v0.3.4 SemanticBackend

### Physical-device semantic validation is pending

Status: open / primary gate.

The v0.3.4 arm64 dylib is CI-built, downloaded and re-hashed, but the new semantic classifications have not yet been proven on a physical device. Do not call Random Dice 2 `conditional-return`, MeChat `return-multiplier`, RogueLegend FP return transform or Path subobject capture device-confirmed until new `V034-*` logs and v034 JSON are collected.

### Phase-1 CFG is intentionally bounded and incomplete

Status: open / known limitation.

The new analyzer follows an unconditional `B` in the specific branch-aware constant-return path and performs bounded linear replacement analysis. It is not yet a full basic-block graph with path merging. Multiple early-return blocks, loops, nested conditionals and heavily flattened dispatchers may therefore remain `unknown-runtime` or expose only partial evidence.

### Dataflow is evidence, not patch authorization

Status: permanent safety/truth rule.

`semanticEvidence` may identify arithmetic, receiver flow or callback constants, but it does not automatically authorize a static patch. `canonicalEligible` still requires independently proven equivalent static bytes, unique target identity and original-byte truth. Dynamic multipliers may legitimately remain Runtime Semantic backends with no fixed patch.

### Feature ↔ Backend binding is not complete

Status: open / phase 2.

The current analyzer can classify a replacement but does not yet fully associate every semantic branch with menu Feature identifiers. This matters for shared replacement sites such as Path of Kings Damage/Defence/God Mode and Random Dice support trampolines. UnitXP `ZNSharedSiteExecutionProbeV3` concepts are the reference for the next binding layer.

### WhisperCastle still requires descriptor-less action analysis

Status: open / phase 3.

WhisperCastle has menu features/actions but no matching descriptor family. The existing descriptor-first AutoBackend can enter v034 but cannot recover the flattened ObjC action implementation as a feature backend. A bounded descriptor-less action/CFG path remains required.

### IL2CPP owning-method scan is bounded

Status: intentional performance guard.

The v0.3.4 enrichment scans live IL2CPP methods with a class cap and wall-clock deadline. On very large titles it may return a timeout/lower-bound result rather than guessing an owner. Native backend evidence must survive metadata enrichment failure.

### Whole-repository output routing is not yet unified

Status: open.

The RuntimeAnalyzer v034/v033/v032/v03 outputs use `HFAOutputPath()` under `Documents/HFAMap_<CFBundleIdentifier>/` and CI forbids direct analyzer root writes. Previous device logs showed that some legacy package/identity/IGMM exporters can still write directly under `Documents/`. Migrating those legacy exporters into the same bundle folder remains a separate task.

### Compile compatibility workaround should be cleaned

Status: low-priority technical debt.

The iPhoneOS SDK rejects `<mach/mach_vm.h>`. v0.3.4 correctly uses `vm_read_overwrite` and Mach-O segment protections instead. The compile-fix generator currently retains a comment mentioning the unsupported header to satisfy a workflow string check; replace that marker check with a direct `vm_read_overwrite` assertion in a later cleanup.

### Output files must remain isolated per App

Status: permanent regression rule.

All RuntimeAnalyzer outputs must use `HFAOutputDirectory()` / `HFAOutputPath()` and reside under `Documents/HFAMap_<CFBundleIdentifier>/`. A stale result from another App must never participate in current analysis.

### Static decrypt fallback remains unique-match only

Status: intentional fail-closed behavior.

The simulator-compatible static fingerprint is used only when exactly one match exists. Missing or ambiguous decrypt must not discard structurally valid descriptors, but plaintext-dependent conclusions remain unavailable.

## Current CI delivery

Authoritative v0.3.4 phase-1 candidate:

- branch: `feature/hfaruntime-v0.3.4-semantic-backend-analyzer`
- build-tested commit: `3918052e30fcc0d7dca78e4754240cf5e94dba3c`
- binary: `HFARuntimeAnalyzer-v0.3.4-SemanticBackend.dylib`
- run: `36218004874`
- artifact ID: `10897963845`
- size: `265424` bytes
- binary SHA256: `cc4cec47801cd3d5dfa581f00fc0be6123a7388e82805f9167765de9d32f9f00`
- artifact ZIP digest: `sha256:de49e2dfd51deb6004e22b407ba20554c81da8c22005f928d633a81f1e67274d`
- compile/link/sign: passed
- device semantic validation: pending

## Legacy known issues retained

- Earn to Die Rogue exact-build Fuel/Boost patches remain build/UUID/original-byte gated; already depleted values are not refilled.
- Earn Posters/Prestige still have a pre-existing overlap at `UnityFramework+0x2E25904` and need explicit conflict handling.
- v1.9.36.4 parser current-line cross-family regression for static-5MB and legacy-15MB families remains separate and pending.
- v1.9.37/v1.9.37.1 combined playback/Dobby parser architecture remains retired after device startup crashes.
- canonical structural validity alone is insufficient; target identity and original-byte truth remain mandatory.
