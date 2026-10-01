# HFAMap Handoff

## Active work — HFARuntimeAnalyzer v0.3.13.19 RuntimeTargetDecrypt

- repository: `a7987083/fenximenu`;
- branch: `feature/hfaruntime-v0.3.13.19-runtime-target-decrypt-v1`;
- stable baseline: v0.3.13.18 `d9bf9dfbba4b81a32ba8bfc7ba86693e032393a6`;
- build-tested commit: `d3754015e32c11ed514dddc90edbdb823d121b6a`;
- GitHub Actions run: `36818369097` — success;
- artifact ID: `11141648675`;
- binary: `HFARuntimeAnalyzer-v0.3.13.19-d3754015.dylib`;
- architecture: arm64;
- minimum OS / SDK: iOS 12.0 / iPhoneOS 18.5;
- size: `417680` bytes;
- Mach-O UUID: `8F08F0C9-BE3D-3E54-9BFE-536E6F635BB8`;
- SHA256: `5343df6ca28f7a09ad118a7c2ba915acf25529b02c3c9e363321146238432a4e`.

### Why this version exists

The remaining runtime corpus contains encrypted native target records. Static analysis can recover the record RVA, replacement RVA, original slot, and replacement semantics, but key IDs 1/2 are populated from a runtime-registered 64 × 16-byte key table. Therefore a Mach-O-only decoder cannot truthfully recover every plaintext target.

v0.3.13.19 resolves that boundary generically on-device: after the target menu has initialized its key table, it copies each eligible encrypted target record to scratch memory and invokes the menu's own verified decrypt routine on the copy. The original record and target image are not written.

### Important truth boundary

Keep these distinct:

- `targetRecordRVA`: encrypted descriptor location in the menu dylib;
- `replacementRVA`: native replacement implementation in the menu dylib;
- `originalSlotRVA`: storage for the original function pointer;
- `menuActionRVA`: UI/action handler;
- `gameTargetRVA`: decrypted target only after strict parsing and unique executable-image resolution.

Only the last one is the actual game target. None of the others may be relabeled as a game offset.

### Current static corpus facts feeding the probe

- MeChat: target record `0xBBE458`, replacement `0xB8AFD4`, original slot `0xD30F40`; historical plaintext target `0x65958E4` is the device oracle.
- RogueLegend: shared record `0xBBE5A0`, replacement `0xB8AC84`, slot `0xD30F40`; Damage/Defence/God Mode semantics already recovered.
- Aniimo: 2 native target records.
- Duck Survival: 2 native target records.
- Path of Kings: 3 native target records plus descriptor-less Debug Menu action.
- Random Dice 2: 7 native target records; only 3 were previously feature-bound.
- Dragon Fever TD: 1 native target record.
- Whisper Castle: 0 target records; must stay on the descriptor-less action/Block path.

### Output

Runtime decrypt evidence is written to:

`Documents/HFARTD_<CFBundleIdentifier>_RuntimeTargetDecrypt.jsonl`

Key records:

- `runtime-target-image`
- `runtime-target-backend`
- `runtime-target-decrypt-end`

Every backend record retains `analysisOnly=true`, `memoryWritten=false`, and `scratchCopyDecrypt=true`.

### Build status vs runtime status

- modified: yes;
- committed: yes;
- compiled: yes;
- CI: yes;
- artifact: yes;
- run on iPhone: **not yet**;
- remaining runtime targets fully closed: **not yet**.

### Next task

Run this exact dylib on the acceptance matrix beginning with MeChat. Return the HFARTD JSONL plus the matching HFAMap app folder. Use MeChat's historical `0x65958E4` as the first positive control before trusting newly decrypted targets.

---

## Active work — HFARuntimeAnalyzer v0.3.4 SemanticBackend Phase 1

- repository: `a7987083/fenximenu`;
- branch: `feature/hfaruntime-v0.3.4-semantic-backend-analyzer`;
- baseline: v0.3.3 `f3090a8c1998f443eb4cae03eb857bfadf2c2002`;
- build-tested commit: `3918052e30fcc0d7dca78e4754240cf5e94dba3c`;
- GitHub Actions run: `36218004874` — success;
- artifact ID: `10897963845`;
- binary: `HFARuntimeAnalyzer-v0.3.4-SemanticBackend.dylib`;
- size: `265424` bytes;
- binary SHA256: `cc4cec47801cd3d5dfa581f00fc0be6123a7388e82805f9167765de9d32f9f00`;
- artifact ZIP digest: `de49e2dfd51deb6004e22b407ba20554c81da8c22005f928d633a81f1e67274d`.

### Why v0.3.4 exists

v0.3.3 solved structural discovery and universal AutoBackend entry, but real-device logs plus offline disassembly showed that many apparent `runtime-state` failures were actually semantic-analysis failures: the analyzer already knew the replacement/original-slot/target but could not explain how the hook transformed arguments, returns, receivers or callbacks.

Known examples motivating v0.3.4:

- Random Dice 2 `MergeAny`: `MOV W0,#1 -> B shared epilogue -> RET`, missed by the old short look-ahead constant-return recognizer;
- MeChat Points: original integer return is multiplied before returning;
- RogueLegend: original float return is transformed by `FMUL` / `FDIV` / `FCSEL` for Damage/Defence/God Mode;
- Path of Kings: two hooks capture subobjects `[X0+0x50]` and `[X0+0x38]`, while another replacement carries multiple gameplay features;
- WhisperCastle: no descriptor family exists, so it will require a later descriptor-less ObjC action/CFG backend.

### Implemented in phase 1

New files:

- `hfamap/src/HFARuntimeSemanticAnalyzer.h`;
- `hfamap/src/HFARuntimeSemanticAnalyzer.m`;
- `.github/scripts/hfamap_runtime_analyzer_v034_semantic_backend.py`;
- `.github/scripts/hfamap_runtime_analyzer_v034_compile_fix.py`;
- `.github/workflows/theos-hfamap-runtime-analyzer-v034.yml`.

The semantic module currently provides:

1. bounded native replacement analysis;
2. unconditional `B` target following for shared-epilogue constant returns;
3. original-slot -> register -> `BLR` evidence;
4. `MUL`, `FMUL`, `FDIV`, `FSUB`, `FCSEL` evidence;
5. direct receiver and subobject receiver propagation;
6. callback constant-argument evidence;
7. semantic types such as `conditional-return`, `return-multiplier`, `return-divider`, `return-select`, `argument-multiplier`, `argument-divider`, `receiver-capture`, `subobject-receiver-capture`, `callback-constant-argument`, with `unknown-runtime` fallback;
8. bounded live IL2CPP owning-method lookup and ABI enrichment inspired by the UnitXP `ZNIL2CPPOwningMethodResolver` / `ZNIL2CPPABIMetadata` design.

AutoBackend runtime records now include:

- `semanticEvidence`;
- `semanticType`;
- `legacySemanticType`;
- `owningMethod`.

The current schema is `com.hfa.runtime-analyzer/v0.3.4`, with output `HFAMap_RuntimeAnalyzer_v034.json`. Compatibility v033/v032/v03 outputs remain.

### Output contract

Analyzer outputs remain under:

`Documents/HFAMap_<CFBundleIdentifier>/`

through `HFAOutputDirectory()` / `HFAOutputPath()`. CI rejects direct analyzer `Documents/HFAMap_*` output paths.

Note: older package/identity/IGMM exporters were previously observed to have some Documents-root routing outside the analyzer output helper. Full repository-wide unified output routing is still a separate task; do not interpret the analyzer CI guard as proof that every legacy exporter is already migrated.

### Verification boundary

Completed:

- generated-source integration;
- semantic marker/source gates;
- universal AutoBackend entry gate;
- v034 per-App output gate;
- iPhoneOS arm64 compile/link/strip/sign;
- final binary marker inspection;
- artifact upload/download/re-hash.

Pending:

- physical-device execution of v0.3.4;
- confirmation that Random Dice 2 / MeChat / RogueLegend / Path receive the expected semantic classifications;
- full Feature ↔ Backend binding;
- descriptor-less action backend for WhisperCastle;
- stronger whole-function CFG/path merging;
- canonical bridge and repository-wide legacy output routing;
- optional runtime corroboration using receiver/return capture techniques.

### Next device validation

Test this exact build in this order:

1. Random Dice 2 — inspect `conditional-return`, argument multipliers and trampoline false positives;
2. MeChat — inspect `return-multiplier` plus owning method/return ABI;
3. RogueLegend — inspect FP operations and owning method;
4. Path of Kings — inspect `subobject-receiver-capture` and shared-feature replacement;
5. Earn to Die Rogue — no-regression reference: keep the existing 18 static + 2 derived patch result.

For each App archive the entire `HFAMap_<CFBundleIdentifier>/` folder and retain `[V034-DECRYPT]`, `[V034-BACKEND]` and `[V034-SCAN-END]` logs.

## Previous checkpoints

- v0.3.3 StaticParity: structural binary-first descriptor retention, decrypt no longer a descriptor prerequisite, universal AutoBackend entry and v033 output.
- v1.9.37.10 Earn to Die Rogue exact-build profile: Fuel `0x2D98AC8` and Boost `0x2D9887C` proven for the matching UnityFramework UUID only.
- v1.9.36.4 JSONExport: device-confirmed WayOfKings/iGMM parser checkpoint.

Evidence-preserving rule remains unchanged: runtime behavior must not be fabricated into canonical static bytes. A semantic backend may be a valid final analysis result even when no equivalent fixed patch has been proven.
