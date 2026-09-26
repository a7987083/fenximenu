# HFAMap Roadmap

## Current phase — HFARuntimeAnalyzer v0.3.4 SemanticBackend

Branch: `feature/hfaruntime-v0.3.4-semantic-backend-analyzer`

Baseline: v0.3.3 `f3090a8c1998f443eb4cae03eb857bfadf2c2002`

Phase-1 build-tested commit: `3918052e30fcc0d7dca78e4754240cf5e94dba3c`

CI run: `36218004874` — success

Artifact: `HFARuntimeAnalyzer-v0.3.4-SemanticBackend` (`10897963845`)

Binary SHA256: `cc4cec47801cd3d5dfa581f00fc0be6123a7388e82805f9167765de9d32f9f00`

### Goal

Move beyond coarse `runtime-state` classification and make the on-device analyzer explain a recovered native backend:

`descriptor/action -> replacement/original slot/target -> native semantic evidence -> IL2CPP owning method/ABI -> Feature binding -> canonical static patch OR Runtime Semantic backend`.

A runtime semantic result is a valid analysis result. Do not manufacture a static patch when no equivalent fixed byte transformation is proven.

### Phase 1 — native semantic core + IL2CPP enrichment — implemented / CI passed

- standalone semantic analyzer module;
- bounded `B` / shared-epilogue constant-return recognition;
- original-slot `BLR` evidence;
- integer/FP arithmetic evidence (`MUL`, `FMUL`, `FDIV`, `FSUB`, `FCSEL`);
- receiver and subobject-receiver flow;
- callback constant argument evidence;
- semantic types with `unknown-runtime` fallback;
- bounded IL2CPP owning-method resolution;
- Assembly/Namespace/Class/Method/MethodInfo/method pointer/intra-method offset;
- parameter/return ABI plus instance/generic/inflated evidence;
- `semanticEvidence`, `semanticType`, `legacySemanticType`, `owningMethod` export;
- `HFAMap_RuntimeAnalyzer_v034.json` in the per-App analyzer output folder.

### Milestone A — device semantic acceptance

Test in this order:

1. Random Dice 2;
2. MeChat;
3. RogueLegend;
4. Path of Kings;
5. Earn to Die Rogue regression.

Acceptance targets:

- every selected dylib emits `[V034-DECRYPT]`, `[V034-BACKEND]`, `[V034-SCAN-END]`;
- `HFAMap_RuntimeAnalyzer_v034.json` exists in the App folder;
- Random Dice `MergeAny` exposes branch-aware conditional return evidence;
- MeChat exposes post-original integer multiplication evidence and coherent owning-method ABI;
- Rogue exposes float post-original transformation evidence without being forced into a fake static patch;
- Path exposes subobject receiver flow for the previously observed `+0x50/+0x38` cases;
- Earn keeps the existing 18 static + 2 derived patch behavior.

### Phase 2 — Feature ↔ Backend binding

Use UnitXP `ZNSharedSiteExecutionProbeV3` concepts and existing menu identifiers/registration evidence to support:

- one Feature -> multiple backend records;
- one backend/replacement -> multiple Features;
- support-thunk/trampoline exclusion;
- per-feature semantic evidence within a shared replacement.

Primary fixtures: Path Damage/Defence/God Mode and Random Dice DmgMulti/MergeAny/SPGainMulti.

### Phase 3 — descriptor-less action backend

Add a bounded ObjC action/IMP analysis path when descriptor discovery returns zero but menu Feature/action evidence exists.

Primary fixture: WhisperCastle `gIlPAd::nwoyqBjpyKcmp` / flattened action path.

### Phase 4 — stronger CFG/dataflow

- basic-block worklist instead of primarily linear bounded scanning;
- conditional edge following and path merge;
- improved register taint across copies/loads;
- better original-call argument/return provenance;
- loop/flattened-dispatch guards and strict time budgets.

### Phase 5 — canonical/runtime bridge

For each semantic backend:

- if an equivalent static transformation is uniquely proven, emit canonical `offset/original/enabled` after target identity and original-byte validation;
- otherwise preserve it as a Runtime Semantic backend with owning-method/ABI/Feature evidence;
- never derive bytes only to satisfy an expected feature count.

### Phase 6 — unified output routing and optional runtime corroboration

- move remaining legacy package/identity/IGMM exports into the same per-App bundle folder;
- add optional receiver/return runtime corroboration inspired by UnitXP `ZNM47ReceiverCapture` and `ZNM48ReturnCapture`;
- runtime evidence validates static hypotheses but must not become a prerequisite for ordinary static discovery.

## Stable / previous checkpoints

- v0.3.3 StaticParity: binary-first descriptor discovery and universal AutoBackend entry.
- v1.9.37.10 Earn exact-build profile: Fuel/Boost static completion for the matching build only.
- v1.9.36.4 JSONExport: device-confirmed WayOfKings/iGMM parser checkpoint.

Core rules remain:

- preserve evidence instead of forcing every runtime behavior into a static patch;
- canonical static patches require target identity and original-byte truth;
- preferred Mach-O VM addresses define static offsets;
- runtime-only/ambiguous evidence stays explicit;
- generated outputs must be attributable to the current App and current scan.
