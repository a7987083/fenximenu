# HFAMap Roadmap

## Current phase — HFARuntimeAnalyzer v0.3.13.19 RuntimeTargetDecrypt

Branch: `feature/hfaruntime-v0.3.13.19-runtime-target-decrypt-v1`

Stable baseline: v0.3.13.18 `d9bf9dfbba4b81a32ba8bfc7ba86693e032393a6`

Build-tested commit: `d3754015e32c11ed514dddc90edbdb823d121b6a`

CI run: `36818369097` — success

Artifact: `HFARuntimeAnalyzer-v0.3.13.19-36818369097` (`11141648675`)

Binary: `HFARuntimeAnalyzer-v0.3.13.19-d3754015.dylib` — arm64, 417680 bytes

Binary SHA256: `5343df6ca28f7a09ad118a7c2ba915acf25529b02c3c9e363321146238432a4e`

Mach-O UUID: `8F08F0C9-BE3D-3E54-9BFE-536E6F635BB8`

### Goal

Close the remaining runtime-only/native-hook backends without confusing menu RVAs, replacement RVAs, descriptor addresses, or ObjC ivar offsets with the actual game target.

The v0.3.13.19 probe performs a read-only runtime target-record pass:

`loaded menu image -> encrypted target record -> installer xref -> replacement/original slot -> scratch-copy decrypt using the menu's initialized runtime key table -> strict plaintext target -> unique executable-image mapping -> semantic/IL2CPP enrichment`

### Implemented / CI passed

- generic target-record families `0x031201 / 0x031211`;
- unique decrypt fingerprint discovery in the selected loaded image;
- encrypted record copy to scratch memory before invoking the menu's own decrypt routine;
- no target/menu image writes and no hook installation;
- installer xref recovery and X3/X4 materialization for replacement/original slot;
- existing `HFASemanticAnalyzeReplacement` and IL2CPP owner enrichment reuse;
- strict hex plaintext parsing;
- unique executable-range target mapping with fail-closed ambiguity handling;
- target entry-byte capture;
- JSONL records: `runtime-target-decrypt-begin`, `runtime-target-image`, `runtime-target-backend`, `runtime-target-decrypt-end`;
- sample-specific names/RVAs prohibited by CI.

### Device acceptance order

1. **MeChat** — oracle: historical same-build target `0x65958E4`; this validates runtime key initialization + scratch decrypt.
2. **RogueLegend** — close Damage/Defence/God Mode shared native target.
3. **Aniimo** — decrypt both native records, then bind the 12 runtime identifiers to the recovered backends.
4. **Duck Survival** — decrypt the two native records and finish `dmgMul/god/nocd` backend binding.
5. **Path of Kings** — decrypt all three records; keep Debug Menu as runtime action unless downstream evidence proves otherwise.
6. **Random Dice 2** — decrypt all seven native records, including the four previously unbound support/backend records.
7. **Dragon Fever TD** — decrypt the single native target record and bind its runtime definitions.
8. **Whisper Castle** — expected zero target records; continue descriptor-less ObjC action/Block analysis separately.

### Next task

Inject exactly `HFARuntimeAnalyzer-v0.3.13.19-d3754015.dylib`, run **Scan Menu** after the menu/runtime key table has initialized, and archive:

- `Documents/HFARTD_<bundle-id>_RuntimeTargetDecrypt.jsonl`;
- the existing `Documents/HFAMap_<bundle-id>/` analyzer folder.

Do not promote any runtime target to a static patch unless target identity, current original bytes, and an equivalent fixed byte transformation are independently proven.

---

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
