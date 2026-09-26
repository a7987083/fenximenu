# Development Status

## HFARuntimeAnalyzer v0.3.4 SemanticBackend — Phase 1

Current branch: `feature/hfaruntime-v0.3.4-semantic-backend-analyzer`

Baseline: v0.3.3 `f3090a8c1998f443eb4cae03eb857bfadf2c2002`

Current build-tested commit: `3918052e30fcc0d7dca78e4754240cf5e94dba3c`

CI run: `36218004874` — PASS

Artifact: `HFARuntimeAnalyzer-v0.3.4-SemanticBackend` (ID `10897963845`)

Binary: `HFARuntimeAnalyzer-v0.3.4-SemanticBackend.dylib`

Binary size: `265424` bytes

Binary SHA256: `cc4cec47801cd3d5dfa581f00fc0be6123a7388e82805f9167765de9d32f9f00`

Artifact ZIP digest: `sha256:de49e2dfd51deb6004e22b407ba20554c81da8c22005f928d633a81f1e67274d`

### Development states

- 已修改: yes
- 已提交: yes
- 已编译: yes
- CI通过: yes
- Artifact下载并复核: yes
- arm64 Mach-O: yes
- v0.3.4 真机运行: pending
- v0.3.4 多游戏语义回归: pending
- Feature ↔ Backend binding: phase 2 pending
- descriptor-less Whisper backend: pending
- canonical bridge: pending

### Implemented in phase 1

- independent `HFARuntimeSemanticAnalyzer` module;
- bounded ARM64 CFG-lite support for unconditional `B` / shared epilogue constant-return evidence;
- original-slot and `BLR original` recognition;
- integer `MUL` and FP `FMUL` / `FDIV` / `FSUB` / `FCSEL` evidence;
- receiver and subobject-receiver propagation;
- callback constant-argument diagnostics;
- semantic classifications with `unknown-runtime` fail-closed fallback;
- bounded live IL2CPP owning-method enrichment;
- Assembly / Namespace / Class / Method / MethodInfo / method pointer / intra-method offset;
- parameter and return ABI evidence plus instance/generic/inflated state;
- new `HFAMap_RuntimeAnalyzer_v034.json`;
- v033/v032/v03 compatibility outputs retained;
- analyzer outputs continue through `HFAOutputPath()` under `Documents/HFAMap_<CFBundleIdentifier>/`.

### Current evidence boundary

CI proves generated-source integration, iPhoneOS compilation/link/sign, output-path guards and final binary markers. It does **not** prove that the new semantic classifier is correct on physical-device samples.

Do not mark the following as device-confirmed until new v034 folders/logs are collected:

- Random Dice 2 `MergeAny` -> `conditional-return`;
- MeChat `Points` -> `return-multiplier`;
- RogueLegend float `FMUL/FDIV/FCSEL` transform;
- Path of Kings `+0x50/+0x38` subobject receiver capture.

### Next required evidence

Use this exact v0.3.4 dylib and collect the complete per-App `HFAMap_<CFBundleIdentifier>/` folder. Prioritize Random Dice 2, MeChat, RogueLegend and Path of Kings, then regress Earn to Die Rogue. Require `[V034-DECRYPT]`, `[V034-BACKEND]`, `[V034-SCAN-END]`, `HFAMap_RuntimeAnalyzer_v034.json`, `semanticEvidence`, `semanticType` and `owningMethod`.

## Stable parser/exporter checkpoint

v1.9.36.4 JSONExport remains the device-confirmed WayOfKings/iGMM parser checkpoint. That line is separate from the v0.3.4 SemanticBackend work and its remaining cross-family parser regressions are unchanged.
