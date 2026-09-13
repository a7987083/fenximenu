# HFAMap Roadmap

## Current phase

v1.9.29 JailpatchRuntimeProfiler — 5 MB device validation

## Completed milestone: legacy AP / ~15 MB

The v1.9.28 GenericMenuResolver has now been validated on-device for the legacy AP/IGSecret family. The supplied runtime evidence produced 12 mapped features, real UnityFramework RVAs, original/enabled bytes, action IMP metadata, and a successful `.hfapatch.json` export.

This establishes the legacy ~15 MB resolver as runtime-confirmed for the tested architecture, while keeping the formal regression baseline at `build/hfamap-v1.4.4-20260901`.

## Current milestone: jailpatch-v2 / ~5 MB

Device logs from v1.9.28 established that the newer family has:

- a feature-definition array made of dictionaries with stable semantic keys such as `label` and `identifier`;
- per-feature collections of custom runtime-record objects;
- stripped Objective-C object type encodings (`@"?"`) on the important nested record fields;
- live menu controls and action/state methods whose IMPs reside in the target dylib.

Because the type metadata is stripped, v1.9.29 profiles runtime records structurally rather than matching `IGSecret*` type names.

## v1.9.29 scope

- Locate menu feature arrays semantically, without obfuscated ivar names.
- Locate per-feature runtime-record collections without hardcoding their dictionary key.
- Profile object ivars, primitive ivars/raw bytes, nested custom objects, methods/IMP RVAs, and block invoke RVAs.
- Emit `Documents/HFAMap_JailpatchMap.jsonl` beside existing logs.
- Preserve v1.9.28 legacy resolver behavior and v1.9.27 exporters.
- Reject current sample labels/classes/modules/RVAs in CI to enforce generic implementation.

## Build checkpoint

- Branch: `feature/hfamap-v1929-jailpatch-runtime-profiler`.
- Build-tested commit: `c6293b4b1aba7b5000d7e8dd6d20785121679588`.
- CI run: `34783065857` — success.
- Artifact ID: `10325960671`.
- Binary SHA256: `8b76b62424c9152a8e09b2e68dfccc09a590f6526403271b07c7056b1f8b0c3e`.

## Regression baselines

- Formal stable baseline: `build/hfamap-v1.4.4-20260901` @ `7bd19ba08a647104d230a2da299bcdd232687abf`.
- Legacy runtime checkpoint: v1.9.28 device log with successful 12-feature package export.
- Immediate code baseline: v1.9.29 build-tested commit above.

## Next task

Run v1.9.29 on the same ~5 MB family, open the menu, scan, exercise its visible controls, and collect `HFAMap_Learn.log`, `HFAMap_MenuMap.jsonl`, and `HFAMap_JailpatchMap.jsonl`. Use those records to identify stable table/record semantics and only then implement the next resolver stage.
