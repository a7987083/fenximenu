# HFAMap Handoff

## Current branch

`feature/hfamap-v1929-jailpatch-runtime-profiler`

## Current build

- Build-tested code commit: `c6293b4b1aba7b5000d7e8dd6d20785121679588`
- GitHub Actions run: `34783065857` — success.
- Artifact: `HFAMapUniversal-v1.9.29-JailpatchRuntimeProfiler` (ID `10325960671`).
- Binary: `HFAMapUniversal_v1.9.29_JailpatchRuntimeProfiler.dylib`.
- Architecture: arm64 Mach-O dylib.
- SHA256: `8b76b62424c9152a8e09b2e68dfccc09a590f6526403271b07c7056b1f8b0c3e`.

## Confirmed v1.9.28 device evidence

### Legacy AP / ~15 MB

Runtime-confirmed. The device log produced a `legacy-ap` resolver classification, 12 valid feature mappings, UnityFramework RVAs, original/enabled bytes, action IMP metadata, and a successful `.hfapatch.json` export. This path is no longer merely “compiled-ready”.

### Jailpatch-v2 / ~5 MB

The v1.9.28 device log confirmed a three-feature definition array and per-feature runtime-record collections. The menu items expose `identifier/type/currentState/setCurrentState:` behavior, but nested descriptor-like ivars have Objective-C type encoding `@"?"`; therefore the legacy `IGSecret*` type-name fingerprint cannot identify the record layout.

## v1.9.29 design

The new profiler does not depend on obfuscated class names, ivar names, game labels, module names, or sample RVAs.

Discovery chain:

`menu target`
→ find NSArray whose entries are dictionaries with non-empty `label` + `identifier`
→ for each feature, locate remaining collection containing custom runtime objects
→ recursively profile runtime records
→ object ivars / primitive ivars / nested custom objects
→ class methods + type encodings + IMP image/RVA
→ block invoke image/RVA
→ structured JSONL evidence.

The target is marked “already profiled” only after a populated feature array exists, so observing the controller before the menu is populated does not suppress a later real scan.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`
- `Documents/HFAMap_JailpatchMap.jsonl`

Important v1.9.29 tags:

- `[JAILPATCH-TARGET]`
- `[JAILPATCH-FEATURE]`
- `[JAILPATCH-RECORD]`
- `[JAILPATCH-CLASS]`
- `[JAILPATCH-METHOD]`
- `[JAILPATCH-IVAR]`
- `[JAILPATCH-SCALAR]`
- `[JAILPATCH-STRING]`
- `[JAILPATCH-BLOCK]`

## Next validation

Inject v1.9.29 into the ~5 MB target, open the original menu, run `Auto Detect / Full Scan`, then operate each visible switch at least once. Collect all three files above. The next engineering step is to identify the stable semantics of the nested runtime-record objects/table from that evidence, not to hardcode the current sample classes or offsets.

## Verification discipline

- v1.9.29 source integrated: yes.
- v1.9.29 compiled/linked/signed: yes.
- CI/invariants/SHA256: passed.
- v1.9.29 5 MB device tested: no.
- v1.9.28 15 MB device tested: yes.
