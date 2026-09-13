# Development Changelog

## v1.9.29 JailpatchRuntimeProfiler — compiled / awaiting 5 MB device validation

Branch: `feature/hfamap-v1929-jailpatch-runtime-profiler`
Build-tested commit: `c6293b4b1aba7b5000d7e8dd6d20785121679588`
Successful CI run: `34783065857`
Artifact ID: `10325960671`
Binary SHA256: `8b76b62424c9152a8e09b2e68dfccc09a590f6526403271b07c7056b1f8b0c3e`

### Runtime evidence received from v1.9.28

- Legacy AP / ~15 MB family is now device-runtime confirmed.
- The sample was recognized as `family=legacy-ap mode=resolver` and exported 12 valid patch features to a `.hfapatch.json` package.
- Runtime evidence included menu identifiers, action IMP image/RVA, UnityFramework patch RVAs, original bytes, and enabled bytes.
- The ~5 MB family was recognized as `family=jailpatch-v2`; its menu controller exposed a three-entry feature-definition array with identifiers `0`, `1`, and `2`.
- Each 5 MB feature dictionary contains a runtime-record collection. Record objects expose identifier-related strings, module text, nested custom objects, primitive/object ivars, and runtime action/state methods.
- Root cause of the v1.9.28 descriptor miss: relevant object ivars use stripped Objective-C type encoding `@"?"`, so `IGSecret*` type-name fingerprinting cannot identify this family.

### Added in v1.9.29

- `hfamap/src/HFAMapJailpatchRuntimeProfiler.m`
  - Locates feature arrays semantically using non-empty `label` + `identifier` dictionaries.
  - Finds runtime-record collections without depending on their obfuscated dictionary key.
  - Profiles custom record objects recursively with bounded depth.
  - Records object ivars even when their ObjC type is stripped to `@"?"`.
  - Records primitive ivar offsets/raw bytes.
  - Enumerates custom-class methods with type encodings plus IMP image/RVA.
  - Resolves block invoke image/RVA.
  - Emits `Documents/HFAMap_JailpatchMap.jsonl`.
- `.github/scripts/hfamap_v1929_jailpatch_runtime.py`
  - Bridges the profiler into target discovery and UIControl actions.
  - Defers target dedupe until a populated feature array exists, preventing an early empty controller observation from suppressing the real scan.
- `.github/workflows/theos-hfamap-v1929-jailpatch-runtime.yml`
  - Replays the historical patch stack, preserves v1.9.28 behavior/exporters, rejects sample-specific hardcoding, builds/signs the arm64 dylib, verifies SHA256, and uploads the artifact.

### Verification

- Patch chain: passed.
- v1.9.28 behavior regression checks: passed.
- Legacy/iGMM exporter byte-identity checks: passed.
- Jailpatch profiler invariant checks: passed.
- Explicit feature/class/module/RVA hardcode deny-list checks: passed.
- Compiled/linked/signed: yes, arm64.
- GitHub Actions: success (`34783065857`).
- Artifact uploaded: yes.
- SHA256 independently rechecked after artifact download: yes.
- v1.9.29 device tested on 5 MB family: not yet.

## v1.9.28 GenericMenuResolver — runtime checkpoint

Successful CI run: `34781824064`
Binary SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`

The legacy ~15 MB path is now runtime-confirmed from device logs. The ~5 MB probe also successfully exposed enough structure to design v1.9.29, but v1.9.28 itself did not resolve the stripped descriptor record layout.
