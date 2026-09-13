# HFAMap Handoff

## Current branch

`feature/hfamap-v1928-generic-menu-resolver`

## Base

`feature/hfamap-v1927-target-chain-resolver`
HEAD before v1.9.28 work: `d7d00e8a97698e8c0545390903e082dd83676166`
Build-tested v1.9.28 commit: `e2054a2196f6650e2a345ae90d46cd139daf40ba`

## Build state

- GitHub Actions run: `34781824064` — success.
- Artifact: `HFAMapUniversal-v1.9.28-GenericMenuResolver` (ID `10324649442`).
- Binary: `HFAMapUniversal_v1.9.28_GenericMenuResolver.dylib`.
- Architecture: arm64 Mach-O dylib.
- SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`.
- v1.9.27 legacy/iGMM exporters verified byte-identical across the v1.9.28 integration patch.
- Device tested: no.

## Architecture

v1.9.28 adds an independent resolver source instead of rewriting the v1.9.27 implementation resolver. The historical patch stack is still applied during CI, then `.github/scripts/hfamap_v1928_generic_menu.py` updates version markers and bridges the new resolver into the existing runtime UI/action traversal.

### Legacy AP/IGSecret path

Recognition is based on stable runtime structure:

`APPatchItem` protocol or `identifier/type/currentState/setCurrentState:` method fingerprint
→ class hierarchy (UIButton / UISlider / UIControl / container)
→ ivar type encodings (`IGSecretInt`, `IGSecretData`, `IGSecretString`, `APSubpatchManager`, `IGCodePatch`)
→ live object/action observation
→ target method IMP image/RVA
→ existing HFAMap descriptor/secret registration.

No obfuscated class names, ivar names, game feature labels, or sample RVAs are hardcoded in the new resolver.

### New jailpatch path

v1.9.28 only detects marker evidence such as `.app-key-metadata-`, `JailpatchConfigValidator`, `Jailpatch runtime table`, and `jailpatch`. It logs `family=jailpatch-v2 mode=probe-only`; no record/table layout is assumed yet.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`

Expected new tags include:

- `[GENERIC-ARCH]`
- `[GENERIC-ARCH-IMAGE]`
- `[GENERIC-CLASS]`
- `[GENERIC-IVAR]`
- `[GENERIC-MENU-ITEM]`
- `[GENERIC-DESCRIPTOR]`
- `[GENERIC-DESCRIPTOR-IVAR]`
- `[GENERIC-ACTION]`
- `[GENERIC-CLASS-SCAN]`

## Next validation

1. Inject the v1.9.28 dylib into one legacy AP/IGSecret (~15 MB family) target, open its menu, run `Auto Detect / Full Scan`, and collect both runtime logs.
2. Repeat with one jailpatch-v2 (~5 MB family) target. The expected result for this family is architecture/probe evidence, not a completed menu-record mapping yet.
3. Only after the legacy sample produces stable menu/descriptor/action evidence should v1.9.28 be marked runtime-confirmed.

## Verification discipline

Do not call v1.9.28 device-tested until a dylib has actually been injected and the two runtime logs have been collected. CI success means compiled + linked + signed + invariant-tested + artifact-delivered; it does not mean device/runtime validation.
