# HFAMap Handoff

## Current branch

`feature/hfamap-v1928-generic-menu-resolver`

## Base

`feature/hfamap-v1927-target-chain-resolver`
HEAD before v1.9.28 work: `d7d00e8a97698e8c0545390903e082dd83676166`

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

No obfuscated class names, ivar names, game feature labels, or sample RVAs should be hardcoded.

### New jailpatch path

v1.9.28 only detects marker evidence such as `.app-key-metadata-`, `JailpatchConfigValidator`, `Jailpatch runtime table`, and `jailpatch`. It logs `family=jailpatch-v2 mode=probe-only`; no record/table layout is assumed yet.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`

Expected new tags include:

- `[GENERIC-ARCH]`
- `[GENERIC-CLASS]`
- `[GENERIC-IVAR]`
- `[GENERIC-MENU-ITEM]`
- `[GENERIC-DESCRIPTOR]`
- `[GENERIC-DESCRIPTOR-IVAR]`
- `[GENERIC-ACTION]`
- `[GENERIC-CLASS-SCAN]`

## Verification discipline

Do not call v1.9.28 device-tested until a dylib has actually been injected and the two runtime logs have been collected. CI success only means compiled + invariant-tested.
