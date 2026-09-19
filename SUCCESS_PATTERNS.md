# ZPatchIG Verified Success Patterns

This document records only evidence-backed reverse-engineering patterns that have been validated by repository history, device logs, or both. Do not treat historical offsets or decompiler output as universal truth.

## Evidence policy

- Prefer real Mach-O / ObjC runtime / ARM64 evidence over strings or decompiler guesses.
- Distinguish file offset, RVA, preferred VA, runtime VA, ASLR slide.
- Never reuse a historical offset across versions without relocating and revalidating it.
- Static analysis, runtime observation, and stable-version comparison should corroborate each other.
- Mark conclusions as verified / inferred / unverified when evidence is incomplete.

## 1. Menu family classification

Validated on current device samples:

- Legacy AP descriptors: instance size `0xA0`, descriptor class index 15 in the current sample set, typed ivars such as `IGSecretInt`, `IGSecretString`, `APSubpatchManager`.
- C4M0 descriptors: instance size `0xA0`, descriptor class index 173 in the current sample set, corresponding object types commonly erased as `@"?"`.
- Runtime presence of `C4M0Manager` / iGameGod does not imply the candidate menu image itself is C4M0.
- ABI/type fingerprint wins over incidental runtime strings.

Do not classify by string presence alone.

## 2. Safe descriptor observation

Validated by ZPatchIG v0.2.1 device logs:

- `setActive:` can be observed repeatedly on both Legacy AP and C4M0 descriptors.
- Hook only setters directly implemented by the descriptor class.
- Require `void` return type, exact argument count, and compatible argument encoding.
- Save original IMP and restore only when the current IMP still equals our replacement.
- Avoid nested diagnostics / shared Foundation mutation in the hot setter path.
- Keep the hot path minimal and bounded.

The v0.2 crash pattern was reproduced when setter events entered heavy Foundation/diagnostic work. v0.2.1 removed that path and multiple previously crashing games completed repeated `setActive:` observation and normal disarm.

## 3. Feature label -> identifier mapping

Historical successful HFAMap branches established a reusable mapping model:

- Resolve user-facing label from real UI/control objects using sources such as `currentTitle`, `text`, `accessibilityLabel`, `titleLabel.text`.
- Resolve menu `identifier` from the feature/control object.
- Register `{label, identifier}` as a feature definition.
- Do not map by visual order alone.

Historical implementations normalized identifiers such as `3` to keys such as `3-switch` when correlating feature definitions with patch descriptors.

### v2.2.3 correction: container evidence outranks shared UI target evidence

The supplied HFAMapUniversal v2.2.3 source documents a concrete failure mode in older UI-target correlation: multiple controls can share a target, so target traversal may reach the same descriptor and temporarily inherit the first button label. Therefore:

- shared `UIControl -> target` relationships are auxiliary evidence only;
- the preferred primary relationship is a feature container/dictionary that itself owns both `label` and `identifier`, followed by its child array/records and descriptor objects;
- never pair features and descriptors by visual order, array proximity, or shared target alone.

Preferred relationship:

`feature container(label + identifier) -> child array/record -> descriptor -> descriptor ivars`

UI labels can corroborate this relationship but must not override it.

## 4. Descriptor -> secret wrappers

Historical Legacy AP analysis and current runtime layout agree on the following model:

- `IGSecretInt` is the offset wrapper.
- `IGSecretData` is the patch/data wrapper.
- `IGSecretString` is signature-related metadata.
- The descriptor owner/object identity must be preserved so wrappers from one descriptor are not mixed with another.

Representative Legacy descriptor fields in the validated sample family include:

- `+0x48` -> `IGSecretInt` offset wrapper
- `+0x58` -> `IGSecretString` signature wrapper
- `+0x98` -> `APSubpatchManager`

Treat the offsets as ABI evidence for this family/sample set, not as a universal cross-version constant without revalidation.

### Address-semantics rule

An Objective-C ivar offset such as `+0x48` is an offset inside an object instance. It is **not** a Mach-O RVA, file offset, preferred VA, runtime VA, or ASLR slide. Any exported descriptor field offset must be labeled `objc-instance-ivar-only` unless it is independently converted into another address domain with explicit evidence.

## 5. Secret-wrapper decoding

Historical branches successfully used a wrapper getter -> decrypt routine chain, but historical relative offsets must not be copied blindly.

Reusable successful idea:

1. Resolve the wrapper's real getter IMP.
2. Resolve candidate decrypt routine(s) from real ARM64 control flow / calls.
3. Validate candidate instructions and image ownership.
4. Copy the encrypted blob to scratch memory.
5. Invoke only a validated decrypt routine.
6. Record getter image/RVA, decrypt image/RVA, blob metadata, and result.

Historical code used `getter + 0xD00` plus an ARM64 fingerprint. The fingerprint-validation concept is useful; the fixed `+0xD00` relation is version-specific and must not be reused as a universal rule.

## 6. Button / feature / descriptor correlation

Preferred model after the v2.2.3 review:

`feature container label + identifier`
`    -> normalized feature key`
`    -> child descriptor relationship`
`    -> offsetWrapper / patchWrapper / signature`

UI control/target evidence may be retained as an auxiliary graph edge but must not define the descriptor relationship by itself.

## 7. Canonical patch truth gates

A feature may be exported as a canonical static byte patch only after all relevant truth gates pass:

- target image resolved;
- image UUID recorded;
- architecture recorded;
- runtime address converted to a stable RVA with correct image base/slide semantics;
- original bytes read and verified;
- patch bytes resolved and verified;
- source descriptor/feature relationship established;
- runtime-only actions are not mislabeled as static byte patches.

Historical exporters already distinguished static patches from runtime actions / booleans / block handlers. Preserve that distinction.

## 8. IL2CPP mapping success pattern

The Earn to Die Rogue 1.28.251 profile provides a verified example of a separate backend:

`global-metadata.dat -> Assembly-CSharp.dll type/method/field -> UnityFramework method RVA -> ARM64 field data flow -> patch candidate -> original-byte validation`

For that exact binary, metadata mapped `com.notdoppler.ETDR.Car.FixedUpdate()` to UnityFramework RVA `0x2D9827C`, with `_fuelAmount +0xB8` and `_boostAmount +0xBC`. ARM64 load/sub/store sequences at the field offsets corroborated the mapping. These exact RVAs are version-specific and must not be reused on other builds.

## 9. Evidence graph rule

The universal analyzer should preserve why a relationship exists, not only the final value. Evidence nodes/edges should distinguish at least:

- UI/control evidence (auxiliary);
- menu target/object-graph reachability;
- feature container with same-container label+identifier (primary);
- descriptor ownership/child-array relationship;
- Objective-C ivar evidence with `objc-instance-ivar-only` semantics;
- runtime observation;
- secret/decrypt evidence;
- IL2CPP metadata/method/field/data-flow evidence;
- Mach-O identity/RVA/original-byte truth evidence.

Unknown or conflicting paths remain `unresolved`; evidence must not be collapsed into a guessed offset.

## 10. Historical branches worth mining

High-value historical branches:

- `feature/hfamap-v1927-target-chain-resolver`
- `feature/hfamap-v1928-generic-menu-resolver`
- `feature/hfamap-v1931-generic-secret-decrypt-resolver`
- `feature/hfamap-v19370-clean-family-resolver`
- `feature/hfamap-v19379-complete-feature-export`
- `feature/hfamap-v193710-unified-feature-model`
- `feature/hfamap-v193711-earntodie-canonical-14`

Reuse proven concepts and evidence gates, not unsafe global hooks or fixed historical RVAs.

## 11. Current development direction

For the current `zpatchig` line:

1. Container-first feature correlation and Evidence Graph foundation — implemented in v0.4.0, CI verified, device validation pending.
2. Async Legacy offset/runtime evidence edges into the graph.
3. Signature/data resolver.
4. IL2CPP metadata backend using the existing graph schema.
5. Target image + stable RVA resolver.
6. Original-byte validation.
7. Canonical exporter only after all truth gates pass.

Current parser/observer work must remain evidence-first, bounded, and reversible.
