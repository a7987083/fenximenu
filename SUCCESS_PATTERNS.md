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

Preferred relationship:

`UI label -> identifier -> feature key -> descriptor`

Historical implementations normalized identifiers such as `3` to keys such as `3-switch` when correlating feature definitions with patch descriptors.

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

Historical working model:

`button/control label`
`    -> identifier`
`    -> normalized feature key`
`    -> descriptor owner`
`    -> offsetWrapper / patchWrapper / signature`

Do not assume button N corresponds to descriptor N.

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

## 8. Historical branches worth mining

High-value historical branches:

- `feature/hfamap-v1927-target-chain-resolver`
- `feature/hfamap-v1928-generic-menu-resolver`
- `feature/hfamap-v1931-generic-secret-decrypt-resolver`
- `feature/hfamap-v19370-clean-family-resolver`
- `feature/hfamap-v19379-complete-feature-export`
- `feature/hfamap-v193710-unified-feature-model`
- `feature/hfamap-v193711-earntodie-canonical-14`

Reuse proven concepts and evidence gates, not unsafe global hooks or fixed historical RVAs.

## 9. Current development direction

For the current `zpatchig` line, the next safe migration order is:

1. Feature label resolver: label -> identifier.
2. Descriptor correlator: identifier/key -> descriptor.
3. Legacy secret-wrapper resolver: `IGSecretInt` -> validated plaintext offset.
4. Signature/data resolver.
5. Target image + RVA resolver.
6. Original-byte validation.
7. Canonical exporter only after all truth gates pass.

Current parser/observer work must remain evidence-first and reversible.
