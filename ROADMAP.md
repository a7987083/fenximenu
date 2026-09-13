# HFAMap Roadmap

## Current phase

v1.9.31 GenericSecretDecryptResolver — 5 MB generic decrypt device validation

## Completed milestone: legacy AP / ~15 MB

The v1.9.28 GenericMenuResolver is runtime-confirmed on the tested legacy AP/IGSecret architecture. Device evidence produced 12 valid patch mappings, UnityFramework RVAs, original/enabled bytes, action IMP metadata, and successful `.hfapatch.json` export.

Formal regression baseline remains:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestone: jailpatch runtime profiling / ~5 MB

v1.9.29 device logs established stable runtime-record semantics despite randomized class/ivar names and stripped declared object types:

- feature dictionaries with stable `label` and `identifier` semantics;
- per-feature custom runtime-record collections;
- descriptor-like records exposing `identifier`, `type`, `architecture`, `active`, `offset`, `signature`, `range`, `searchDirection`, and `setActive:`;
- secret-wrapper objects exposing the stable `secret` interface.

## Completed milestone: v1.9.30 selector/wrapper bridge

v1.9.30 is now device-tested on the runtime-record style ~5 MB path.

Confirmed:

- stable selector fingerprint identifies the descriptor;
- `offset` resolves to the correct secret wrapper;
- after excluding `offset` and `signature`, the observed records yield one patch-data secret-wrapper candidate;
- the descriptor reaches the mature HFAMap mapping pipeline.

Not confirmed under v1.9.30:

- decrypted offset/patch data;
- valid `[MAPPING]` / `[FULL-MAPPING]` output;
- package export through the runtime-record selector path.

Root cause: v1.9.30 inherited the legacy decrypt locator `getter + 0xD00`; that candidate does not match the existing decrypt function fingerprint in the tested runtime-record 5 MB image.

The independent WayOfKings-style ~5 MB iGMM path remains a confirmed package-export path and is preserved as a regression checkpoint.

## Current milestone: v1.9.31 generic secret decrypt resolver

Cross-sample static inspection found that each supplied ~5 MB image contains exactly one function in loaded `__TEXT,__text` matching the decrypt fingerprint already used by the legacy HFAMap pipeline:

- candidate `+0x00`: `0xD105C3FF`
- candidate `+0x30`: `0xB9400408`
- candidate `+0x40`: `0x53187D00`

The two observed decrypt RVAs differ (`0x2123D4` and `0x2129A4`), which is why v1.9.31 resolves by image-local function fingerprint rather than by RVA. The observed `getter → decrypt` delta happens to be `0x1204` in both samples, but that value is explicitly not used by the implementation.

Resolver policy:

- Keep the already runtime-confirmed legacy `getter + 0xD00` fingerprint fast path for the 15 MB family.
- If the legacy candidate fails, parse the live Mach-O image and locate `__TEXT,__text`.
- Scan 4-byte-aligned addresses for the established decrypt fingerprint.
- Accept only exactly one match; reject zero or multiple matches.
- Cache resolved/ambiguous results per image.
- Reuse the existing decrypt ABI and mapping/export pipeline.
- Do not hardcode 5 MB image names, class names, feature labels, RVAs, or the observed `0x1204` delta.

## Build checkpoint

- Branch: `feature/hfamap-v1931-generic-secret-decrypt-resolver`.
- Base: `feature/hfamap-v1930-jailpatch-selector-resolver` @ `ded59d42ebca90895173ac4f185bd69cc94348a0`.
- Build-tested code commit: `e50600f00d65a84e6ed42b56dd18fbdd3a64906b`.
- CI run: `34786393869` — success.
- Artifact ID: `10326447565`.
- Binary: `HFAMapUniversal_v1.9.31_GenericSecretDecryptResolver.dylib`.
- Binary SHA256: `7638894c72b7b5f391be02ea3ee481fa5ff31cd28080eda2de3bc07fe5a1453f`.
- Previous exporter byte-identity/regression checks: passed.
- v1.9.30 selector bridge regression checks: passed.
- Sample-specific hardcode checks: passed.
- v1.9.31 device validation: pending.

## Regression checkpoints

- Formal stable baseline: v1.4.4 exact branch/SHA above.
- Legacy runtime checkpoint: v1.9.28 15 MB, 12-feature successful package export.
- Jailpatch structure checkpoint: v1.9.29 runtime records/selectors confirmed.
- Jailpatch bridge checkpoint: v1.9.30 selector + offset/patch-wrapper association confirmed; decrypt locator failed.
- iGMM checkpoint: WayOfKings-style ~5 MB package export remains functional.
- Immediate code checkpoint: v1.9.31 build-tested commit above.

## Next task

Run v1.9.31 on the runtime-record style ~5 MB sample, open its original menu, run `Auto Detect / Full Scan`, exercise visible controls, and collect:

- `HFAMap_Learn.log`
- `HFAMap_MenuMap.jsonl`
- `HFAMap_JailpatchMap.jsonl`
- any generated `*.hfapatch.json`

Promote the generic 5 MB resolver to runtime-confirmed only when the evidence chain reaches:

`[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1`
→ `[MAP-DECRYPT] rc=0`
→ valid decrypted offset/patch data
→ `[MAPPING]` / `[FULL-MAPPING] valid=1`
→ preferably successful package export.
