# HFAMap Roadmap

## Current phase

v1.9.30 JailpatchSelectorResolver — 5 MB selector-bridge device validation

## Completed milestone: legacy AP / ~15 MB

The v1.9.28 GenericMenuResolver is runtime-confirmed on the tested legacy AP/IGSecret architecture. Device evidence produced 12 valid patch mappings, UnityFramework RVAs, original/enabled bytes, action IMP metadata, and successful `.hfapatch.json` export.

Formal regression baseline remains:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestone: jailpatch runtime profiling / ~5 MB

v1.9.29 device logs established that the newer runtime-record family preserves stable semantic behavior despite randomized names and stripped declared object types:

- feature dictionaries with stable `label` and `identifier` semantics;
- per-feature custom runtime-record collections;
- descriptor-like records exposing `identifier`, `type`, `architecture`, `active`, `offset`, `signature`, `range`, `searchDirection`, and `setActive:`;
- secret-wrapper objects exposing the stable `secret` interface;
- record strings that include feature keys/identifiers and module text;
- compatible semantic property/selector fingerprints across both supplied ~5 MB dylibs.

A second ~5 MB path also produced a valid WayOfKings patch package via the already-existing iGMM path, which remains a required regression path.

## Current milestone: v1.9.30 selector resolver

v1.9.30 promotes the runtime profiler evidence into a generic resolver without relying on obfuscated class/ivar names, current feature labels, sample module names, or sample RVAs.

Resolver policy:

- Require the stable descriptor selector fingerprint.
- Reuse semantic getters rather than field-name guesses.
- Discover `secret` wrappers through runtime behavior even when ObjC type metadata is `@"?"`.
- Register `offset` through the existing offset-wrapper path.
- Exclude `offset` and `signature` from patch-data candidates.
- Only auto-register patch data when exactly one remaining secret-wrapper candidate exists.
- Fall back to evidence-only mode on ambiguity.
- Reuse the mature v1.9.27 mapping/decrypt/group/full-export pipeline rather than adding a second decrypt implementation.

## Build checkpoint

- Branch: `feature/hfamap-v1930-jailpatch-selector-resolver`.
- Base: `feature/hfamap-v1929-jailpatch-runtime-profiler` @ `0ddbac96ddae0a0162711ce4d7e979d7d1b95438`.
- Build-tested code commit: `786a26eb66a3aa22d1f1c1ef7a94910e7f8b6f42`.
- CI run: `34785200383` — success.
- Artifact ID: `10326735655`.
- Binary SHA256: `6c716180e7e5a2659cfb538e6ca6ee217773a0ce583741f9d1e43f0f140f9d14`.
- Previous exporter byte-identity/regression checks: passed.
- Sample-specific hardcode checks: passed.
- v1.9.30 device validation: pending.

## Regression checkpoints

- Formal stable baseline: v1.4.4 exact branch/SHA above.
- Legacy runtime checkpoint: v1.9.28 15 MB, 12-feature successful package export.
- Jailpatch profiling checkpoint: v1.9.29 5 MB runtime records/selectors confirmed.
- iGMM checkpoint: WayOfKings-style ~5 MB package export remains functional.
- Immediate code checkpoint: v1.9.30 build-tested commit above.

## Next task

Run v1.9.30 on the runtime-record style ~5 MB sample, open its original menu, run `Auto Detect / Full Scan`, exercise all visible controls, and collect `HFAMap_Learn.log`, `HFAMap_MenuMap.jsonl`, `HFAMap_JailpatchMap.jsonl`, plus any generated `.hfapatch.json`.

Promote v1.9.30 to runtime-confirmed only if the evidence chain reaches valid `[MAP-DECRYPT]` and `[MAPPING]`/`[FULL-MAPPING]` output (or package export). If the bridge remains ambiguous, refine the discriminator from cross-sample runtime evidence rather than hardcoding names or offsets.
