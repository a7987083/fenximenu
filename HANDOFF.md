# HFAMap Handoff

## Current branch

`feature/hfamap-v1930-jailpatch-selector-resolver`

## Current build

- Base branch: `feature/hfamap-v1929-jailpatch-runtime-profiler`.
- Base commit: `0ddbac96ddae0a0162711ce4d7e979d7d1b95438`.
- Build-tested v1.9.30 code commit: `786a26eb66a3aa22d1f1c1ef7a94910e7f8b6f42`.
- GitHub Actions run: `34785200383` — success.
- Artifact: `HFAMapUniversal-v1.9.30-JailpatchSelectorResolver` (ID `10326735655`).
- Binary: `HFAMapUniversal_v1.9.30_JailpatchSelectorResolver.dylib`.
- Architecture: arm64 Mach-O dylib.
- SHA256: `6c716180e7e5a2659cfb538e6ca6ee217773a0ce583741f9d1e43f0f140f9d14`.

## Confirmed runtime checkpoints

### Legacy AP / ~15 MB

Runtime-confirmed from v1.9.28 device logs. The resolver produced 12 valid mappings with UnityFramework RVAs, original/enabled bytes, action IMP metadata, and a successful `.hfapatch.json` export.

### Jailpatch-v2 / ~5 MB — v1.9.29 evidence

The v1.9.29 device capture confirmed populated feature dictionaries and runtime-record arrays. The descriptor-like runtime record retains stable semantic selectors even though its class and ivar names are randomized and important object ivars are declared as `@"?"`:

`identifier / type / architecture / active / offset / signature / range / searchDirection / setActive:`

The same semantic property/selector set and compatible `secret` wrapper interface were confirmed across both supplied ~5 MB dylibs by static metadata comparison. This is the primary portability signal for v1.9.30.

One supplied ~5 MB path also successfully produced a WayOfKings `.hfapatch.json` package through the pre-existing iGMM resolver/exporter. v1.9.30 deliberately preserves that path rather than replacing it.

## v1.9.30 resolver design

Discovery/bridge chain:

`v1.9.29 runtime record`
→ require stable selector fingerprint
→ call `identifier/type/architecture/active/offset/signature/range/searchDirection`
→ enumerate object ivars without trusting randomized names or declared class metadata
→ collect string evidence (`<id>-switch`, identifier, loaded-module name)
→ collect objects implementing stable `secret`
→ register `offset` object as offset wrapper
→ exclude `offset` and `signature`
→ if exactly one secret-wrapper candidate remains, register it as patch-data wrapper
→ `HFARegisterPatchObject`
→ reuse existing `setActive:` hook
→ existing decrypt / `[MAPPING]` / group mapping / full mapping / package export pipeline.

If patch-data candidate count is not exactly one, v1.9.30 logs `bridgeStatus=evidence-only` and does not force a mapping.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`
- `Documents/HFAMap_JailpatchMap.jsonl`
- Any generated `*.hfapatch.json` package.

Important v1.9.30 evidence tags:

- `[JAILPATCH-TARGET]`
- `[JAILPATCH-FEATURE]`
- `[JAILPATCH-RECORD]`
- `[JAILPATCH-SELECTOR-DESCRIPTOR]`
- `[MAP-DECRYPT]`
- `[MAPPING]`
- `[GROUP-MAPPING]`
- `[FULL-MAPPING]`

## Next validation

Inject v1.9.30 into the runtime-record style ~5 MB target, open the original menu, run `Auto Detect / Full Scan`, then exercise every visible control. Collect all three logs and any generated `.hfapatch.json` file.

The success criterion is not merely seeing the selector descriptor. To mark the selector resolver runtime-confirmed, evidence should show the bridge reaching the mature mapping pipeline with valid decrypted offset/patch data and preferably `FULL-MAPPING`/package export. If it remains evidence-only, use the logged secret-wrapper set to refine the generic discriminator instead of adding sample-specific offsets/classes.

## Verification discipline

- v1.9.30 source integrated: yes.
- v1.9.30 compiled/linked/signed: yes.
- CI/invariants/exporter regression/SHA256: passed.
- v1.9.30 device tested: no.
- v1.9.29 ~5 MB profiler device tested: yes.
- v1.9.28 ~15 MB resolver device tested: yes.
