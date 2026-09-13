# HFAMap Handoff

## Current branch

`feature/hfamap-v1932-crash-safe-full-scan`

## Current build

- Base branch: `feature/hfamap-v1931-generic-secret-decrypt-resolver`.
- Base commit: `4a4db8fbaff6f1a0decf715bc07b782c54022df0`.
- Build-tested v1.9.32 code commit: `ac2f5419f975ce9f63d2ad59546fe7c9ec16383a`.
- GitHub Actions run: `34790789928` — success.
- Artifact: `HFAMapUniversal-v1.9.32-CrashSafeFullScan` (ID `10328366811`).
- Binary: `HFAMapUniversal_v1.9.32_CrashSafeFullScan.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175616` bytes.
- SHA256: `96c47b4509929bf03289b3329ed4399f13cfa78db7eb2ac7c75bfa8fd1fd8c0c`.

## Confirmed runtime checkpoints

### Legacy AP / ~15 MB

Runtime-confirmed under v1.9.28 with 12 valid mappings, UnityFramework RVAs, original/enabled bytes, action IMP metadata, and successful `.hfapatch.json` export.

### Jailpatch selector bridge / ~5 MB

v1.9.30 device evidence confirms descriptor selector matching plus offset/patch-wrapper association. The old fixed decrypt locator failed, which motivated v1.9.31.

### v1.9.31 Full Scan regression

Both supplied ~5 MB games crashed when `Auto Detect / Full Scan` was pressed. This crash is upstream of decrypt execution:

- Both real menu targets were already found in window index 0.
- Scanning continued into unrelated windows/targets.
- Neither log reached `[AUTO-TRAVERSAL-END]` or `[AUTO-SCAN]`.
- One sample had `records=0`, so it could not have entered the generic secret-decrypt path.

The shared historical risk is the old v1.9.24 deep iGMM runtime-graph probe. It was attached to every custom control target and could enumerate object ivars through UIKit/framework superclasses. Objective-C exception handling does not catch raw `EXC_BAD_ACCESS` faults from unsafe object graph traversal.

## v1.9.32 design

Full Scan now follows a semantic, bounded path:

`UI control target`
→ generic menu observer
→ Jailpatch runtime profiler
→ `HFAJailpatchTargetHasFeatures`
→ if a semantic feature array exists, optionally register the stricter iGMM `{label,identifier,type}` array
→ log `[AUTO-MENU-CANDIDATE]`
→ set `gAutoMenuFound=1`
→ stop scanning later controls/windows
→ finalize scan.

Safety changes:

- The old `igmm_probe_target(o)` is no longer called by Auto Detect.
- `HFAJPFindFeatureArray` stops at framework superclasses.
- Runtime-record object profiling stops at framework superclasses.
- The historical iGMM object-ivar walker stops at framework superclasses.
- v1.9.31 `HFAResolveSecretDecrypt` and `HFADecryptWrapper` are preserved byte-for-byte.
- Legacy and iGMM exporters are preserved byte-for-byte.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`
- `Documents/HFAMap_JailpatchMap.jsonl`
- any generated `*.hfapatch.json` package.

## Next validation — two stages

Stage 1, scan stability: open the original menu and press `Auto Detect / Full Scan` without toggling any feature. Required evidence:

`[AUTO-MENU-CANDIDATE]`
→ `[AUTO-TRAVERSAL-END]`
→ `[AUTO-SCAN]`
→ no crash.

Run this on both supplied 5 MB games.

Stage 2, decrypt/mapping: only after Stage 1 is stable, exercise visible switches/controls and require:

`[JAILPATCH-SELECTOR-DESCRIPTOR]`
→ `[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1`
→ `[MAP-DECRYPT] rc=0`
→ `[MAPPING]` / `[FULL-MAPPING] valid=1`
→ preferably package export.

## Verification discipline

- v1.9.32 source integrated: yes.
- v1.9.32 compiled/linked/signed: yes.
- CI/regression/invariants/SHA256: passed.
- Artifact independently downloaded and re-hashed: passed.
- v1.9.32 device tested: no.
- v1.9.31 Full Scan crash reproduced on both supplied 5 MB games: yes.
- v1.9.31 generic decrypt runtime success: not established.
- v1.9.28 legacy 15 MB resolver device tested: yes.
