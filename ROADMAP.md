# HFAMap Roadmap

## Current phase

v1.9.32 CrashSafeFullScan — two-game 5 MB scan-stability validation

## Completed milestone: legacy AP / ~15 MB

v1.9.28 remains runtime-confirmed on the tested legacy AP/IGSecret architecture with 12 valid patch mappings and successful `.hfapatch.json` export.

Formal regression baseline remains:

`build/hfamap-v1.4.4-20260901 @ 7bd19ba08a647104d230a2da299bcdd232687abf`

## Completed milestone: 5 MB structure and selector bridge

- v1.9.29 established feature dictionaries, runtime-record arrays, stable descriptor selectors, and secret-wrapper behavior.
- v1.9.30 device-confirmed selector matching plus offset/patch-wrapper association; the inherited fixed decrypt locator was the remaining mapping failure.
- The independent WayOfKings-style iGMM path has already produced a valid patch package and remains a required regression path.

## v1.9.31 finding: Full Scan crash is upstream of decrypt

Both supplied 5 MB games crashed when `Auto Detect / Full Scan` was pressed. The common evidence is stronger than a decrypt hypothesis:

- each real menu target was discovered in window index 0;
- Full Scan continued into unrelated windows/targets;
- neither log reached `[AUTO-TRAVERSAL-END]` or `[AUTO-SCAN]`;
- one crashing game exposed `records=0`, so the generic decrypt path was not entered.

Historical review identified an unsafe legacy design: the v1.9.24 iGMM probe deep-traversed every custom target and could enumerate object ivars through UIKit/framework superclasses. This is not protected from `EXC_BAD_ACCESS` by Objective-C `@try/@catch`.

## Current milestone: v1.9.32 CrashSafeFullScan

Policy:

- Prefer semantic feature-array confirmation instead of deep arbitrary object-graph probing.
- Once a semantic 5 MB menu target is confirmed, set `gAutoMenuFound` and stop scanning later windows.
- Preserve iGMM feature-array registration when `{label,identifier,type}` validation succeeds.
- Stop feature-array and runtime-record ivar enumeration when superclass traversal reaches framework classes.
- Keep the historical deep iGMM probe inactive during Auto Detect.
- Preserve v1.9.31 generic decrypt logic byte-for-byte.
- Preserve both package exporters byte-for-byte.

## Build checkpoint

- Branch: `feature/hfamap-v1932-crash-safe-full-scan`.
- Base: v1.9.31 docs HEAD `4a4db8fbaff6f1a0decf715bc07b782c54022df0`.
- Build-tested code commit: `ac2f5419f975ce9f63d2ad59546fe7c9ec16383a`.
- CI run: `34790789928` — success.
- Artifact ID: `10328366811`.
- Binary: `HFAMapUniversal_v1.9.32_CrashSafeFullScan.dylib`.
- SHA256: `96c47b4509929bf03289b3329ed4399f13cfa78db7eb2ac7c75bfa8fd1fd8c0c`.
- v1.9.31 decrypt functions byte-identical: passed.
- Legacy/iGMM exporter byte-identity: passed.
- Crash-safe invariants and no-sample-hardcode checks: passed.
- v1.9.32 device validation: pending.

## Regression checkpoints

- Formal stable baseline: v1.4.4 exact branch/SHA above.
- Legacy runtime: v1.9.28 15 MB package export.
- Jailpatch structure: v1.9.29 runtime records/selectors.
- Jailpatch bridge: v1.9.30 descriptor + wrapper association.
- Full Scan regression evidence: v1.9.31 crashes on both supplied 5 MB games before traversal end.
- iGMM runtime/export: WayOfKings-style package export.
- Immediate build checkpoint: v1.9.32 build-tested commit above.

## Next task

First validate scan stability on both supplied 5 MB games. Open the original menu and press `Auto Detect / Full Scan` only; do not toggle a feature yet. Require:

`[AUTO-MENU-CANDIDATE]` → `[AUTO-TRAVERSAL-END]` → `[AUTO-SCAN]` with no crash.

Only after that succeeds, operate menu controls and resume generic decrypt validation:

`[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1` → `[MAP-DECRYPT] rc=0` → valid `[MAPPING]/[FULL-MAPPING]` → package export when available.
