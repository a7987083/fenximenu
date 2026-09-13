# HFAMap Roadmap

## Current phase

v1.9.28 GenericMenuResolver — device validation

## Goal

Build a framework-level resolver for the legacy iOSGods/AP menu family without relying on obfuscated class names, ivar names, game labels, or sample RVAs.

## v1.9.28 completed scope

- Detect the legacy AP/IGSecret family with `APPatchItem`, selector fingerprints, Objective-C ivar type encodings, and Mach-O cstring evidence.
- Enumerate and classify APPatchItem implementations (switch/button/slider/group/item).
- Observe live menu objects during UI traversal and control actions.
- Resolve action IMP image/RVA and patch-descriptor component types.
- Emit human-readable `Documents/HFAMap_Learn.log` plus machine-readable `Documents/HFAMap_MenuMap.jsonl`.
- Detect the newer jailpatch metadata family as `probe-only`; do not claim record/table resolution yet.
- Preserve v1.9.27 target-chain and existing package exporters.
- Compile, link, sign, hash-check, and publish the arm64 dylib as a GitHub Actions artifact.

## Build checkpoint

- CI run: `34781824064` — success.
- Build commit: `e2054a2196f6650e2a345ae90d46cd139daf40ba`.
- Binary SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`.
- Runtime/device validation: pending.

## Regression baseline

- Stable formal baseline: `build/hfamap-v1.4.4-20260901`.
- Immediate development baseline: `feature/hfamap-v1927-target-chain-resolver` at `d7d00e8a97698e8c0545390903e082dd83676166`.

## Next task

Run v1.9.28 on one legacy AP/IGSecret (~15 MB family) sample and collect `HFAMap_Learn.log` + `HFAMap_MenuMap.jsonl`; then run it on one jailpatch-v2 (~5 MB family) sample to recover the runtime metadata/table layout for the next resolver revision.
