# HFAMap Roadmap

## Current phase

v1.9.28 GenericMenuResolver

## Goal

Build a framework-level resolver for the legacy iOSGods/AP menu family without relying on obfuscated class names, ivar names, game labels, or sample RVAs.

## v1.9.28 scope

- Detect the legacy AP/IGSecret family with `APPatchItem`, selector fingerprints, Objective-C ivar type encodings, and Mach-O cstring evidence.
- Enumerate and classify APPatchItem implementations (switch/button/slider/group/item).
- Observe live menu objects during UI traversal and control actions.
- Resolve action IMP image/RVA and patch-descriptor component types.
- Emit human-readable `Documents/HFAMap_Learn.log` plus machine-readable `Documents/HFAMap_MenuMap.jsonl`.
- Detect the newer jailpatch metadata family as `probe-only`; do not claim record/table resolution yet.
- Preserve v1.9.27 target-chain and existing package exporters.

## Regression baseline

- Stable formal baseline: `build/hfamap-v1.4.4-20260901`.
- Immediate development baseline: `feature/hfamap-v1927-target-chain-resolver` at `d7d00e8a97698e8c0545390903e082dd83676166`.

## Next task

Build v1.9.28 in GitHub Actions, fix all compiler/invariant failures, publish the dylib, then collect device logs from one legacy AP/IGSecret sample and one jailpatch sample.
