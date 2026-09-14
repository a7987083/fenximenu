# HFAMap Roadmap

## Current phase

v1.9.34 CanonicalTruthGate — compiled / CI passed / awaiting device validation

## Completed foundations

- Legacy ~15 MB static patch path remains runtime-confirmed under v1.9.28.
- 5 MB runtime-record discovery/decrypt/mapping is runtime-confirmed through v1.9.33.
- 5 MB iGMM semantic menu/runtime-implementation discovery is runtime-confirmed through v1.9.33.
- The canonical consumer contract is now explicitly the 15 MB-style `com.hfa.patch/v1` static package.

## Why the next milestone changed

Static analysis of the two supplied 5 MB target/menu pairs showed that the menu framework family is shared but the execution primitives are not:

- runtime-record features resolve to concrete static byte patch points;
- iGMM features can share native-hook infrastructure and use dynamic numeric values or runtime state.

Therefore cross-family closure cannot be achieved by copying iGMM runtime metadata into an empty `patches` array and still calling the result `com.hfa.patch/v1`.

## Current milestone: v1.9.34 CanonicalTruthGate

Policy:

- Only true static patches can produce `.hfapatch.json`.
- Formal feature/patch keys must match the canonical 15 MB contract exactly.
- Canonical offsets are Mach-O preferred VM addresses.
- Binary byte evidence must be tied to UUID + CPU subtype/build identity.
- iGMM runtime primitives remain evidence-rich diagnostics until a portable static equivalent is actually proven.

Implementation:

- strict `HFACanonical34Validate` preflight;
- target identity sidecar `com.hfa.patch.identity/v1`;
- iGMM diagnostic schema `com.hfa.igmm.runtime/v1`;
- execution primitive classification (`numericRuntimeModifier`, `nativeHook`, `blockHandler`, `runtimeBoolean`, `runtimeAction`, `unresolved`);
- no new canonical-looking `.hfapatch.json` from unresolved iGMM features.

## Build checkpoint

- Branch: `feature/hfamap-v1934-unified-canonical-exporter`.
- Base commit: `59ceb4bfa28b016b1bc52acea1613527c06aa231`.
- Build-tested code commit: `5c7edc0a70f571813c8b2882dd260beae3c0db6c`.
- CI run: `34824481536` — success.
- Artifact ID: `10339925211`.
- Binary: `HFAMapUniversal_v1.9.34_CanonicalTruthGate.dylib`.
- SHA256: `98d5643e1c72b049e647bd58fcf861ef1012a6efbf406fbb71fec7e36673863c`.
- v1.9.34 device validation: pending.

## Next validation

First clear stale generated output files.

Runtime-record 5 MB must reproduce the proven scan/decrypt/mapping chain and additionally show canonical validation plus target identity, ending in the same 3-feature / 8-static-patch package.

iGMM 5 MB must emit execution-primitive diagnostics and a `.hfamap.igmm.json` report, while producing no new `.hfapatch.json` through the iGMM fallback.

After both pass, the next branch can investigate whether any iGMM runtime primitive has a genuinely portable static equivalent. Features that do not must remain non-canonical rather than being represented by fabricated bytes.

A v1.9.34-on-15MB device regression is still required before promoting the current binary itself as the cross-family runtime candidate.
