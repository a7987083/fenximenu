# HFAMap Handoff

## Current branch

`feature/hfamap-v1934-unified-canonical-exporter`

## Current build

- Base: `feature/hfamap-v1933-original-byte-resolver @ 59ceb4bfa28b016b1bc52acea1613527c06aa231`.
- Build-tested code commit: `5c7edc0a70f571813c8b2882dd260beae3c0db6c`.
- GitHub Actions run: `34824481536` — success.
- Artifact: `HFAMapUniversal-v1.9.34-CanonicalTruthGate` (ID `10339925211`).
- Binary: `HFAMapUniversal_v1.9.34_CanonicalTruthGate.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175648` bytes.
- SHA256: `98d5643e1c72b049e647bd58fcf861ef1012a6efbf406fbb71fec7e36673863c`.

## Canonical contract

The formal `.hfapatch.json` contract is the static 15 MB shape:

`schema/name/package/targets/features`
→ feature `id/title/group/defaultEnabled/patches`
→ patch `target/offset/original/enabled`.

Canonical offsets are Mach-O preferred VM addresses. They are not runtime slid addresses and are not file offsets. A main executable can therefore legitimately use `0x100...` values while a framework/dylib can use lower preferred VMs.

## Confirmed historical runtime checkpoints

### Legacy AP / ~15 MB

v1.9.28 remains runtime-confirmed with 12 static mappings and successful canonical package export.

### Runtime-record / ~5 MB

v1.9.33 is runtime-confirmed for semantic menu discovery, selector descriptors, secret-wrapper association, generic decrypt, 8/8 valid mappings and a 3-feature / 8-static-patch package.

### iGMM / ~5 MB

v1.9.33 is runtime-confirmed for semantic menu discovery and runtime implementation discovery. Static analysis of the supplied menu/target pair shows the backend can use shared native hooks and dynamic numeric state; therefore its old runtime-definition JSON must not be treated as equivalent to a static canonical package.

## v1.9.34 behavior

### Static patch path

Before canonical export, `HFACanonical34Validate` requires exact target/feature/patch keys, nonempty patch arrays, valid `0x...` preferred-VM-address offsets, known targets, and same-length differing `original/enabled` bytes. A failure logs `[CANONICAL-EXPORT-SKIP]` instead of producing a misleading package.

A successful static package also writes `*.hfapatch.identity.json` with target UUID, CPU type/subtype, architecture, preferred `__TEXT` VM address, slide and cryptid. This sidecar exists to prevent cross-build or arm64/arm64e byte validation mistakes without changing the canonical `com.hfa.patch/v1` schema.

### iGMM path

`HFAWriteIGMMPackage` is retained as the internal call surface but now writes only diagnostic `*.hfamap.igmm.json` using `com.hfa.igmm.runtime/v1`. Each feature records an execution primitive and why it is not yet canonical. It does not create a new `.hfapatch.json` for unresolved runtime hooks/modifiers.

## Device validation protocol

Delete or move old generated `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files before each test so stale v1.9.33 output cannot be mistaken for v1.9.34 output.

Runtime-record 5 MB expected chain:

`AUTO-MENU-CANDIDATE`
→ `AUTO-TRAVERSAL-END`
→ `AUTO-SCAN`
→ decrypt `matches=1 / rc=0`
→ 8 valid mappings
→ `[CANONICAL-CHECK] status=pass`
→ `[TARGET-IDENTITY-EXPORT]`
→ canonical 3-feature / 8-patch `.hfapatch.json`.

The iGMM 5 MB expected chain:

`AUTO-MENU-CANDIDATE source=igmm-feature-array`
→ `AUTO-TRAVERSAL-END/AUTO-SCAN`
→ one `[IGMM-PRIMITIVE]` per feature
→ `[IGMM-RUNTIME-EXPORT]`
→ `*.hfamap.igmm.json`
→ no newly created `.hfapatch.json` from the iGMM fallback.

## Verification discipline

- v1.9.34 source modified/committed: yes.
- compiled/linked/signed: yes.
- CI regression/invariants: passed.
- artifact independently downloaded and re-hashed: passed.
- v1.9.34 device-tested: no.
- v1.9.34 15 MB runtime regression: no.
- portable static equivalents for iGMM native hooks/modtext: not established; do not invent them.
