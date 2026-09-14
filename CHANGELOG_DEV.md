# Development Changelog

## v1.9.34 CanonicalTruthGate — compiled / CI passed / awaiting device validation

Branch: `feature/hfamap-v1934-unified-canonical-exporter`
Base: `feature/hfamap-v1933-original-byte-resolver @ 59ceb4bfa28b016b1bc52acea1613527c06aa231`
Build-tested commit: `5c7edc0a70f571813c8b2882dd260beae3c0db6c`
Successful CI run: `34824481536`
Artifact ID: `10339925211`
Binary: `HFAMapUniversal_v1.9.34_CanonicalTruthGate.dylib`
Binary size: `175648` bytes
Binary SHA256: `98d5643e1c72b049e647bd58fcf861ef1012a6efbf406fbb71fec7e36673863c`

### Why v1.9.34 exists

The canonical 15 MB package establishes a strict static-patch contract: root `schema/name/package/targets/features`; feature `id/title/group/defaultEnabled/patches`; patch `target/offset/original/enabled`.

Static comparison of the two supplied ~5 MB menu families showed that they share the same Jailpatch selector/decrypt family but not the same execution primitive:

- runtime-record backend resolves to real static byte-patch points and can use the canonical contract;
- iGMM backend can implement numeric runtime modifiers, native hooks and block actions. Those are not equivalent to fixed static bytes merely because a runtime target can be identified.

Therefore v1.9.34 stops treating unresolved iGMM runtime definitions as `com.hfa.patch/v1` packages.

### Added in v1.9.34

- Strict canonical preflight before `.hfapatch.json` export.
  - Exact target keys: `image`.
  - Exact feature keys: `id/title/group/defaultEnabled/patches`.
  - Exact patch keys: `target/offset/original/enabled`.
  - Patch arrays must be nonempty.
  - Offsets use `preferred-mach-o-vmaddr` semantics and must be `0x...` hex.
  - `original` and `enabled` must be valid, same-length, differing hex strings.
  - Every patch target must exist in the target table.
- Binary-identity sidecar for canonical targets.
  - Records Mach-O UUID, CPU type/subtype, arm64 vs arm64e, preferred `__TEXT` VM address, ASLR slide and cryptid.
  - File: `*.hfapatch.identity.json` using schema `com.hfa.patch.identity/v1`.
- iGMM runtime-analysis export is now diagnostic-only.
  - Schema: `com.hfa.igmm.runtime/v1`.
  - File: `*.hfamap.igmm.json`.
  - Per-feature `executionPrimitive`, `canonicalEligible=false`, and `canonicalReason`.
  - Preserves runtime implementation/handler evidence.
  - Does not write a canonical-looking `.hfapatch.json` for unresolved runtime primitives.

### Preserved regressions

CI byte-compares and preserves the v1.9.32 crash-safe Full Scan, v1.9.31 secret decrypt functions, v1.9.33 original-byte readers, compact mapping writer and canonical patch writer. Sample-specific names/RVAs are deny-listed from the new implementation.

### Verification

- Historical patch-chain replay: passed.
- Proven runtime-path regression checks: passed.
- Canonical/static-vs-iGMM surface separation: passed.
- arm64 compile/link/sign: passed.
- Distributable SHA256 check: passed and independently re-hashed.
- v1.9.34 device validation: pending.

## Earlier checkpoints

- v1.9.33: runtime-record 5 MB reached 3 features / 8 static patches; iGMM runtime-definition export worked but was not the canonical 15 MB static contract.
- v1.9.32: fixed the common 5 MB Full Scan crash and confirmed generic decrypt + 8/8 mappings.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
