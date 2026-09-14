# Known Issues

## v1.9.34 CanonicalTruthGate

### v1.9.34 has not yet been device-tested

Status: open / primary validation gate.

The source is committed, CI replay/regression/invariant checks pass, the arm64 dylib is compiled/signed, and the artifact hash is independently verified. Do not claim runtime behavior for the new canonical gate, identity sidecar, or iGMM diagnostic-only export until device logs/files are supplied.

### iGMM runtime features are not canonical static patches

Status: intentionally unresolved, not silently converted.

Static analysis of the supplied iGMM target/menu pair confirms that multiple user-visible features can share native-hook infrastructure and use runtime numeric/state decisions. A fixed `target/offset/original/enabled` tuple is therefore not established merely because a hook target address is known.

v1.9.34 stops writing unresolved iGMM runtime-definition data as `com.hfa.patch/v1`. It emits `com.hfa.igmm.runtime/v1` diagnostics instead. A later version may promote an individual feature only if a real portable static equivalent is demonstrated.

### Stale v1.9.33 package files can confuse device validation

Status: test-environment hazard.

Before testing v1.9.34, delete or move old generated `.hfapatch.json`, `.hfapatch.identity.json`, and `.hfamap.igmm.json` files. Otherwise an old iGMM `.hfapatch.json` can be mistaken for new output even though v1.9.34 no longer creates one through the iGMM fallback.

### Binary identity is required for byte-level comparisons

Status: addressed by sidecar, device verification pending.

Offset similarity alone does not prove identical machine bytes across builds/slices. In particular, arm64 and arm64e can preserve similar function layout while differing in PAC-related instructions and original bytes.

v1.9.34 writes canonical-target UUID, cputype/cpusubtype, architecture, preferred `__TEXT` VM address, slide and cryptid to `*.hfapatch.identity.json`. The sidecar must be checked before cross-file byte validation.

### Canonical offset semantics must stay consistent

Status: defined / device verification pending.

The canonical offset field is a Mach-O preferred VM address. It is not a slid runtime address and not a file offset. Main executables can legitimately use `0x100...` preferred addresses while frameworks/dylibs may use lower values. Consumers must apply the image slide exactly once.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks are preserved and CI-verified. Previous runtime testing recovered all observed originals through `vm-read`, so the fallback branches are still not device-confirmed.

### v1.9.34 has not been runtime-regression-tested on ~15 MB

Status: open.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28. CI preserves the canonical writer path, but the v1.9.34 binary itself has not yet been injected into the 15 MB target.

### Generalization beyond supplied samples

Status: open / future validation.

The current architecture is grounded in one runtime-record 5 MB sample, one iGMM/native-hook 5 MB sample, and the legacy 15 MB family. Additional menu generations are still needed before claiming universal Jailpatch coverage.

### CI delivery

Status: intentional.

Verified binary: `HFAMapUniversal_v1.9.34_CanonicalTruthGate.dylib`, run `34824481536`, artifact `10339925211`, SHA256 `98d5643e1c72b049e647bd58fcf861ef1012a6efbf406fbb71fec7e36673863c`.
