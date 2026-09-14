# Known Issues

## v1.9.33 OriginalByteResolver

### Runtime-record 5 MB package aggregation gap

Status: resolved on the supplied runtime-record sample.

v1.9.32 produced 8/8 valid mappings but exported only one patch because seven mappings lacked trusted original bytes. v1.9.33 device logs now show eight `PACKAGE-ORIGINAL ... source=vm-read status=ok` records. The generated package contains exactly 3 features / 8 patches with complete target, offset, original, and enabled fields.

### Crash-safe Full Scan on the supplied 5 MB games

Status: resolved for the tested games.

Both games reach semantic menu confirmation, `AUTO-TRAVERSAL-END`, and `AUTO-SCAN` without reproducing the v1.9.31 crash. The historical deep `igmm_probe_target(o)` remains inactive in Auto Detect and framework-superclass ivar traversal remains bounded.

### Generic 5 MB decrypt resolution

Status: resolved for the tested runtime-record sample.

The image-local `__TEXT,__text` fingerprint resolver returns `matches=1`, and live decrypt calls return `rc=0`. Eight full mappings are valid.

### Original-byte fallback branches

Status: open / not runtime-exercised.

v1.9.33 includes readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks after the primary `vm_read` path. CI verifies these branches compile and satisfy invariants, but the current device test recovered all eight originals through `vm-read`; therefore the fallback branches must not yet be described as runtime-confirmed.

### WayOfKings iGMM features have empty static patch arrays

Status: expected design, not a bug.

The iGMM exporter represents these four features as runtime definitions with implementation metadata. `patches=[]` is intentional for this backend and remains valid under v1.9.33.

### v1.9.33 has not been runtime-regression-tested on ~15 MB

Status: open / low priority.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28 with 12 valid mappings and package export. CI preserves the legacy path through v1.9.33, but the current v1.9.33 binary itself has not been re-injected into a 15 MB target.

### Generalization beyond the two supplied 5 MB samples

Status: open / future validation.

The current selector/decrypt/original-byte strategy is runtime-confirmed on the supplied runtime-record sample and the independent iGMM sample. Additional 5 MB binaries are still needed before claiming universal coverage across all Jailpatch generations.

### CI delivery

Status: intentional.

Verified binaries are distributed through GitHub Actions artifacts. The v1.9.33 build checkpoint is run `34799869649`, artifact `10330589684`, SHA256 `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.
