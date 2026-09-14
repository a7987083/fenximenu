# Known Issues

## v1.9.33 OriginalByteResolver

### 15 MB and 5 MB JSON are not yet proven to share one canonical contract

Status: open / current project blocker.

The 5 MB runtime paths are device-confirmed, but their exported JSON representations are not yet verified as structurally and semantically equivalent to the formal 15 MB output.

Current 5 MB outputs include two different representations:

- runtime-record backend: static patch features with `target`, `offset`, `original`, and `enabled`;
- iGMM backend: runtime-definition features with `runtime/config/backend` metadata and empty static `patches` arrays.

Therefore "5 MB runtime chain complete" must not be conflated with "project export format complete". The canonical 15 MB package must be used as the compatibility target and explicitly diffed against both 5 MB forms before declaring closure.

### Runtime-record 5 MB package aggregation gap

Status: resolved on the supplied runtime-record sample.

v1.9.32 produced 8/8 valid mappings but exported only one patch because seven mappings lacked trusted original bytes. v1.9.33 device logs show eight `PACKAGE-ORIGINAL ... source=vm-read status=ok` records and a generated package with 3 features / 8 static patches.

This resolves only the internal runtime-record package completeness issue; it does not establish parity with the 15 MB canonical JSON.

### Crash-safe Full Scan on the supplied 5 MB games

Status: resolved for the tested games.

Both games reach semantic menu confirmation, `AUTO-TRAVERSAL-END`, and `AUTO-SCAN` without reproducing the v1.9.31 crash.

### Generic 5 MB decrypt resolution

Status: resolved for the tested runtime-record sample.

The image-local `__TEXT,__text` fingerprint resolver returns `matches=1`, live decrypt calls return `rc=0`, and eight full mappings are valid.

### Original-byte fallback branches

Status: open / not runtime-exercised.

The readable-memory `memcpy` and cryptid-aware Mach-O file fallbacks compile and pass CI invariants, but the current device test recovered all eight originals through `vm-read`.

### WayOfKings iGMM features have empty static patch arrays

Status: representation mismatch / requires unified-contract decision.

This is intentional for the current iGMM runtime-definition backend, but whether that representation is acceptable in the final 15 MB-compatible package contract is still unresolved. Do not label it "not a bug" at project level until the canonical cross-family schema is defined.

### v1.9.33 has not been runtime-regression-tested on ~15 MB

Status: open.

The legacy AP/IGSecret family remains runtime-confirmed under v1.9.28. The current v1.9.33 binary itself has not been re-injected into a 15 MB target.

### Generalization beyond the two supplied 5 MB samples

Status: open / future validation.

The current selector/decrypt/original-byte strategy is confirmed on the supplied runtime-record sample and the independent iGMM sample. Additional binaries are still needed before claiming universal Jailpatch coverage.

### CI delivery

Status: intentional.

Verified binaries are distributed through GitHub Actions artifacts. The v1.9.33 build checkpoint is run `34799869649`, artifact `10330589684`, SHA256 `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.
