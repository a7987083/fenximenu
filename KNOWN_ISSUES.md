# Known Issues

## v1.9.33 OriginalByteResolver

### Runtime-record package is still incomplete under v1.9.32

Status: open / current v1.9.33 validation target.

The v1.9.32 runtime-record sample produced eight valid mappings across three features, and `HFAMap_Mapping.log` contains all eight. The exported `.hfapatch.json` contained only one feature/one patch because seven valid mappings logged `reason=identity-or-original-unavailable`.

This is an exporter-input problem, not a selector/decrypt/mapping problem.

### v1.9.33 original-byte fallback is compiled but not device-confirmed

Status: open.

v1.9.33 tries live `vm_read_overwrite`, readable direct memory, then on-disk Mach-O segment translation. CI verifies the implementation and preserves previous scan/decrypt/package-writer functions, but only device evidence can show which source succeeds for the seven previously skipped mappings.

Require `[PACKAGE-ORIGINAL]` evidence for every valid mapping before declaring the package path complete.

### On-disk original fallback refuses active FairPlay-encrypted ranges

Status: intentional safety behavior.

The file fallback parses `LC_ENCRYPTION_INFO_64`. If the requested file bytes overlap a range whose `cryptid` is active, the fallback returns unavailable rather than exporting encrypted bytes as an "original" instruction sequence.

If a future sample is FairPlay-encrypted and live memory cannot be read, a verified decrypted image/dump will be required instead of weakening this check.

### Live bytes may already equal the enabled patch

Status: handled conservatively.

If live memory returns bytes identical to the enabled patch, v1.9.33 attempts a trustworthy unencrypted file original. If that is unavailable, the existing package logic still skips the patch rather than inventing an original value.

### v1.9.32 Full Scan crash is resolved on both supplied 5 MB games

Status: device-confirmed resolved for the tested games.

Both v1.9.32 captures reached `[AUTO-MENU-CANDIDATE]`, `[AUTO-TRAVERSAL-END]`, and `[AUTO-SCAN]` without crashing. The historical deep iGMM Auto Detect probe remains inactive.

### Generic 5 MB decrypt resolution is runtime-confirmed on the tested runtime-record sample

Status: resolved for current architecture evidence.

v1.9.32 selected the image-local text fingerprint with `matches=1`; offset and patch-data decrypt calls returned `rc=0`; all eight full mappings were valid. Future binaries with zero or multiple fingerprint matches still fail closed.

### WayOfKings iGMM path remains a separate supported architecture path

Status: runtime-confirmed / regression requirement.

Under v1.9.32, WayOfKings completed crash-safe Full Scan and exported a four-feature iGMM package. v1.9.33 changes only ordinary patch original-byte recovery and must not regress this path.

### Patch-data candidate inference requires uniqueness

Status: intentionally conservative / confirmed for current runtime records.

Patch data is registered only when exactly one remaining `secret` wrapper exists after excluding offset/signature candidates. Ambiguous records remain evidence-only.

### Relevant Jailpatch ivars may use stripped type metadata

Status: understood / handled.

Discovery relies on stable selectors, live object behavior, and bounded runtime structure rather than randomized class/ivar names or declared object types.

### v1.9.33 has not been runtime-regression-tested on ~15 MB

Status: open / low priority.

The legacy 15 MB architecture remains runtime-confirmed under v1.9.28. CI preserves the legacy mapping/decrypt/export paths, but v1.9.33 itself has not been injected into the 15 MB sample.

### CI delivery remains artifact-only

Status: intentional.

Verified binaries are distributed through GitHub Actions artifacts because the workflow token has read-only Contents permission.
