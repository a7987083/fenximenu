# Known Issues

## v1.9.31 GenericSecretDecryptResolver

### Generic 5 MB decrypt resolution is not yet device-confirmed

Status: open / current validation target.

v1.9.30 device evidence confirms the selector descriptor and secret-wrapper association, but its inherited fixed decrypt locator failed. v1.9.31 replaces that locator with an image-local `__TEXT,__text` fingerprint scan. CI proves the implementation compiles and preserves prior paths; it does not prove that the scanned function decrypts the live 5 MB secret successfully. Require device evidence showing `[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1` followed by `[MAP-DECRYPT] rc=0` before marking this resolved.

### v1.9.30 fixed decrypt locator fails on runtime-record 5 MB

Status: understood / superseded by v1.9.31.

The v1.9.30 selector bridge itself is device-confirmed. It associated `offset` and the unique remaining patch-data secret-wrapper and reached the mature `[MAPPING]` path. The failure was the legacy assumption that the decrypt routine resides at `secret getter + 0xD00`. The tested 5 MB candidate at that location did not match HFAMap's established decrypt instruction fingerprint, so decrypted offset/patch data remained unavailable and mapping validity stayed false.

### Cross-sample decrypt fingerprint uniqueness is static evidence, not runtime proof

Status: understood.

Both supplied ~5 MB dylibs contain exactly one `__TEXT,__text` function matching the same three-instruction fingerprint used to validate the legacy decrypt routine. Observed decrypt RVAs are `0x2123D4` and `0x2129A4`; the observed getter-to-decrypt delta is `0x1204` in both files. v1.9.31 intentionally does not hardcode those RVAs or that delta. A future build must continue to reject ambiguous scans rather than selecting the nearest match.

### Patch-data candidate inference still requires uniqueness

Status: intentionally conservative / runtime-confirmed for the tested records.

The selector resolver excludes the getter-resolved `offset` and `signature` wrappers and registers patch data only when exactly one other object implementing `secret` remains. The v1.9.30 runtime capture satisfied this rule for the observed runtime records. New samples with zero or multiple remaining candidates will still fall back to evidence-only mode instead of guessing.

### Important jailpatch object ivars use stripped type metadata

Status: understood / handled.

Relevant object ivars can be declared as `@"?"`; class-name/type-encoding matching is therefore not considered a stable discriminator. The current resolver uses selector semantics, live object behavior, and the `secret` interface.

### Two ~5 MB menu paths remain supported

Status: understood / regression requirement.

One supplied sample uses populated per-feature runtime records and is handled by the selector/decrypt path. Another supplied sample has already generated a `.hfapatch.json` package through the pre-existing iGMM implementation/target-chain path. v1.9.31 augments the runtime-record path and must not replace or break the iGMM path.

### v1.9.31 has not been runtime-regression-tested on ~15 MB

Status: open / low priority.

The legacy AP/IGSecret architecture was runtime-confirmed under v1.9.28. v1.9.31 keeps the previously validated `getter + 0xD00` candidate as its first fast path and requires the same decrypt instruction fingerprint, while CI verifies previous exporters and mapping paths remain intact. However, v1.9.31 itself has not been re-injected into a 15 MB target, so runtime regression success must not be claimed yet.

### Menu visibility remains required for live runtime records

Status: design limitation.

Open the original menu before `Auto Detect / Full Scan`, then operate visible controls. Populated feature arrays, runtime records, state changes, and mapping hooks require live objects.

### Generic `__text` scan cost

Status: monitored.

When the legacy decrypt fast path fails, v1.9.31 scans the loaded image's `__TEXT,__text` section in 4-byte steps for a three-instruction fingerprint. The result is cached per image, so the full scan should occur once per relevant image rather than for every secret wrapper. Device logs should still be checked for startup or scan-time regressions.

### Profiling logs remain intentionally verbose

Status: monitored.

The structural profiler remains active beside the selector/decrypt resolver so any zero/ambiguous fingerprint or wrapper case retains enough evidence for the next revision. `HFAMap_JailpatchMap.jsonl` and `HFAMap_Learn.log` can be large during this development phase.

### CI delivery is artifact-only

Status: resolved / intentional.

The repository Actions token has read-only Contents permission. Verified builds are uploaded as GitHub Actions artifacts; the workflow does not attempt to push binaries back into the source branch.
