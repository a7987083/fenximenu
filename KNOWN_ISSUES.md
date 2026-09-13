# Known Issues

## v1.9.30 JailpatchSelectorResolver

### Selector bridge is not yet device-confirmed

Status: open / current validation target.

v1.9.29 device logs and cross-sample static metadata establish a stable descriptor selector/property fingerprint for the runtime-record style ~5 MB family. v1.9.30 bridges that fingerprint into the existing offset/patch mapping pipeline, but the new bridge itself has not yet been run on-device. CI success must not be reported as runtime mapping success.

### Patch-data candidate inference requires uniqueness

Status: intentionally conservative.

The descriptor exposes `offset` and `signature` getters plus additional secret-wrapper objects. v1.9.30 excludes the getter-resolved `offset` and `signature` wrappers, then registers patch data only when exactly one other object implementing `secret` remains. If zero or multiple candidates remain, the resolver reports evidence-only instead of guessing. Device evidence may require a stronger generic discriminator in a later revision.

### Important jailpatch object ivars use stripped type metadata

Status: understood / handled.

Relevant object ivars can be declared as `@"?"`; therefore class-name/type-encoding matching is not considered a stable discriminator. v1.9.30 relies on selector semantics, live object behavior, and the `secret` interface instead.

### Two ~5 MB menu paths exist in the supplied evidence

Status: understood / regression requirement.

One supplied sample exposes populated per-feature runtime-record arrays and is the target of the new selector resolver. Another supplied sample reached a successful `.hfapatch.json` export through the existing iGMM implementation/target-chain path even though its profiler capture did not expose populated runtime-record arrays. The selector resolver must augment, not replace, the existing iGMM path.

### v1.9.30 has not been runtime-regression-tested on ~15 MB

Status: open / low priority.

CI verifies that previous exporter functions remain byte-identical and the legacy resolver/mapping strings remain present. The ~15 MB architecture was runtime-confirmed under v1.9.28, but v1.9.30 itself has not been re-injected into that target, so a v1.9.30-on-15MB runtime regression must not be claimed.

### Menu visibility remains required for live runtime records

Status: design limitation.

Open the original menu before `Auto Detect / Full Scan`, then operate visible controls. Class-level evidence can exist earlier, but populated feature arrays, runtime records, state changes, and mapping hooks require live objects.

### Profiling logs remain intentionally verbose

Status: monitored.

The v1.9.29 structural profiler is retained beside the v1.9.30 resolver so failed/ambiguous bridges still produce enough evidence to refine generic rules. `HFAMap_JailpatchMap.jsonl` and `HFAMap_Learn.log` can therefore be large during this development phase.

### CI delivery is artifact-only

Status: resolved / intentional.

The repository Actions token has read-only Contents permission. Verified builds are uploaded as GitHub Actions artifacts; the workflow does not attempt to push binaries back into the source branch.
