# Known Issues

## v1.9.28 GenericMenuResolver

### Jailpatch-v2 record layout is not resolved

Status: open / expected.

The ~5 MB family is detected by metadata/runtime-table marker evidence, but v1.9.28 deliberately reports it as `probe-only`. A device log is required before defining record offsets or table semantics.

### Device behavior is not yet verified

Status: open.

The implementation has compiled, linked, signed, passed CI invariants, and produced a verified arm64 dylib in run `34781824064`, but it has not yet been injected on a device. CI success must not be reported as runtime success.

### APPatchItem live instances depend on menu traversal/action visibility

Status: design limitation.

Class-level fingerprints are discoverable without opening the menu, but live `identifier`, state, nested descriptor pointers, and action IMPs require the corresponding objects/controls to exist and be traversed or acted on. Open the target menu before running Full Scan.

### Runtime cstring scan cost

Status: monitored.

Architecture detection scans non-system Mach-O `__cstring` sections when a manual generic rescan runs. It is intentionally not executed every 0.5-second UI timer tick.

### CI branch publishing uses artifact-only delivery

Status: resolved / intentional.

The repository Actions token exposes read-only Contents permission. The first v1.9.28 run compiled successfully but could not push the dylib back to the branch. The workflow now verifies and uploads the binary as a GitHub Actions artifact instead; run `34781824064` completed successfully. Do not reintroduce bot `git push` unless repository workflow permissions are explicitly changed.
