# Known Issues

## v1.9.29 JailpatchRuntimeProfiler

### Jailpatch-v2 table semantics are not yet resolved

Status: open / expected.

The v1.9.28 device log proved that the ~5 MB family exposes a three-feature definition array and per-feature custom runtime-record collections. v1.9.29 now profiles those records generically, but the semantic roles of the nested custom objects and primitive fields still require one v1.9.29 device capture before offsets/table layout can be promoted to resolver logic.

### Important object ivars use stripped type metadata

Status: understood / handled by profiler.

The 5 MB sample exposes relevant nested object ivars with Objective-C type encoding `@"?"`. This is why the v1.9.28 `IGSecret*` type-name descriptor fingerprint reported zero descriptors for this family. v1.9.29 enumerates object values, concrete runtime classes, nested graphs, methods/IMP RVAs, and scalar bytes without requiring a declared class type.

### v1.9.29 is not yet device-tested

Status: open.

Run `34783065857` compiled, linked, signed, invariant-tested, hash-verified, and uploaded the v1.9.29 arm64 dylib. The new profiler still requires a real 5 MB runtime capture before it can be called runtime-confirmed.

### Legacy AP / ~15 MB runtime status

Status: resolved for the tested sample.

The v1.9.28 device capture successfully produced 12 patch mappings and a `.hfapatch.json` package with real target RVAs and bytes. This path is runtime-confirmed for the tested architecture. v1.9.29 preserves the v1.9.28 behavior in CI, but a v1.9.29-on-15MB device rerun has not been performed and should not be claimed as a runtime regression test.

### Live instances still depend on menu visibility

Status: design limitation.

Open the original menu before `Auto Detect / Full Scan`. v1.9.29 specifically avoids marking a target as already profiled until its populated feature array is present, so observing the controller too early should no longer suppress the later scan.

### Runtime profiling volume

Status: monitored.

The jailpatch profiler enumerates bounded object graphs, methods, ivars, scalar bytes, and block invoke metadata. It runs when relevant menu targets are observed, not continuously on every UI timer tick. Logs may be significantly larger than v1.9.28; this is intentional for the profiling stage.

### CI delivery remains artifact-only

Status: resolved / intentional.

The repository Actions token has read-only Contents permission. Builds are verified and uploaded as GitHub Actions artifacts rather than pushed back to the branch by the workflow.
