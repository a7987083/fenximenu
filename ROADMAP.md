# HFAMap Roadmap

## Current phase

v1.9.36.3 JSONExport — pure parser/exporter, CI passed, awaiting device validation.

## Product direction

HFAMapUniversal stays focused on:

`original menu -> parser -> evidence -> normalized JSON`

The runtime execution engine is not part of the HFAMapUniversal parser mainline. v1.9.37/v1.9.37.1 demonstrated that merging the playback consumer/Dobby directly into the parser created device-startup regressions and was reverted.

## Stable foundation

- Frozen parser baseline: v1.9.36 ArchitectureTruth, commit `75f94da37221343b6839465ad365ddec2679e63a`.
- Preserve constructor, `run_full_scan()` and resolver/decrypt/original-byte core exactly.
- Canonical static patches remain `com.hfa.patch/v1` with preferred Mach-O VM addresses.
- iGMM runtime behavior remains diagnostic-only under `com.hfa.igmm.runtime/v1`.
- Normalized cross-family analysis uses `com.hfa.menu.analysis/v1` with `analysisOnly=true`.

## Device-confirmed checkpoint: v1.9.36.1

WayOfKings device archive confirmed:

- injection stability;
- Full Scan completion;
- four iGMM feature records;
- iGMM diagnostic JSON generation;
- normalized analysis JSON generation.

One normalization defect was exposed: the raw source type `kTypeButton` for Debug Menu was not recognized and became `unknown`.

## v1.9.36.2

Completed:

- exact observed alias `kTypeButton -> button`;
- CI run `34904404292` passed;
- no parser-core changes.

## Current milestone: v1.9.36.3

Completed in code/CI:

- preserve raw source `executionPrimitive` evidence;
- add `normalizedExecutionPrimitive` so `buttonBlock` can be represented as `runtimeAction` without rewriting source diagnostics;
- collect referenced image names from canonical/iGMM analysis trees;
- resolve each loaded image read-only;
- export target identity fields: UUID, cputype, cpusubtype, architecture, filetype, preferred `__TEXT` VM address and cryptid;
- no new constructor;
- no Dobby;
- no HFAPatchConsumer;
- no command polling;
- no runtime takeover.

Build checkpoint:

- branch: `feature/hfamap-v19361-json-export`;
- build-tested commit: `67e291c640f6bc503860b414d65c21dd8af8e153`;
- CI run: `34906163687` — success;
- artifact ID: `10372078251`;
- artifact digest: `sha256:f9a3da845862e535dbad8007b1b243fcb87db3de37adf1ee69cc2b275514f3ed`;
- binary: `HFAMapUniversal_v1.9.36.3_JSONExport.dylib`;
- size: `192432` bytes;
- SHA256: `5078c75833b246067ec3b8c3342db62c06ef80d1fa890363769290549239a546`.

## Next validation: WayOfKings

Inject v1.9.36.3 and run the same Full Scan. Require:

1. no crash at injection/startup;
2. HFA floating window appears;
3. Full Scan completes;
4. `.hfamap.igmm.json` is regenerated;
5. `.hfamap.analysis.json` is regenerated;
6. `Debug Menu` has `control.kind = button`;
7. raw source primitive remains visible;
8. `normalizedExecutionPrimitive = runtimeAction` for the observed button block;
9. `targetIdentities` resolves both `libpathofkings.dylib` and `UnityFramework`;
10. UnityFramework UUID/architecture/preferred-`__TEXT` evidence matches the supplied target binary.

## Following validation

After WayOfKings passes:

1. regression-test the runtime-record/static 5 MB family and confirm canonical byte-patch export is unchanged;
2. regression-test the legacy ~15 MB family;
3. compare normalized analysis output across all three families;
4. only then consider the parser/exporter line a cross-family candidate.

## Deferred work

Execution of generated JSON remains a separate project/module. Do not merge it back into HFAMapUniversal until there is a separately device-validated integration design with startup isolation and explicit user approval.
