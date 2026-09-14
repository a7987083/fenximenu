# Development Changelog

## v1.9.36.3 JSONExport — compiled / CI passed / awaiting device validation

Branch: `feature/hfamap-v19361-json-export`
Parser baseline: `v1.9.36 ArchitectureTruth @ 75f94da37221343b6839465ad365ddec2679e63a`
Build-tested commit: `67e291c640f6bc503860b414d65c21dd8af8e153`
Successful CI run: `34906163687`
Artifact ID: `10372078251`
Binary: `HFAMapUniversal_v1.9.36.3_JSONExport.dylib`
Binary size: `192432` bytes
Binary SHA256: `5078c75833b246067ec3b8c3342db62c06ef80d1fa890363769290549239a546`
Artifact digest: `sha256:f9a3da845862e535dbad8007b1b243fcb87db3de37adf1ee69cc2b275514f3ed`

### Direction correction

The v1.9.37 and v1.9.37.1 experiments merged the separate playback/runtime consumer and Dobby backend into HFAMapUniversal. Both builds crashed immediately when injected on device. The exact crash instruction was not captured, but the architecture decision was reversed: HFAMapUniversal is again a parser/exporter only.

v1.9.36 is the frozen parser baseline. JSONExport changes are layered after `run_full_scan()` and CI requires the baseline constructor, scan body and `HFAMapPatchExecutionTrace.m` resolver core to remain unchanged.

### v1.9.36.1 device result

WayOfKings device archive confirmed:

- injection did not crash;
- Full Scan completed;
- `com.hfa.igmm.runtime/v1` output was written;
- `com.hfa.menu.analysis/v1` output was written;
- four menu features were exported.

Observed control mappings:

- Damage Multiplier: `modtext -> number`, default `1`;
- Defence Multiplier: `modtext -> number`, default `1`;
- God Mode: `customSwitch -> toggle`;
- Debug Menu: source type `kTypeButton`, but v1.9.36.1 normalized it as `unknown`.

### v1.9.36.2

Fixed the proven alias `kTypeButton -> button` in the normalized analysis layer. No resolver-core change. CI run `34904404292` passed.

### v1.9.36.3

Adds evidence-preserving normalization and target identity:

- raw source `executionPrimitive` remains unchanged;
- new `normalizedExecutionPrimitive` uses control/runtime structure to express the analysis-layer interpretation;
- the observed `buttonBlock` shape normalizes to `runtimeAction` while retaining the original raw primitive;
- referenced Mach-O images are collected recursively from canonical/iGMM evidence;
- each loaded image is annotated read-only with UUID, cputype/cpusubtype, architecture, filetype, preferred `__TEXT` VM address and cryptid;
- normalized schema remains `com.hfa.menu.analysis/v1` with `analysisOnly=true`;
- no Dobby, playback consumer, runtime takeover, command polling or extra constructor.

### Verification

- baseline constructor preserved: PASS;
- baseline `run_full_scan()` preserved: PASS;
- baseline trace/resolver core preserved: PASS;
- WayOfKings observed control fixture: PASS;
- analysis-only invariants: PASS;
- arm64 compile/link/strip/sign: PASS;
- no Dobby symbols in final binary: PASS;
- artifact upload: PASS;
- artifact independently downloaded/re-hashed: PASS;
- v1.9.36.3 device validation: PENDING.

## v1.9.36.2 JSONExport — CI passed

- Added exact normalization for the observed iGMM type `kTypeButton`.
- Kept the v1.9.36 startup and resolver core unchanged.
- CI run: `34904404292`.

## v1.9.36.1 JSONExport — device tested on WayOfKings

- Rebased work onto the stable v1.9.36 parser instead of the runtime-consumer merge.
- Added a serializer that runs only after Full Scan and consumes existing canonical/iGMM JSON outputs.
- Generated `*.hfamap.analysis.json` with `analysisOnly=true`.
- Device archive proved stable injection, completed scan and normalized analysis export.
- Device evidence exposed the `kTypeButton` normalization gap fixed in v1.9.36.2.

## Retired experiment: v1.9.37 / v1.9.37.1

- Combined parser, dynamic JSON UI, playback consumer, Dobby and runtime takeover into one dylib.
- CI/build succeeded, but both device injections crashed at startup.
- SafeStart delayed the consumer startup but still crashed, so the combined architecture was abandoned as the HFAMapUniversal mainline.

## Earlier parser checkpoints

- v1.9.36: ArchitectureTruth parser baseline; target architecture derived from canonical targets.
- v1.9.35: MainImageTruth.
- v1.9.34: CanonicalTruthGate; iGMM diagnostics separated from static canonical patches.
- v1.9.33: multi-source original-byte resolver.
- v1.9.32: crash-safe Full Scan.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
