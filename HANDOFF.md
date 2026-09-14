# HFAMap Handoff

## Current branch

`feature/hfamap-v19361-json-export`

## Current direction

HFAMapUniversal is again a **parser/exporter only**. The runtime-consumer/Dobby merge from v1.9.37 and v1.9.37.1 is retired from the product direction after both builds crashed immediately on device injection.

The parser baseline is the previously validated v1.9.36 ArchitectureTruth commit `75f94da37221343b6839465ad365ddec2679e63a`. New JSONExport layers must preserve the v1.9.36 constructor, `run_full_scan()` and `HFAMapPatchExecutionTrace.m` resolver core exactly.

## Current build: v1.9.36.3 JSONExport

- Branch: `feature/hfamap-v19361-json-export`.
- Build-tested commit: `67e291c640f6bc503860b414d65c21dd8af8e153`.
- GitHub Actions run: `34906163687` — success.
- Artifact: `HFAMapUniversal-v1.9.36.3-JSONExport` (ID `10372078251`).
- Artifact digest: `sha256:f9a3da845862e535dbad8007b1b243fcb87db3de37adf1ee69cc2b275514f3ed`.
- Binary: `HFAMapUniversal_v1.9.36.3_JSONExport.dylib`.
- Architecture: arm64 Mach-O dylib, NOUNDEFS.
- Size: `192432` bytes.
- SHA256: `5078c75833b246067ec3b8c3342db62c06ef80d1fa890363769290549239a546`.

## Device evidence

### v1.9.36.1 WayOfKings

Device archive confirmed:

- injection did not crash;
- HFA parser/scan completed;
- `com.hfa.igmm.runtime/v1` was generated;
- normalized `com.hfa.menu.analysis/v1` was generated;
- four menu features were exported.

Observed controls:

- `Damage Multiplier`: `modtext` -> `number`, default `1`;
- `Defence Multiplier`: `modtext` -> `number`, default `1`;
- `God Mode`: `customSwitch` -> `toggle`;
- `Debug Menu`: source type `kTypeButton`; v1.9.36.1 incorrectly normalized this to `unknown`.

Observed implementation evidence remains diagnostic only:

- Damage/Defence/God share handler evidence around `libpathofkings.dylib + 0x4128`, with trampoline evidence and target resolution toward `UnityFramework + 0x3BF6D94`;
- Debug Menu has block evidence at `libpathofkings.dylib + 0x66B0`, nested handler `+0x66C4`, resolving to `UnityFramework + 0x3DEC9A0`.

## v1.9.36.2

Adds the proven control normalization `kTypeButton -> button`. CI run `34904404292` passed. Device validation was superseded by v1.9.36.3.

## v1.9.36.3

Keeps source evidence intact but adds two analysis-layer improvements:

1. `normalizedExecutionPrimitive`: for an observed `buttonBlock`, the normalized analysis reports `runtimeAction` while the raw source `executionPrimitive` remains untouched.
2. `targetIdentities`: every referenced Mach-O image is resolved read-only and annotated with UUID, cputype/cpusubtype, architecture, filetype, preferred `__TEXT` VM address and cryptid.

No runtime executor, Dobby, hook takeover, command polling or extra constructor is present.

## Output contract

Normal scan outputs may include:

- `HFAMap_Learn.log`
- `HFAMap_MenuMap.jsonl`
- `HFAMap_JailpatchMap.jsonl`
- canonical `*.hfapatch.json` only when a true static byte-patch contract is proven
- `*.hfapatch.identity.json` when canonical target identity exists
- `*.hfamap.igmm.json` for iGMM runtime diagnostics
- `*.hfamap.analysis.json` for normalized analysis-only menu description

The normalized analysis schema is `com.hfa.menu.analysis/v1` and must keep `analysisOnly=true`.

## Next device test

Inject `HFAMapUniversal_v1.9.36.3_JSONExport.dylib` into WayOfKings and run the same Full Scan. Require:

1. no injection crash;
2. Full Scan completes;
3. `Debug Menu` exports `control.kind = button`;
4. `Debug Menu` exports raw source primitive plus `normalizedExecutionPrimitive = runtimeAction`;
5. `targetIdentities` resolves `libpathofkings.dylib` and `UnityFramework`;
6. UnityFramework identity matches the known target build evidence;
7. no playback/runtime execution behavior is introduced.

After this, regression-test the canonical static-patch family and then the legacy ~15 MB family with the same parser-only build.

## Verification discipline

- v1.9.36 parser baseline: frozen/reference baseline.
- v1.9.36.1 WayOfKings device startup: passed.
- v1.9.36.1 WayOfKings Full Scan: passed.
- v1.9.36.1 normalized analysis export: passed.
- v1.9.36.2 CI: passed.
- v1.9.36.3 compile/link/sign: passed.
- v1.9.36.3 CI: passed on run `34906163687`.
- v1.9.36.3 artifact re-hash: passed.
- v1.9.36.3 device validation: pending.
- v1.9.37/v1.9.37.1 runtime-merge device startup: failed / retired from parser mainline.
- project final closure: no.
