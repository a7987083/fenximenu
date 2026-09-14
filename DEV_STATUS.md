# Development Status

## HFAMapUniversal v1.9.36.4 JSONExport

Current branch: `feature/hfamap-v19361-json-export`
Current build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`
CI run: `34907671999` — PASS
Artifact: `HFAMapUniversal-v1.9.36.4-JSONExport` (ID `10372928333`)
Binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`

### Development states

- 已修改: yes
- 已提交: yes
- 已编译: yes
- CI通过: yes
- v1.9.36.3 真机运行: passed on WayOfKings
- v1.9.36.4 真机运行: pending
- cross-family 回归验证: pending

### Device evidence confirmed in v1.9.36.3

- injection stable;
- Full Scan complete;
- iGMM diagnostic JSON generated;
- normalized analysis JSON generated;
- 4 features exported;
- Debug Menu = `control.kind: button`;
- Debug Menu raw primitive preserved as `nativeHook`;
- Debug Menu normalized primitive = `runtimeAction`;
- `libpathofkings.dylib` identity resolved to UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`;
- `UnityFramework` identity resolved to UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`;
- both target images reported arm64, filetype 6, preferred `__TEXT` VM `0x0`, cryptid 0.

### v1.9.36.4 purpose

Pure parser/exporter only. No playback engine, no Dobby, no runtime takeover and no extra constructor.

Adds one analysis-layer field while preserving raw evidence:

- `normalizedCanonicalReason`;
- observed Debug Menu buttonBlock/runtimeAction -> `runtime-action-not-static-bytes`;
- raw `canonicalReason` remains unchanged.

### Next required evidence

Run WayOfKings with v1.9.36.4 and provide regenerated `.hfamap.analysis.json`, `.hfamap.igmm.json` and `HFAMap_Learn.log`. Required checks:

- no startup crash;
- all v1.9.36.3 mappings/identities unchanged;
- Debug Menu normalized primitive remains `runtimeAction`;
- Debug Menu `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- raw source primitive and raw canonical reason remain present.

After WayOfKings passes, regression-test the runtime-record/static family and legacy ~15 MB family.
