# Development Status

## HFAMapUniversal v1.9.36.3 JSONExport

Current branch: `feature/hfamap-v19361-json-export`
Current build-tested commit: `67e291c640f6bc503860b414d65c21dd8af8e153`
Current docs head: updated after the build commit
CI run: `34906163687` — PASS
Artifact: `HFAMapUniversal-v1.9.36.3-JSONExport` (ID `10372078251`)
Binary SHA256: `5078c75833b246067ec3b8c3342db62c06ef80d1fa890363769290549239a546`

### Development states

- 已修改: yes
- 已提交: yes
- 已编译: yes
- CI通过: yes
- 真机运行: pending for v1.9.36.3
- 回归验证: pending for v1.9.36.3

### Device evidence already confirmed

v1.9.36.1 on WayOfKings:

- injection stable;
- Full Scan complete;
- iGMM diagnostic JSON generated;
- normalized analysis JSON generated;
- 4 features exported.

### v1.9.36.3 purpose

Pure parser/exporter only. No playback engine, no Dobby, no runtime takeover and no extra constructor.

Adds:

- `kTypeButton -> button` normalization inherited from v1.9.36.2;
- `normalizedExecutionPrimitive` while preserving raw source evidence;
- read-only `targetIdentities` for referenced Mach-O images.

### Next required evidence

Run WayOfKings with v1.9.36.3 and provide the regenerated `.hfamap.analysis.json`, `.hfamap.igmm.json` and `HFAMap_Learn.log`. Required checks:

- no startup crash;
- Debug Menu = `control.kind: button`;
- Debug Menu normalized primitive = `runtimeAction`;
- target identities resolve `libpathofkings.dylib` and `UnityFramework`;
- UnityFramework identity matches the expected target build;
- no behavior execution is introduced.

After WayOfKings passes, regression-test the runtime-record/static family and legacy ~15 MB family.
