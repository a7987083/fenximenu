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
- v1.9.36.4 WayOfKings 真机运行: passed
- v1.9.36.4 WayOfKings 解析回归: passed
- runtime-record/static 5 MB 回归: pending
- legacy ~15 MB 回归: pending
- cross-family closure: pending

### v1.9.36.4 device evidence

Device archive `归档 6(1).zip` confirmed:

- injection stable;
- Full Scan complete;
- iGMM diagnostic JSON regenerated;
- normalized analysis JSON regenerated;
- 4 features exported;
- Debug Menu = `control.kind: button`;
- Debug Menu raw primitive remains `nativeHook`;
- Debug Menu normalized primitive = `runtimeAction`;
- Debug Menu raw canonical reason remains `runtime-hook-requires-portable-equivalent`;
- Debug Menu normalized canonical reason = `runtime-action-not-static-bytes`;
- target identities resolve `libpathofkings.dylib` and `UnityFramework` with the expected UUID/arm64/cryptid evidence;
- `JSON-EXPORT status=pass features=4 sources=1 targetIdentities=2`.

### Product boundary

Pure parser/exporter only. No playback engine, no Dobby, no runtime takeover, no command polling and no extra constructor.

### Next required evidence

Use the same v1.9.36.4 binary on the runtime-record/static 5 MB family. Require trusted canonical output, correct target identity and original-byte truth. Then run the legacy ~15 MB family. Only after both pass should this parser line be called cross-family validated.
# Development Status — v2.0.1-dev

Active branch: `feature/hfamap-v2-bounded-universal-analyzer`

- architecture replacement: complete;
- old scanner removed from active Makefile: complete;
- host parser unit tests: pass;
- supplied real-dylib regression: 10/10 pass;
- arm64 Theos CI: passed (`35186351403`);
- artifact: `10481758150`, binary SHA-256 `d6605ec4b3c36bd3daa7d944d9cd24f230dc4905d33ac67ab5659557b6d57413`;
- device runtime: pending;
- release status: not yet device-validated.
- first device archive: scan stability passed; discovery partially passed; static patch extraction failed.
- corrective source changes: complete; v2.0.1 CI pending.
