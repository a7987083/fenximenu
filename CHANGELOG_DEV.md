# Development Changelog

## v1.9.36.4 JSONExport — compiled / CI passed / awaiting device validation

Branch: `feature/hfamap-v19361-json-export`
Parser baseline: `v1.9.36 ArchitectureTruth @ 75f94da37221343b6839465ad365ddec2679e63a`
Build-tested commit: `c62b378220d1908c2788a5a359083b484b187c66`
Successful CI run: `34907671999`
Artifact ID: `10372928333`
Binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
Binary size: `192432` bytes
Binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
Artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`

### v1.9.36.3 device result

WayOfKings device archive confirmed:

- injection did not crash;
- Full Scan completed;
- `com.hfa.igmm.runtime/v1` output was written;
- `com.hfa.menu.analysis/v1` output was written;
- four features were exported;
- Damage Multiplier: `modtext -> number`, default `1`;
- Defence Multiplier: `modtext -> number`, default `1`;
- God Mode: `customSwitch -> toggle`;
- Debug Menu: `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` remained preserved;
- Debug Menu `normalizedExecutionPrimitive = runtimeAction`;
- `targetIdentities` resolved `libpathofkings.dylib` and `UnityFramework` with the expected UUID, arm64, filetype, preferred `__TEXT` and cryptid evidence.

Confirmed identities:

- `libpathofkings.dylib`: UUID `4C4C448B-5555-3144-A14F-4905D9ED4E59`, arm64, filetype 6, text VM `0x0`, cryptid 0;
- `UnityFramework`: UUID `E0039512-CCB0-33E3-A69A-3DBEBFF3641B`, arm64, filetype 6, text VM `0x0`, cryptid 0.

### v1.9.36.4 change

v1.9.36.3 correctly preserved raw classifier evidence, but Debug Menu therefore had a raw `canonicalReason` corresponding to its source `nativeHook` classification while the normalized primitive was `runtimeAction`.

v1.9.36.4 keeps the raw evidence and adds a parallel normalized reason:

- raw `canonicalReason`: unchanged;
- `normalizedExecutionPrimitive`: unchanged from v1.9.36.3;
- new `normalizedCanonicalReason`;
- observed button block/action -> `runtime-action-not-static-bytes`.

No parser-core or runtime behavior changed.

### Verification

- baseline constructor preserved: PASS;
- baseline `run_full_scan()` preserved: PASS;
- baseline trace/resolver core preserved: PASS;
- WayOfKings normalization fixture: PASS;
- analysis-only invariants: PASS;
- arm64 compile/link/strip/sign: PASS;
- no Dobby symbols in final binary: PASS;
- artifact upload: PASS;
- artifact independently downloaded/re-hashed: PASS;
- v1.9.36.4 device validation: PENDING.

## v1.9.36.3 JSONExport — device passed on WayOfKings

- Added evidence-preserving `normalizedExecutionPrimitive`.
- Added read-only `targetIdentities`.
- Device archive confirmed stable startup, scan, button normalization and target identity output.

## v1.9.36.2 JSONExport — CI passed

- Added exact `kTypeButton -> button` normalization.

## v1.9.36.1 JSONExport — device tested on WayOfKings

- Rebased onto the stable v1.9.36 parser.
- Added analysis-only serializer after Full Scan.
- Device archive proved stable injection and JSON export, and exposed the `kTypeButton` gap.

## Retired experiment: v1.9.37 / v1.9.37.1

- Combined parser, dynamic JSON UI, playback consumer, Dobby and runtime takeover into one dylib.
- CI/build succeeded, but both device injections crashed at startup.
- Combined architecture abandoned for the HFAMapUniversal parser mainline.

## Earlier parser checkpoints

- v1.9.36: ArchitectureTruth frozen parser baseline.
- v1.9.35: MainImageTruth.
- v1.9.34: CanonicalTruthGate.
- v1.9.33: multi-source original-byte resolver.
- v1.9.32: crash-safe Full Scan.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
