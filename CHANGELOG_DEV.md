# Development Changelog

## v1.9.31 GenericSecretDecryptResolver — compiled / awaiting 5 MB decrypt validation

Branch: `feature/hfamap-v1931-generic-secret-decrypt-resolver`
Base: `feature/hfamap-v1930-jailpatch-selector-resolver` @ `ded59d42ebca90895173ac4f185bd69cc94348a0`
Build-tested commit: `e50600f00d65a84e6ed42b56dd18fbdd3a64906b`
Successful CI run: `34786393869`
Artifact ID: `10326447565`
Binary: `HFAMapUniversal_v1.9.31_GenericSecretDecryptResolver.dylib`
Binary size: `175552` bytes
Binary SHA256: `7638894c72b7b5f391be02ea3ee481fa5ff31cd28080eda2de3bc07fe5a1453f`

### Runtime evidence received from v1.9.30

The v1.9.30 device capture confirms that the selector-based descriptor stage is correct for the runtime-record style ~5 MB family:

- Runtime records were recognized by the stable selector fingerprint rather than obfuscated class/ivar names.
- `offset` resolved to a secret-wrapper object.
- After excluding the `offset` and `signature` objects, the observed records had exactly one remaining `secret` wrapper, so the patch-data candidate bridge was deterministic rather than guessed.
- The descriptor was registered into the mature HFAMap mapping pipeline and execution reached `[MAPPING]`.
- The failure occurred after that bridge: decrypted `offset` and `patchData` remained unavailable, therefore mapping validity stayed false.

The concrete failing locator evidence showed the legacy `getter + 0xD00` candidate did not match the already-established decrypt fingerprint on the runtime-record sample. This isolates the remaining problem to decrypt-function location, not menu discovery, record classification, or secret-wrapper association.

The second supplied ~5 MB path continued to produce a patch package through the pre-existing iGMM exporter. That path remains an independent regression requirement.

### Cross-sample static decrypt evidence

Static comparison of both supplied ~5 MB dylibs established a stronger generic signal:

- Their `secret` getters remain simple wrapper accessors but the real decrypt routine is not at the legacy `+0xD00` relative position.
- Scanning each image's Mach-O `__TEXT,__text` for the three instruction words already used by HFAMap to validate the legacy decrypt routine yields exactly one match per image:
  - candidate + `0x00`: `0xD105C3FF`
  - candidate + `0x30`: `0xB9400408`
  - candidate + `0x40`: `0x53187D00`
- Observed decrypt RVAs were `0x2123D4` and `0x2129A4` in the two supplied samples.
- The observed getter-to-decrypt delta happened to be `0x1204` in both samples, but this value is evidence only and is deliberately not used as an implementation constant.

### Added in v1.9.31

- `.github/scripts/hfamap_v1931_generic_secret_decrypt.py`
  - Preserves the runtime-confirmed legacy `getter + 0xD00` candidate as a fast path, but only when the existing instruction fingerprint still matches.
  - Adds loaded Mach-O parsing for `__TEXT,__text` when the legacy candidate fails.
  - Scans 4-byte-aligned instruction addresses for the established decrypt fingerprint.
  - Accepts the scanned routine only when exactly one match exists in the image.
  - Caches the result per image and fails closed on zero or multiple matches.
  - Adds `[MAP-DECRYPT-RESOLVE]` evidence with image, getter RVA, decrypt RVA, resolution mode, and match count.
  - Does not hardcode the observed `0x1204` delta, module names, obfuscated classes, feature labels, or sample RVAs.
- `.github/workflows/theos-hfamap-v1931-generic-secret-decrypt.yml`
  - Replays the full historical patch chain through v1.9.30, applies v1.9.31, verifies previous exporters remain byte-identical, preserves the selector bridge, rejects sample-specific hardcoding, builds/signs the arm64 dylib, verifies SHA256, and uploads the artifact.

### Verification

- Historical patch chain: passed.
- Previous exporter byte-identity checks: passed.
- v1.9.30 selector bridge/invariants retained: passed.
- Generic secret decrypt invariants: passed.
- Explicit hardcode deny-list including `0x1204`, both supplied 5 MB module names, class names, feature labels, getter/decrypt RVAs: passed.
- Compiled/linked/signed: yes, arm64.
- GitHub Actions: success (`34786393869`).
- Artifact uploaded: yes (`10326447565`).
- CI SHA256 check: passed.
- Artifact independently downloaded and re-hashed: passed.
- v1.9.31 device tested: no.

## v1.9.30 JailpatchSelectorResolver — device checkpoint

CI run: `34785200383`
Binary SHA256: `6c716180e7e5a2659cfb538e6ca6ee217773a0ce583741f9d1e43f0f140f9d14`

v1.9.30 is now device-tested on the runtime-record ~5 MB path. Its selector/secret-wrapper bridge is confirmed, but its inherited fixed decrypt locator failed. Therefore v1.9.30 must not be described as a completed 5 MB mapping/export resolver.

## v1.9.29 JailpatchRuntimeProfiler — runtime structure checkpoint

CI run: `34783065857`
Binary SHA256: `8b76b62424c9152a8e09b2e68dfccc09a590f6526403271b07c7056b1f8b0c3e`

The v1.9.29 device capture established the runtime-record object graph and stable semantic selector surface used by v1.9.30 and v1.9.31.

## v1.9.28 GenericMenuResolver — legacy runtime checkpoint

CI run: `34781824064`
Binary SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`

The legacy ~15 MB AP/IGSecret path remains runtime-confirmed with 12 valid feature mappings and successful patch-package export. v1.9.31 preserves the same legacy decrypt fingerprint fast path, but v1.9.31 itself has not been runtime-regression-tested on the 15 MB target.
