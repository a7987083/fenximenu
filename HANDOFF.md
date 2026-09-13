# HFAMap Handoff

## Current branch

`feature/hfamap-v1931-generic-secret-decrypt-resolver`

## Current build

- Base branch: `feature/hfamap-v1930-jailpatch-selector-resolver`.
- Base commit: `ded59d42ebca90895173ac4f185bd69cc94348a0`.
- Build-tested v1.9.31 code commit: `e50600f00d65a84e6ed42b56dd18fbdd3a64906b`.
- GitHub Actions run: `34786393869` — success.
- Artifact: `HFAMapUniversal-v1.9.31-GenericSecretDecryptResolver` (ID `10326447565`).
- Binary: `HFAMapUniversal_v1.9.31_GenericSecretDecryptResolver.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175552` bytes.
- SHA256: `7638894c72b7b5f391be02ea3ee481fa5ff31cd28080eda2de3bc07fe5a1453f`.

## Confirmed runtime checkpoints

### Legacy AP / ~15 MB

Runtime-confirmed under v1.9.28. Device evidence produced 12 valid mappings with UnityFramework RVAs, original/enabled bytes, action IMP metadata, and successful `.hfapatch.json` export.

### Jailpatch-v2 runtime-record path / ~5 MB — v1.9.30

v1.9.30 has now been device tested. The selector resolver correctly recognized runtime records and associated the descriptor with:

- its `offset` secret wrapper;
- its stable `<identifier>-switch`/identifier/module string evidence;
- exactly one remaining secret-wrapper patch-data candidate after excluding `offset` and `signature`.

The bridge reached the mature HFAMap `[MAPPING]` path. Therefore menu discovery, descriptor fingerprinting, and wrapper association are runtime-confirmed for the tested 5 MB runtime-record architecture.

The remaining failure was decrypt-function location. The inherited legacy logic tested `secret getter + 0xD00`; on the tested runtime-record sample that candidate did not match the established three-instruction decrypt fingerprint, so offset/patch plaintext was not recovered and mapping validity remained false.

### Independent iGMM ~5 MB path

The WayOfKings-style sample previously exported `com.TornadoBear.WayOfKings_1.4.0_165.hfapatch.json` through the existing iGMM resolver/exporter. This path is preserved and must remain regression-protected.

## Static evidence behind v1.9.31

Both supplied ~5 MB dylibs were inspected independently. Their `secret` wrappers differ in obfuscated class names and absolute RVAs, but each image contains exactly one `__TEXT,__text` function matching the decrypt fingerprint already used by the mature HFAMap decrypt pipeline:

- `+0x00 = 0xD105C3FF`
- `+0x30 = 0xB9400408`
- `+0x40 = 0x53187D00`

Observed decrypt RVAs:

- sample A: `0x2123D4`
- sample B: `0x2129A4`

The observed getter-to-decrypt delta is `0x1204` in both supplied binaries. This is recorded as evidence only. The v1.9.31 implementation does **not** use `0x1204`, either module name, either sample RVA, or any obfuscated class name.

## v1.9.31 resolver design

`HFADecryptWrapper`
→ obtain live `secret` getter IMP/image
→ try the already runtime-confirmed legacy `getter + 0xD00` candidate and require the fingerprint
→ if it fails, parse the loaded image's Mach-O headers
→ locate `__TEXT,__text`
→ scan 4-byte-aligned addresses for the same three-instruction decrypt fingerprint
→ accept only exactly one match
→ cache result per image
→ call the existing decrypt function ABI `(secretCopy, plainBuffer)`
→ continue existing `[MAP-DECRYPT]` / `[MAPPING]` / group/full mapping / exporter pipeline.

New resolution evidence:

- `[MAP-DECRYPT-RESOLVE] ... mode=legacy-relative matches=1`
- `[MAP-DECRYPT-RESOLVE] ... mode=text-fingerprint matches=1`
- `[MAP-DECRYPT-SKIP] ... reason=resolver ...` for zero/ambiguous matches.

## Runtime outputs

- `Documents/HFAMap_Learn.log`
- `Documents/HFAMap_MenuMap.jsonl`
- `Documents/HFAMap_JailpatchMap.jsonl`
- any generated `*.hfapatch.json` package.

## Next validation

Inject v1.9.31 into the runtime-record style ~5 MB target, open the original menu, run `Auto Detect / Full Scan`, then exercise visible controls.

Required success chain before marking the generic 5 MB resolver runtime-confirmed:

`[JAILPATCH-SELECTOR-DESCRIPTOR]`
→ `[MAP-DECRYPT-RESOLVE] mode=text-fingerprint matches=1`
→ `[MAP-DECRYPT] rc=0` with valid plaintext
→ `[MAPPING]` / `[FULL-MAPPING] valid=1`
→ preferably successful `.hfapatch.json` package export.

## Verification discipline

- v1.9.31 source integrated: yes.
- v1.9.31 compiled/linked/signed: yes.
- CI/invariants/exporter regression/SHA256: passed.
- Artifact independently downloaded and re-hashed: passed.
- v1.9.31 5 MB device tested: no.
- v1.9.30 selector/wrapper bridge device tested: yes.
- v1.9.30 decrypted mapping/package on runtime-record 5 MB: no.
- v1.9.28 legacy 15 MB resolver device tested: yes.
- v1.9.31-on-15MB runtime regression: not performed.
