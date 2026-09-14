# HFAMap Handoff

## Current branch

`feature/hfamap-v1933-original-byte-resolver`

## Current build

- Build-tested code commit: `8845d84b2adbada07fdd46a1de0243ff8ae4165b`.
- GitHub Actions run: `34799869649` — success.
- Artifact: `HFAMapUniversal-v1.9.33-OriginalByteResolver` (ID `10330589684`).
- Binary: `HFAMapUniversal_v1.9.33_OriginalByteResolver.dylib`.
- Architecture: arm64 Mach-O dylib.
- Size: `175616` bytes.
- SHA256: `1b0029907683e40439d8bc23442491e314648257d6f517a6cf2df3687e56bd4a`.

## Confirmed runtime checkpoints

### Legacy AP / ~15 MB

Runtime-confirmed under v1.9.28 with 12 valid mappings and successful `.hfapatch.json` export.

### Runtime-record Jailpatch / ~5 MB under v1.9.32

The v1.9.32 device capture closes the scan + decrypt + mapping chain:

`[AUTO-MENU-CANDIDATE] source=jailpatch-feature-array`
→ `[AUTO-TRAVERSAL-END]`
→ `[AUTO-SCAN]`
→ no crash
→ 8 `[JAILPATCH-SELECTOR-DESCRIPTOR]` records
→ `[MAP-DECRYPT-RESOLVE] ... mode=text-fingerprint matches=1`
→ `[MAP-DECRYPT] rc=0`
→ 8 `[FULL-MAPPING] ... valid=1` records.

`[FULL-SCAN-END]` reported `groups=3 mappings=8 valid=8 unresolved=0`. `HFAMap_Mapping.log` contains all eight mappings.

Therefore the generic selector/wrapper/decrypt/mapping path is runtime-confirmed for the tested runtime-record 5 MB architecture.

### WayOfKings iGMM / ~5 MB under v1.9.32

The scan completed with semantic early stop and no crash. `com.TornadoBear.WayOfKings_1.4.0_165.hfapatch.json` exported four iGMM features, so the existing iGMM path remains runtime-confirmed.

## Remaining package issue

The runtime-record package contained only one feature/one patch even though eight mappings were valid. Seven mappings emitted:

`[PACKAGE-SKIP] reason=identity-or-original-unavailable`

The package exporter intentionally requires original bytes. The previous reader used only `vm_read_overwrite` on the resolved image/vmaddr and had no fallback.

## v1.9.33 design

Original-byte resolution order:

1. live `vm_read_overwrite`;
2. bounded direct `memcpy` only if `HFAReadable` confirms the range;
3. on-disk Mach-O segment mapping using the resolved VM address;
4. reject on-disk bytes if the requested file range overlaps an active `LC_ENCRYPTION_INFO_64` encrypted range.

If live bytes equal the enabled patch, v1.9.33 may replace them with a trustworthy unencrypted Mach-O file original when available.

New evidence:

`[PACKAGE-ORIGINAL] title=... module=... offset=... bytes=... imageIndex=... source=vm-read|memcpy|mach-o-file|mach-o-file-after-enabled-live|unavailable cryptid=... status=ok|unavailable`

The existing rule remains unchanged: no trustworthy original bytes means no package patch entry.

## Next validation

Test the runtime-record 5 MB sample first:

- open the original menu;
- run `Auto Detect / Full Scan`;
- require the scan/decrypt chain to remain stable and all 8 mappings to remain valid;
- inspect all `[PACKAGE-ORIGINAL]` lines;
- compare the package with the expected semantic result: 3 features and 8 patch records if all originals are resolved.

Then run the WayOfKings sample once as an iGMM regression and confirm its four-feature package remains intact.

## Verification discipline

- v1.9.33 source integrated: yes.
- compiled/linked/signed: yes.
- CI/regression/invariants/SHA256: passed.
- artifact independently downloaded and re-hashed: passed.
- v1.9.32 two-game Full Scan stability: device-confirmed.
- v1.9.32 runtime-record decrypt: device-confirmed.
- v1.9.32 runtime-record mappings: 8/8 device-confirmed valid.
- v1.9.33 original-byte fallback: not yet device-confirmed.
