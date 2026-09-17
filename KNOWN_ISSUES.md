# Known Issues

## v1.9.37.10 Earn to Die Rogue profile

### Device runtime validation pending

Status: open.

Fuel/Boost are statically proven and generation-tested, but the new analyzer
binary has not yet been built by GitHub Actions or exercised on device. Required
checks are clean scan output, `14` canonical features, `20` patches, independent
Fuel/Boost enable/disable and original-byte restoration.

### Already-depleted values are not refilled

Status: intentional behavior.

The two patches NOP the subtraction instructions. They prevent additional
consumption but do not assign a full tank. Enable them before Fuel/Boost reaches
zero or start a new driving session.

### Exact-build profile only

Status: permanent safety gate.

The RVAs are valid only for `com.notdoppler.earntodierogue` `1.28.251 (1)`,
arm64, UnityFramework UUID `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`, with exact
original bytes. A game update requires fresh metadata and binary analysis.

### Posters/Prestige patch overlap

Status: open / pre-existing.

Both features touch `UnityFramework+0x2E25904`. Posters writes `08E0BF12`
(4 bytes), while Prestige writes `20008052C0035FD6` (8 bytes). Toggle order can
overwrite the shared first instruction. Fuel/Boost do not introduce this
conflict, but the package needs explicit conflict handling or a new independent
Prestige/Posters patch site.

### Generic observed-action classification remains too broad

Status: mitigated for the verified target only.

The generic v1.9.37.9/v1.9.37.10 logic can classify an observed action as
`runtimeAction` even when the action is only a shared menu dispatcher. The exact
Earn to Die profile corrects the two proven records; a future generic fix should
use `dispatcher-observed/unresolved` until independent write/hook/static-byte
evidence exists.

## Current parser-only line: v1.9.36.4 JSONExport

### v1.9.36.4 WayOfKings/iGMM validation

Status: **passed / closed**.

Device archive `归档 6(1).zip` confirmed stable injection, Full Scan completion, 4-feature iGMM diagnostic export and normalized analysis export. It also confirmed:

- `kTypeButton -> button`;
- raw Debug Menu `executionPrimitive = nativeHook` remains preserved;
- `normalizedExecutionPrimitive = runtimeAction`;
- raw `canonicalReason = runtime-hook-requires-portable-equivalent` remains preserved;
- `normalizedCanonicalReason = runtime-action-not-static-bytes`;
- `targetIdentities` resolves both `libpathofkings.dylib` and `UnityFramework` with the expected UUID/arm64/cryptid evidence;
- `JSON-EXPORT status=pass features=4 sources=1 targetIdentities=2`.

### Cross-family regression is still pending

Status: open / primary validation gate.

The current v1.9.36.4 parser has now passed the WayOfKings/iGMM family, but the same binary still must be regression-tested on:

- runtime-record/static 5 MB family;
- legacy ~15 MB family.

Do not claim universal/cross-family coverage until both current-line regressions pass.

### Target identities are analysis evidence, not execution authorization

Status: permanent rule.

Read-only UUID/architecture/filetype/preferred-`__TEXT`/cryptid records are for build matching and analysis quality only. They do not authorize hook installation or package execution.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device-confirmed.

WayOfKings uses runtime numeric/native-hook/block behavior. These records remain diagnostic and analysis-only and are not fabricated into `target/offset/original/enabled` static patches.

### v1.9.37 and v1.9.37.1 are retired from the parser mainline

Status: confirmed device startup failure / architecture reverted.

Those builds merged the independent playback/runtime consumer and Dobby into HFAMapUniversal. Both crashed immediately when injected. HFAMapUniversal remains a parser/exporter only.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing a new menu family, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs. A stale canonical package must never be mistaken for current output.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Runtime-record/static 5 MB regression

Status: open / next test.

The current v1.9.36.4 build must reproduce a trusted `com.hfa.patch/v1` package for the static 5 MB family. Required checks include real target identity, preferred VM offsets, original-byte truth and no stale-output contamination.

### Legacy ~15 MB regression

Status: open / follows the 5 MB static test.

The legacy AP/IGSecret family was previously runtime-confirmed on older parser versions. The current v1.9.36.4 binary must still prove that path has not regressed.

## Current CI delivery

Authoritative candidate:

- binary: `HFAMapUniversal_v1.9.36.4_JSONExport.dylib`
- run: `34907671999`
- artifact: `10372928333`
- binary SHA256: `a6fd46cffd2d4ce133229c4248d350a79dfbdfbb20755033132837d5690200c5`
- artifact digest: `sha256:1fe9e536abdf9fc31c4a58e3a26db14b2e7870a2424b88cb5cb6d150c7198cce`
- WayOfKings/iGMM device validation: passed
- cross-family regression: pending
# v2 open issues

### Jailpatch runtime table is not yet decoded

Status: confirmed by first device archive.

`libdragonfevertd.dylib` was selected correctly and the scan completed, but UI-target object traversal exposed
no offset/patch descriptor. Static strings and Mach-O structure identify a Jailpatch `loadConfig:` and runtime
metadata path, but strings alone do not prove its structure. A bounded observer at that exact boundary is the
next task if v2.0.1 still exports no descriptors.

### First device build had discovery/traversal defects

Status: fixed in v2.0.1-dev; device re-test pending.

The 512-image cap omitted late-loaded menu images in three runs. A wrapper/payload pair was rejected because
their total scores differed by only eight points. UIKit/Foundation objects polluted unresolved output. The
corrective build raises the bounded cap, applies descriptor-strength tie-breaking and filters non-descriptor
containers.

### Device validation is pending

The host-side parser passes all ten supplied dylib samples and arm64 CI compile/link passed, but the new
Objective-C++ runtime path has not yet been injected on a device. Clean-device regressions are required
before release.

### Runtime-generated descriptors are intentionally unresolved

If a menu decrypts or constructs its patch only at interaction time, a read-only menu snapshot cannot prove
the bytes. v2 reports this instead of converting UI actions into static patches. A future observer must target
an evidenced registration/decryption boundary and remain bounded to the selected image.

### Candidate ties require a future manual picker

When the top two loaded app-local candidates differ by fewer than ten points, v2 refuses automatic selection.
The JSON contains both candidates; a UI picker is not yet implemented.
