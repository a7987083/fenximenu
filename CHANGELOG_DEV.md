# Development Changelog

## v1.9.36 ArchitectureTruth — compiled / CI passed / awaiting device validation

Branch: `feature/hfamap-v1936-architecture-truth`
Base: `feature/hfamap-v1935-main-image-truth @ 9556c223646c4dda12d566a1e65b8a4394bbb59d`
Build-tested commit: `75f94da37221343b6839465ad365ddec2679e63a`
Successful CI run: `34832916059`
Artifact ID: `10343305875`
Artifact digest: `sha256:db31af9643b24861fbb10a5408fa8605d5bc1812d47565450ac541a8fc6dcb4d`
Binary: `HFAMapUniversal_v1.9.36_ArchitectureTruth.dylib`
Binary size: `175664` bytes
Binary SHA256: `3249137776562b0723114904c4a92131387c908fd227aec0709d92c3e8f2ca13`

### Device evidence from v1.9.35

The runtime-record/Dragons sample confirmed that v1.9.35 fixed the main-image/original-byte truth defect:

- all eight `PACKAGE-ORIGINAL` records used `imageIndex=1 image=Dragons-prod-remote-nocheat filetype=2`;
- `FULL-SCAN-END` remained `groups=3 mappings=8 valid=8 unresolved=0 packageFeatures=3`;
- `CANONICAL-CHECK` remained `status=pass features=3 patches=8 targets=1`;
- the identity sidecar resolved the real executable with UUID `7E74523C-90F5-3D72-9A9C-108BDE23A4A8`, `arm64`, `cpusubtype=0`, preferred `__TEXT` VM address `0x100000000`, and `cryptid=0`;
- that UUID exactly matches the previously supplied `Dragons-prod-remote-nocheat` Mach-O;
- mapping all eight exported preferred VM addresses back to that file produced byte-for-byte matches for every `original` value: 8/8 verified.

The previous v1.9.34 ASCII-like wrong originals disappeared. Therefore main target resolution and original-byte truth are now runtime-confirmed on this sample.

### Remaining v1.9.35 defect

The formal package still wrote:

`package.architectures = ["arm64e"]`

while the same package's identity sidecar proved the canonical target was `arm64 / cpusubtype=0`.

Source inspection found one remaining historical positional assumption inside `HFAWritePatchPackage`: architecture was still derived from `_dyld_get_image_header(0)`.

### v1.9.36 fix

Package architecture is now derived exclusively from the actual canonical targets resolved through `HFAImageIndexForName`.

Policy:

1. every canonical target must resolve to a loaded image;
2. every target must be ARM64;
3. all canonical targets must agree on one architecture (`arm64` or `arm64e`);
4. unresolved, non-ARM64, or mixed architectures fail closed and no package is written;
5. successful resolution logs `[PACKAGE-ARCH] status=pass ... source=canonical-targets`.

The v1.9.35 main resolver, v1.9.33 original readers, v1.9.34 canonical gate, iGMM diagnostic writer, decrypt path and crash-safe scan are protected unchanged in CI.

### Verification

- historical patch-chain replay: passed;
- protected runtime-path byte comparison: passed;
- ArchitectureTruth invariants: passed;
- v1.9.35 truth-path preservation: passed;
- arm64 compile/link/sign: passed;
- distributable hash check: passed;
- artifact independently downloaded and re-hashed: passed;
- v1.9.36 device validation: pending.

## v1.9.35 MainImageTruth — device-tested / core byte truth passed / package architecture metadata failed

v1.9.35 correctly resolved `main/@main` to the real `MH_EXECUTE` game image and restored correct original bytes. Eight of eight exported originals were independently verified against the same-UUID supplied Mach-O. However, `package.architectures` still inherited the old dyld-index-0 assumption and reported `arm64e` instead of the target's `arm64`.

## v1.9.34 CanonicalTruthGate — device tested / partial pass, byte truth failed

- iGMM diagnostic isolation: passed on device.
- runtime-record scan/decrypt/mapping: passed on device.
- canonical structural contract: passed on device.
- `@main` binary identity/original-byte truth: failed due to dyld index 0 assumption.

## Earlier checkpoints

- v1.9.33: runtime-record 5 MB reached 3 features / 8 structurally complete static patches.
- v1.9.32: fixed the common 5 MB Full Scan crash and confirmed generic decrypt + 8/8 mappings.
- v1.9.31: generic image-local decrypt resolver.
- v1.9.30: selector/secret-wrapper bridge device-confirmed.
- v1.9.29: runtime-record structure/selectors device-confirmed.
- v1.9.28: legacy ~15 MB static package export runtime-confirmed.
