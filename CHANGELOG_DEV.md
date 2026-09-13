# Development Changelog

## v1.9.28 GenericMenuResolver — in development

Branch: `feature/hfamap-v1928-generic-menu-resolver`
Base: `feature/hfamap-v1927-target-chain-resolver` @ `d7d00e8a97698e8c0545390903e082dd83676166`

### Added

- `hfamap/src/HFAMapGenericMenuResolver.m`
  - APPatchItem protocol/method fingerprint discovery.
  - Generic switch/button/slider/group classification.
  - IGSecretInt / IGSecretData / IGSecretString / APSubpatchManager / IGCodePatch descriptor fingerprinting.
  - Runtime action IMP image/RVA logging.
  - Legacy AP vs jailpatch-v2 architecture detection.
  - `Documents/HFAMap_MenuMap.jsonl` structured evidence output.
- `.github/scripts/hfamap_v1928_generic_menu.py`
  - Connects the generic resolver to the existing UI traversal, target discovery, action hook, and full-scan button.
- `hfamap/Makefile`
  - Compiles the new generic resolver source.

### Compatibility

- v1.9.27 target-chain behavior is intended to remain intact.
- Existing legacy/iGMM package exporters are intended to remain byte-identical across the v1.9.28 integration patch.
- jailpatch-v2 is probe-only in this version.

### Verification

- Source changes committed: yes.
- Compiled: pending CI.
- GitHub Actions: pending.
- Device tested: no.
- Regression tested: pending CI invariants.
