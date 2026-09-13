# Development Changelog

## v1.9.28 GenericMenuResolver — compiled / awaiting device validation

Branch: `feature/hfamap-v1928-generic-menu-resolver`
Base: `feature/hfamap-v1927-target-chain-resolver` @ `d7d00e8a97698e8c0545390903e082dd83676166`
Build commit: `e2054a2196f6650e2a345ae90d46cd139daf40ba`
Successful CI run: `34781824064`
Artifact ID: `10324649442`
Binary SHA256: `9e29222665f374fa54dc03d43106e1a10e247aac3e44902ca9e6537b9bf0925a`

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
- `.github/workflows/theos-hfamap-v1928-generic-menu.yml`
  - Applies the historical patch chain through v1.9.27, applies v1.9.28, verifies invariants, builds, checks SHA256, and publishes a workflow artifact.

### Compatibility / regression checks

- v1.9.27 legacy and iGMM exporter functions were verified byte-identical before/after the v1.9.28 patch.
- Generic resolver invariant checks passed.
- Explicit sample/game/class/RVA hardcode deny-list checks passed.
- Existing v1.9.27 target-chain strings and mapping/export paths remain present in the built dylib.
- jailpatch-v2 remains deliberately `probe-only`.

### Build result

- Source changes committed: yes.
- Compiled: yes, arm64.
- Linked: yes.
- Signed: yes.
- GitHub Actions: success (`34781824064`).
- Artifact uploaded: yes (`HFAMapUniversal-v1.9.28-GenericMenuResolver`).
- SHA256 verified: yes.
- Device tested: no.
- Runtime regression tested: no; requires device logs.

### CI note

The first run (`34781698047`) compiled successfully but the final bot `git push` failed because the repository Actions token had read-only Contents permission. The workflow was changed to artifact-only delivery; run `34781824064` then completed successfully end-to-end.
