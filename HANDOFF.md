# ZPatchIG Handoff

- Repository: `a7987083/fenximenu`
- Branch: `zpatchig`
- Current line: `v0.2.1` Safe Observer
- Product role: evidence-first parser/exporter/runtime observer; patch execution remains excluded from the current line.
- Log naming: `CFBundleIdentifier -> CFBundleDisplayName -> CFBundleName -> unknown`.
- Current observer: bounded/reversible descriptor setter observation with strict setter ABI checks.
- Verified family logic: Legacy typed descriptor ABI overrides incidental C4M0/iGameGod runtime strings; C4M0 erased descriptor ABI remains separately identified.
- Verified v0.2 crash lesson: avoid heavy Foundation/shared diagnostics work in the setter hot path. v0.2.1 removed this path and multiple previously crashing samples completed repeated `setActive:` events and normal disarm.
- Verified historical migration path: UI label -> identifier -> feature key -> descriptor -> secret wrapper -> offset/signature/data -> target image/RVA -> original bytes -> canonical export.
- Historical branches with successful experience: `feature/hfamap-v1927-target-chain-resolver`, `feature/hfamap-v1928-generic-menu-resolver`, `feature/hfamap-v1931-generic-secret-decrypt-resolver`, `feature/hfamap-v19379-complete-feature-export`, `feature/hfamap-v193710-unified-feature-model`, `feature/hfamap-v193711-earntodie-canonical-14`.
- Important rule: historical fixed RVAs or relations such as `getter + 0xD00` are not reusable truth. Re-locate from the current binary and validate ARM64 control flow/fingerprint before use.
- Canonical static export requires target image identity/UUID/architecture, stable RVA semantics, original-byte verification, and confirmed patch bytes.
- Detailed success patterns are documented in `SUCCESS_PATTERNS.md` and should be reviewed before the next reverse-engineering stage.
- Next migration target: feature label resolver + descriptor correlator + validated Legacy `IGSecretInt` offset resolver.
