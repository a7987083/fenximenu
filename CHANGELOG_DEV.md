# ZPatchIG development changelog

## v0.2.0
- App-specific log filenames: Bundle ID -> CFBundleDisplayName -> CFBundleName -> unknown.
- Added reversible 10-second descriptor setter observer.
- Correlates descriptor identity, identifier, active, offset/signature object evidence and range snapshots.
- Preserves/restores original IMPs; no patch execution.
- Added dedicated `*_DescriptorEvents.jsonl` evidence stream.

## v0.1.1
- ABI-first Legacy AP / C4M0 classification.
- Conflicting runtime strings no longer override typed descriptor ABI.
