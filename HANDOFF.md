# ZPatchIG Handoff

- Repository: `a7987083/fenximenu`
- Branch: `zpatchig`
- Current line: `v0.4.0` Universal Evidence Graph foundation.
- Product role: evidence-first parser/exporter/runtime observer; patch execution remains excluded.
- Build commit: `5abc63729922f3f8df6052a6b289d55747343ad0`.
- GitHub Actions run: `35437806329` — success.
- Artifact: `ZPatchIG-v0.4.0` / ID `10582392706`.
- Artifact ZIP digest: `sha256:862bf5eae43cd70656b8a61f526fd2f7c3b4b3040ce28f0c4fd70fc014a4369e`.
- Dylib SHA-256: `66c3d836f817064c47fa97209eb63486fae2aa213963022afa0f583723f4b986`.
- Binary identity: Mach-O 64-bit arm64 dylib, `NOUNDEFS|DYLDLINK|TWOLEVEL|NO_REEXPORTED_DYLIBS`.

## v0.4 architecture

- Added `ZPEvidenceGraph`: bounded nodes/edges exported as app-specific `EvidenceGraph.json`.
- Added `ZPContainerResolver`: short main-thread UI/target seed capture followed by worker-side read-only object-graph traversal.
- Feature containers that contain both label and identifier are primary evidence (`evidenceRank=100`).
- UI control/target mappings are auxiliary only (`evidenceRank=30/20`) and cannot override a container mapping.
- Container -> child descriptor relationships are recorded explicitly; visual order is never used as the relationship.
- Descriptor ivars are collected read-only with `class_copyIvarList`, `object_getIvar`, and `ivar_getOffset`.
- Every descriptor ivar offset is labeled `objc-instance-ivar-only`; it must never be interpreted as Mach-O RVA/file offset/runtime VA.
- Foundation scalar/string/data evidence is bounded; other object values record class/pointer evidence rather than invoking target getters.
- Existing Safe Observer remains unchanged in its hot-path policy.
- Legacy offset resolver remains asynchronous and keeps its separate `OffsetEvents.jsonl`; historical fixed `getter + 0xD00` is still forbidden.

## HFAMapUniversal v2.2.3 lesson incorporated

The supplied v2.2.3 source established an important correction to older UI-target correlation: shared targets can make multiple controls reach the same descriptor and inherit the wrong first label. Therefore the preferred evidence order is now:

`feature container (label + identifier) -> child array/record -> descriptor -> ivar evidence`

UI control/target evidence is retained only as an auxiliary path into the object graph.

## Validation boundary

- CI/source/build verification: passed.
- Final binary marker/SHA verification: passed.
- Device validation of v0.4 container relationships and EvidenceGraph output: pending.
- Do not record container mappings as device-verified until new device logs confirm them.
- Do not promote any ObjC ivar offset to a patch address.
- Canonical static patch still requires target image identity/UUID/architecture, stable Mach-O RVA semantics, original-byte validation, and confirmed patch bytes.

## Next validation

Run v0.4 on the existing multi-game sample set and inspect:

- `Analysis.json` -> `containerFeatures`, `descriptorEvidence`, `containerMetrics`;
- `EvidenceGraph.json`;
- `DescriptorEvents.jsonl`;
- `OffsetEvents.jsonl`;
- `Diagnostics.jsonl` and `Process.jsonl`.

Then add asynchronous offset/runtime evidence edges to the graph and begin the IL2CPP metadata backend without changing the evidence schema.
