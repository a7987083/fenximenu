# HFAMap Handoff

## Active work

- repository: `a7987083/fenximenu`;
- branch: `feature/universal-mutation-refactor`;
- phase: `v1.9.38.0 Stage 1 Universal Mutation IR`;
- base branch: `feature/hfamap-v193710-unified-feature-model`;
- base commit: `9fe759fe8519bfcaa90c2461a256c18a4d6c2080`;
- build-tested implementation: `a26cab49985fbb675e76378899eeb02052e7f2c6`.

## Current architectural direction

HFAMapUniversal remains a parser/exporter. The refactor changes the internal ownership of truth:

```text
family/static/runtime evidence provider
        -> existing target/original-byte truth gate
        -> Canonical Mutation IR
        -> export / regression
```

Family-specific code is allowed to discover evidence, but the final mutation model must not depend on family-specific classes, selectors or strings.

Stage 1 schema: `com.hfa.mutation/v1`.

Core files:

- `hfamap/src/HFACanonicalMutation.h`
- `hfamap/src/HFACanonicalMutation.m`
- `.github/scripts/hfamap_v19380_canonical_mutation_ir.py`
- `.github/workflows/theos-hfamap-universal-mutation-refactor.yml`
- `docs/UNIVERSAL_MUTATION_REFACTOR.md`

Runtime output added by Stage 1:

- `Documents/HFAMap_CanonicalMutations.json`

The existing canonical `com.hfa.patch/v1` output is preserved unchanged for compatibility.

## Stage 1 acceptance boundary

`HFACanonicalMutation.m` accepts only static byte mutations with:

- feature id;
- target id/image;
- offset;
- valid even-length hex original bytes;
- valid even-length hex enabled bytes;
- equal original/enabled lengths;
- original bytes different from enabled bytes.

Deduplication key:

`feature-id + target-id + offset + enabled-bytes`

Provider evidence is accumulated separately.

The IR core intentionally contains no `IGSecretInt`, `IGCodePatch`, `APPatchItem`, `Jailpatch`, or 5M-specific names.

## CI result

GitHub Actions run `35194007919`: **success**.

Build output:

```text
artifact        HFAMapUniversal-UniversalMutationRefactor
artifact id     10484872379
artifact digest sha256:d3ff65db4470250f008134a180ae01c866e410cc13b4e6bff258069355ac9876
binary          HFAMapUniversal_UniversalMutationRefactor.dylib
architecture    arm64 Mach-O dylib
binary SHA256   09f04e942d6f571048f26fe728e6a51974bb8c2aeeba29a06878befd28a5ea16
```

Verified in CI:

- historical generation chain completed;
- Stage 1 patcher applied;
- existing original-byte truth gate markers remained;
- provider-neutral core assertion passed;
- new module compiled;
- final dylib linked, stripped and signed;
- `com.hfa.mutation/v1`, `MUTATION-IR-INGEST`, and `MUTATION-IR-FLUSH` markers are present;
- artifact upload passed.

Not yet verified:

- device startup/injection with the refactor binary;
- actual on-device generation of `HFAMap_CanonicalMutations.json`;
- five-pair cross-family regression;
- provider-neutral capture of an unknown menu implementation.

## Important build history

The first Stage 1 CI attempt failed at the first real compiler error in `HFACanonicalMutation.m`: an extra `]` in the flush log expression. The fix was syntax-only; the architecture and truth model were unchanged. The successful build is run `35194007919`.

## Existing verified Earn to Die evidence retained

Target:

```text
bundle       com.notdoppler.earntodierogue
version      1.28.251
build        1
architecture arm64
image        UnityFramework
UUID         8654D76C-B760-34FC-BEE0-FE70AE8C95C8
```

Verified static patches:

```text
Fuel  UnityFramework+0x2D98AC8  0038211E -> 1F2003D5
Boost UnityFramework+0x2D9887C  0038281E -> 1F2003D5
```

Both are inside `Assembly-CSharp.dll!com.notdoppler.ETDR.Car.FixedUpdate()` at RVA `0x2D9827C`. Fuel is `_fuelAmount +0xB8`; Boost is `_boostAmount +0xBC`.

The exact-build profile remains a safety/verification profile, not a generic discovery algorithm.

## Stable parser evidence retained

WayOfKings/iGMM v1.9.36.4 remains the last device-confirmed parser checkpoint:

- stable injection;
- Full Scan completion;
- 4-feature iGMM output;
- normalized analysis output;
- target identities for menu dylib + UnityFramework confirmed.

The old v1.9.37/v1.9.37.1 playback/Dobby merge remains retired after startup crashes.

## Next task

Stage 2 must add a provider-neutral mutation capture layer underneath the family adapters:

1. establish feature execution context;
2. observe the actual code/data mutation rather than infer from storage class names;
3. resolve runtime VA -> loaded Mach-O -> preferred VM offset;
4. capture pre-write/post-write bytes;
5. validate against the same truth gate;
6. emit the same `HFACanonicalMutation` regardless of menu framework.

Use the supplied five menu-dylib + host-binary pairs as the primary regression corpus. A family is not considered supported merely because its strings/classes are recognized.

## Verification discipline

Strictly distinguish:

- source changed: yes;
- generated source assertions: passed;
- arm64 compile/link/strip/sign: passed;
- GitHub Actions CI: passed;
- artifact uploaded: passed;
- device runtime: pending;
- cross-family regression: pending;
- full generic/universal claim: not yet justified.
