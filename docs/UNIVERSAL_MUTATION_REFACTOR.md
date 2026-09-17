# Universal Mutation Refactor

## Goal

Refactor HFAMapUniversal from a collection of family-specific parsers into a pipeline with one provider-neutral truth model:

```text
Evidence Provider
  -> existing truth gate
  -> Canonical Mutation IR
  -> export / regression validation
```

The refactor must preserve already verified 5M, legacy ~15 MB, Jailpatch, iGMM and exact-build profile behavior while removing provider-specific assumptions from the final mutation representation.

## Stage 1: Canonical Mutation IR

Stage 1 introduces `com.hfa.mutation/v1` in:

- `hfamap/src/HFACanonicalMutation.h`
- `hfamap/src/HFACanonicalMutation.m`

The core accepts only mutations that already have all of:

- feature id;
- target id/image;
- preferred Mach-O VM offset;
- non-empty even-length hex original bytes;
- non-empty even-length hex enabled bytes;
- equal original/enabled lengths;
- original bytes different from enabled bytes.

The core intentionally contains no iGameGod/AP/Jailpatch/5M class names or selectors. Family-specific code remains an Evidence Provider, not a truth authority.

`HFAPatchTraceFinalizeScan()` is bridged after the existing truth gate by `.github/scripts/hfamap_v19380_canonical_mutation_ir.py`:

```text
validated exportFeatures/exportTargets
  -> HFAIngestCanonicalPackage(..., "patch-trace")
  -> HFAFlushCanonicalMutations()
  -> HFAMap_CanonicalMutations.json
```

The existing `com.hfa.patch/v1` output remains unchanged in Stage 1.

## Mutation schema

Example:

```json
{
  "schema": "com.hfa.mutation/v1",
  "analysisOnly": false,
  "mutations": [
    {
      "id": "Fuel",
      "title": "Unlimited Fuel",
      "kind": "static-bytes",
      "target": {
        "id": "UnityFramework",
        "image": "UnityFramework"
      },
      "location": {
        "offset": "0x2D98AC8",
        "semantics": "preferred-mach-o-vmaddr"
      },
      "bytes": {
        "original": "0038211E",
        "enabled": "1F2003D5"
      },
      "canonicalEligible": true,
      "confidence": 1.0,
      "evidence": {
        "providers": ["patch-trace"],
        "truth": "original-enabled-byte-difference-validated"
      }
    }
  ]
}
```

## Non-goals of Stage 1

Stage 1 does **not** claim generic discovery of an unknown menu implementation. It does not yet intercept arbitrary executable-page writes, infer arbitrary function hooks, or replace family-specific feature discovery.

## Stage 2

Add provider-neutral mutation capture beneath family resolvers:

1. correlate a menu feature context with the action that executes;
2. observe the resulting code/data mutation rather than relying on storage object names;
3. resolve runtime VA -> loaded Mach-O -> preferred VM offset;
4. capture pre-write and post-write bytes;
5. pass the candidate through the same original-byte/identity truth gates;
6. emit `HFACanonicalMutation` regardless of source framework.

Family adapters then become optional evidence accelerators:

- AP / IGCodePatch provider;
- Jailpatch provider;
- 5M dispatcher provider;
- static Mach-O provider;
- runtime write provider;
- hook/trampoline provider.

## Regression rule

A provider may improve discovery confidence, but it must not change the meaning of the final mutation schema. A new menu family is considered supported only when its verified mutation can be represented without adding family-specific fields or names to `HFACanonicalMutation.m`.
