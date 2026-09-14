# HFA Unified Feature Package v2

`com.hfa.feature/v2` is an additive format. It does **not** replace or invalidate `com.hfa.patch/v1`.

The v1 contract models one UI idea: a boolean feature whose implementation is a set of reversible byte patches. Real menu families are broader: numeric inputs, toggles, buttons, runtime hook graphs and future control types. v2 separates **control semantics** from **execution semantics**.

## Compatibility

- Existing `com.hfa.patch/v1` packages remain valid and keep their current playback path.
- A v2 feature with `execution.kind = bytePatch` has the same `target / offset / original / enabled` tuple semantics as v1.
- Unknown `control.kind` or `execution.kind` values are extension points. They must carry a non-empty `provider`, and consumers must fail closed unless that provider is explicitly supported.
- Target identity remains out-of-band in the existing `com.hfa.patch.identity/v1` sidecar for now. Offsets remain preferred Mach-O VM addresses.

## Core control kinds

- `toggle`: boolean state.
- `number`: editable numeric state.
- `slider`: bounded numeric state.
- `button` / `action`: one-shot, stateless invocation.
- `choice` / `multiChoice`: enumerated values.
- `text`: string state.

## Core execution kinds

- `bytePatch`: reversible static byte patch list. This is the direct v1 equivalent.
- `runtimeState`: bind a control value to state owned by a shared `runtimeGraph`.
- `runtimeGraph`: activate a graph as a feature action.
- `nativeCall`: invoke a native target once.

The schema intentionally keeps `control` and `execution` extensible. The strict Python validator in `tools/validate_hfa_feature_v2.py` enforces the currently supported core kinds and fail-closed extension rules.
