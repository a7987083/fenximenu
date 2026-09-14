# HFA Feature v2 Runtime Executor — v1.2.0

This layer extends `HFAPatchConsumerPlayback` without changing the frozen HFAMap v1.9.36 generator. It keeps the existing `com.hfa.patch/v1` and v2 `bytePatch` transaction paths, then adds an intentionally small built-in runtime primitive set for `com.hfa.feature/v2`.

## Supported built-in runtime primitives

- `runtimeState` bound to `bool` or numeric graph state;
- `pointerSet` runtime stores;
- `captureFieldPointer` hook behavior with `x0 + fieldOffset` capture;
- `conditionalPipeline` over ARM64 `x0` subject / `x1` integer argument with the proven protected-object God Mode / Defence / Damage rule shape;
- `nativeCall` for a `button` control with ABI `void()`.

Anything outside that subset fails closed. The generic v2 schema remains extensible; this document describes only what the v1.2.0 built-in executor can execute.

## Runtime commands

Commands continue to use `Documents/HFAPatchPlayback.command.json` and produce the same result/log files. Runtime actions use one `featureId` instead of `featureIds`.

`prepare` bootstraps the runtime graph referenced by a `runtimeState` feature but leaves every state at its declared default. `set` bootstraps the graph if needed, then changes one bound value. `invoke` executes one `button + nativeCall` feature once.

Examples in this directory cover:

- graph prepare via `god_mode`;
- Damage value `16`;
- Defence value `12`;
- God Mode ON and OFF;
- Debug Menu one-shot invoke.

## Fail-closed hook installation

Before any Dobby hook is installed, the executor:

1. verifies package metadata against the running bundle;
2. verifies the target against the existing `com.hfa.patch.identity/v1` identity sidecar;
3. resolves the preferred Mach-O VM offset using the actual loaded-image slide;
4. reads the declared `original` bytes at every hook entry;
5. refuses to install the graph if any byte differs;
6. installs the hooks transactionally and rolls back already-installed hooks if a later hook fails;
7. re-reads each hook entry and requires it to differ from the original bytes after installation.

The runtime backend is Dobby built as an arm64 iOS static library at the pinned upstream commit recorded in CI. Dobby is linked into the consumer; the target game does not need a separate Dobby dylib.

## WayOfKings model

The current WayOfKings fixture represents the static analysis already established from the supplied `UnityFramework` and `libpathofkings.dylib`:

- producer hook: `UnityFramework + 0x3BFA200`, original `F657BDA9`, captures `[x0+0x50]`;
- producer hook: `UnityFramework + 0x3DC3310`, original `F657BDA9`, captures `[x0+0x38]`;
- damage consumer hook: `UnityFramework + 0x3BF6D90`, original `EB2BBA6D`;
- Debug Menu one-shot call: `UnityFramework + 0x3DEC9A0`, entry preflight `F44FBEA9`.

The two producers populate one protected-object set. The consumer hook applies God Mode/Defence only to protected objects and Damage Multiplier only to non-protected objects, then calls the original trampoline when not bypassed.

## Important playback condition

The runtime executor expects the target hook entries to still contain the JSON-declared original bytes. Do **not** inject the original iGMM menu at the same time when validating this consumer. If another menu/hook has already replaced those entries, `prepare` must fail with a preflight mismatch rather than stacking a second hook over unknown state.

## Evidence boundary

CI can prove source transformation, schema/runtime validation, Dobby static linkage, arm64 compilation, and artifact hashing. It cannot prove that a jailed or jailbroken target device accepts the runtime code remap, nor can it prove gameplay semantics. Those remain **PENDING** until returned device logs and behavior evidence show:

- graph `prepare` succeeds;
- Damage / Defence values change behavior as intended;
- God Mode ON protects only tracked objects and OFF restores normal behavior;
- Debug Menu button executes once per invoke;
- no crash/regression occurs;
- the original-menu and consumer behaviors match.

A successful hook/readback result alone is not labeled gameplay verification.
