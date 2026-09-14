# HFAPatch Consumer v2 compatibility layer

This branch adds additive support for `com.hfa.feature/v2` without removing or weakening the existing `com.hfa.patch/v1` path.

## First execution gate

The v2-compatible consumer accepts both package schemas, but only executes v2 features that satisfy all of these conditions:

- `control.kind == "toggle"`;
- `execution.kind == "bytePatch"`;
- `execution.patches` is non-empty;
- every patch still passes the existing target identity, preflight-byte, transaction, readback and restore checks.

The selected v2 feature is normalized in-memory to the existing v1 playback shape and then uses the same transaction engine.

## Fail-closed runtime features

The first compatibility build deliberately refuses to execute these v2 kinds:

- `runtimeState`;
- `runtimeGraph`;
- `nativeCall`;
- any unknown provider-backed execution kind.

They return `v2-execution-not-playable:<featureId>:<kind>` and perform no write. This keeps the WayOfKings runtime model representable in JSON while preventing the consumer from pretending a runtime hook graph is already implemented.

## Identity

Target identity remains the existing `com.hfa.patch.identity/v1` sidecar. Package metadata and target UUID / architecture / Mach-O preferred VM address checks are unchanged.

## Next gate

After the v2 bytePatch compatibility artifact builds and regresses against legacy v1, implement runtime executors separately, beginning with the WayOfKings shared combat graph and only after static/runtime evidence is preserved in the package.
