# HFA Feature v2 development status

Branch: `feature/hfa-feature-v2-unified-schema`.

## Implemented and committed

- `com.hfa.feature/v2` additive schema.
- Control/execution separation.
- Core controls: toggle, number, slider, button/action, choice/multiChoice, text.
- Core execution kinds: bytePatch, runtimeState, runtimeGraph, nativeCall.
- Runtime graph structure with state, stores and hook descriptors.
- Strict standard-library validator for both `com.hfa.patch/v1` and `com.hfa.feature/v2`.
- Fail-closed unknown extension rule: unknown control/execution kinds require a provider identifier.
- v1 <-> v2 bytePatch bridge for compatibility with the existing v1 consumer path.
- Dragons patch #1 v2 bytePatch example.
- WayOfKings runtimeGraph example covering Damage, Defence, God Mode and Debug Menu.
- Objective-C consumer v2 compatibility patcher.
- Consumer accepts v1 and v2 packages, but v2 playback is currently limited to `control.kind=toggle` + `execution.kind=bytePatch`.
- v2 bytePatch features are normalized in-memory to the existing v1 transaction engine.
- `runtimeState`, `runtimeGraph`, `nativeCall`, and unknown providers remain fail-closed until their executors exist.

## Schema / bridge verification

Local validation: PASS.
Unit tests: 10/10 PASS.
Remote GitHub Actions: PASS.

Schema CI:
- run: `34878393155`
- head: `c4fdd7ed50aaf7059f6d6ca547173ad204ad8217`
- conclusion: `success`
- Validate examples: PASS
- Unit tests: PASS

## Consumer v1.1.0 v2 compatibility build

GitHub Actions:
- run: `34878638733`
- head: `bf67270258d8423d002eb61fb8fc5688306106cf`
- conclusion: `success`

Build verification:
- frozen v1.9.36 generator protection: PASS
- v2 package model validation: PASS
- v2 compatibility source patch: PASS
- consumer invariants / sample-hardcode check: PASS
- arm64 compile/link/sign: PASS
- artifact upload: PASS

Binary:
- `HFAPatchConsumerPlayback_v1.1.0.dylib`
- Mach-O 64-bit arm64 dynamically linked shared library
- SHA256: `a1aa902ab80ec516e359d9acf4714c656828a95eeb6adecaf8acb4c6b2392749`

Artifact:
- name: `HFAPatchConsumerPlayback-v1.1.0-v2-compat`
- artifact ID: `10361259579`
- uploaded ZIP digest: `580982d05316cb49358d6b7cd0c542f8dff39f12b5bc2d43eb86911121752b30`

## Evidence boundary

The v2 schema and the consumer v1.1.0 compatibility binary are build/CI verified. They are **not device-playback verified**.

`HFAPatchConsumerPlayback_v1.1.0` can currently replay v1 packages and v2 `bytePatch` toggle features through the existing fail-closed byte transaction engine. It deliberately refuses WayOfKings `runtimeState`, `runtimeGraph`, and `nativeCall` features until those runtime executors are implemented and verified.

## Next implementation gate

1. independently device-test v1.1.0 against a v2 bytePatch package: preflight -> apply -> readback -> behavior -> restore -> readback -> behavior restore;
2. preserve the same identity/original-byte fail-closed rules;
3. implement runtime graph bootstrap/state/store primitives for WayOfKings;
4. implement capture-field-pointer producers and the shared conditional damage pipeline;
5. implement one-shot `nativeCall` for Debug Menu;
6. build/CI verify; then perform device playback before claiming runtimeGraph support.
