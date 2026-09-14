# HFA Feature v2 development status

Branch reserved on GitHub: `feature/hfa-feature-v2-unified-schema`.

## Implemented locally

- `com.hfa.feature/v2` additive schema.
- Control/execution separation.
- Core controls: toggle, number, slider, button/action, choice/multiChoice, text.
- Core execution kinds: bytePatch, runtimeState, runtimeGraph, nativeCall.
- Runtime graph structure with state, stores and hook descriptors.
- Strict standard-library validator for both `com.hfa.patch/v1` and `com.hfa.feature/v2`.
- Fail-closed unknown extension rule: unknown control/execution kinds require a provider identifier.
- v1 <-> v2 bytePatch bridge for compatibility with the existing v1 consumer path.
- Real Dragons patch #1 v2 bytePatch example.
- WayOfKings runtimeGraph example covering Damage, Defence, God Mode and Debug Menu.
- GitHub Actions workflow for example validation and unit tests.

## Verification

Local validation: PASS.
Unit tests: 10/10 PASS.

## GitHub state

The earlier email-verification blocker has been resolved by the repository owner. This suite is prepared for commit to `feature/hfa-feature-v2-unified-schema`; remote CI status is tracked separately and must not be inferred from local tests.

## Next implementation gate

1. commit this schema/validator/bridge suite;
2. run GitHub Actions;
3. add Objective-C v2 package parsing to `HFAPatchConsumerPlayback`;
4. normalize v2 `bytePatch` features onto the existing v1 transaction engine;
5. fail closed on runtimeState/runtimeGraph/nativeCall until their executors exist;
6. then implement WayOfKings runtime graph execution separately.
