# Earn to Die Rogue 1.28.251 (1) verified profile

## Result

The two features missing from the v1.9.37.10 scan are canonical static byte
patches in `UnityFramework`, not proven runtime-only actions.

| Feature | Preferred Mach-O VM RVA | Original | Enabled |
|---|---:|---|---|
| Unlimited Fuel (`Fuel`) | `0x2D98AC8` | `0038211E` | `1F2003D5` |
| Unlimited Boost (`Boost`) | `0x2D9887C` | `0038281E` | `1F2003D5` |

`1F2003D5` is the little-endian ARM64 encoding of `nop`.

## Build identity gate

This profile is accepted only when all of the following match:

- bundle identifier: `com.notdoppler.earntodierogue`;
- short version: `1.28.251`;
- build version: `1`;
- architecture: `arm64`;
- image: `UnityFramework`;
- Mach-O UUID: `8654D76C-B760-34FC-BEE0-FE70AE8C95C8`;
- Fuel original bytes at `0x2D98AC8`: `0038211E`;
- Boost original bytes at `0x2D9887C`: `0038281E`.

The runtime address is `UnityFramework load base + RVA`. The analyzed image has
preferred `__TEXT` VM address `0x0`, so the RVA and file offset are equal for
both sites.

## IL2CPP mapping and ARM64 evidence

Matching metadata maps both sites into:

```text
Assembly-CSharp.dll
com.notdoppler.ETDR.Car.FixedUpdate()
RVA 0x2D9827C
```

Relevant instance fields:

```text
Car._fuelAmount  +0xB8
Car._boostAmount +0xBC
```

Fuel consumption converges on:

```asm
0x2D98AB8  ldr  s0, [x19, #0xB8]
0x2D98ABC  ldr  s2, [x19, #0xE0]
0x2D98AC0  fmul s2, s8, s2
0x2D98AC4  fmul s1, s2, s1
0x2D98AC8  fsub s0, s0, s1
0x2D98ACC  str  s0, [x19, #0xB8]
```

Boost consumption converges on:

```asm
0x2D98878  ldr  s0, [x19, #0xBC]
0x2D9887C  fsub s0, s0, s8
0x2D98880  str  s0, [x19, #0xBC]
```

Replacing only the subtraction with `nop` preserves the existing store,
comparisons, HUD flow and callbacks while preventing further depletion. It does
not refill a value that was already zero before the patch was enabled.

## Input verification

- analyzed UnityFramework SHA-256:
  `7d19c706d3a2768799a4d1dd452ff0aa327e62221e5d59d88e706ed1347f7b57`;
- matching metadata version: `31`;
- metadata SHA-256:
  `de4eac81ed758381ef929c65d7efddb8592ccaf1dacf9d9f523df8ee1041081b`;
- the two supplied metadata files are byte-identical;
- all 18 pre-existing canonical original-byte records match this image;
- both newly identified original-byte records match this image and the earlier
  supplied UnityFramework at the same RVAs.

## v1.9.37.10 classification defect

The observed menu action is shared by all 14 controls:

```text
AaNfXa -ddktmnuyvBoEK:
EarntoDieRogue.dylib + 0x397098
```

Therefore the presence of an observed action is not sufficient evidence that a
feature uses `runtimeAction`. The v1.9.37.9 exporter classified every observed
action that way, while v1.9.37.10 could append only definitions present in
`gFeatureDefinitions`. The device log contained 14 observed controls but only
12 definitions and 18 mappings, so Fuel and Boost were reintroduced as
runtime-observed records with empty patch arrays.

The verified profile corrects only this exact binary. It does not weaken the
generic canonical truth gates and does not reuse these RVAs for other versions.

## Existing patch overlap

The earlier 12-feature export contains one independent conflict at
`UnityFramework + 0x2E25904`:

- `Unlimited Posters` writes four bytes: `08E0BF12`;
- `Prestige Pass Unlocked` writes eight bytes: `20008052C0035FD6`.

The ranges overlap and toggle order can overwrite the first four bytes. This is
not caused by the Fuel/Boost profile, but it remains a required device-regression
item before the full 14-button package is promoted as conflict-free.

## Validation status

- metadata/binary identity: passed;
- IL2CPP field and method mapping: passed;
- ARM64 instruction/data-flow review: passed;
- static original-byte verification: passed (`20/20` including the new sites);
- repository generation checks: required in CI;
- build/link/sign: pending the next GitHub Actions run;
- device enable/disable regression: pending.
