# HFAMap Path of Kings — Full Handoff

## Read this first

This file is intended for another GPT/engineer taking over the exact research state from the 2026-09-23 session. Do not restart from menu strings only. The important chains have already been separated and several tempting but wrong address interpretations were corrected.

## What triggered this work

The user supplied two Path of Kings tweak artifacts and asked whether HFAMap could recover either:

- static `offset + patch bytes`, or
- method/function hook information.

The analysis showed the tweak contains both styles plus a third hardware-debug discovery subsystem. The immediate goal became determining how God Mode/Damage/Defence are actually implemented and why current HFAMap does not emit their final target RVA.

## Artifacts

Standalone:

- `libpathofkings.dylib`
- SHA256 `a7775bcd7ed38a799c2ba0d1c2dd2588d5cd2c15853d943a059d914f96f37ed6`
- size `5749821`

DEB:

- `Path of Kings 1.4.1 Jailbreak iOS Hack by iOSGods.com.deb`
- SHA256 `34a8df5856ffbf57dde51e1d04813c67f68684b82ad155f672db73da43cf580f`
- embedded `/Library/MobileSubstrate/DynamicLibraries/pathofkings.dylib`
- embedded SHA256 `060d9850b4c17d45341f91488737384c9bbf2dcbf4821c3a6ad5d9894a77edf0`
- filter bundle `com.TornadoBear.WayOfKings`

The dylibs are not byte-identical. They appear to be related builds with randomized/obfuscated names but stable important structures. This is useful for identifying structural invariants rather than hardcoding names or ciphertext.

## Stable Mach-O/runtime observations

Important strings/selectors observed include:

- `God Mode`
- `Damage`
- `Defence`
- `setActive:`
- `secret`
- `MSHookFunction`
- `MSHookMemory`
- APPatch/Jailpatch/MemoryPatcher-related identifiers
- `WatchpointRegister`
- `BreakpointRegister`
- `HardwareDebugger.DebugRegister`

Stable `secret` getter:

```asm
0x2117A0: LDR X0, [X0,#0x10]
0x2117A4: RET
```

Interpretation: wrapper `secret` returns an opaque descriptor pointer stored at object offset `+0x10`.

## Architecture learned from the tweak

Use this conceptual model:

```text
                         HFAMap
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
   Static Patch       Runtime Hook      Runtime Debug
          |                |                |
   offset + bytes    target/replacement     +-- breakpoint
   APPatch           original/trampoline    +-- watchpoint
   secret            ObjC/native/block      +-- ARM debug state
   setActive:                            Mach exception
                                               |
                                               v
                                      discover PC/LR/RVA
```

Runtime Debug is primarily a resolver/discovery backend. Its output can later be classified as a Static Patch target or Runtime Hook target.

## God Mode / Damage / Defence native-hook chain

### Shared replacement

Replacement RVA: `0x4128`

The replacement checks whether the current object matches a previously captured object set. Then:

- God Mode enabled -> early return, skipping original damage processing.
- Damage path -> multiply incoming numeric damage value by configured multiplier.
- Defence path -> divide incoming damage by configured multiplier.
- otherwise/tail path -> continue to original/trampoline.

Therefore God Mode, Damage and Defence are not three independent byte patches in this sample.

### Two supporting capture hooks

Replacement `0x4050`:

- reads a pointer around `x0 + 0x50`;
- stores it into a bounded global target-object table;
- tail-calls its original via slot `0x543CA8`.

Replacement `0x40BC`:

- reads a pointer around `x0 + 0x38`;
- stores it into the same logical target-object table;
- tail-calls its original via slot `0x543CB0`.

Main replacement `0x4128` uses the captured set and tails to original storage `0x543CB8` when appropriate.

### Registration tuples

Recovered around hook installer/registration code near `0x4304`:

```text
descriptor 0x4B6848 -> replacement 0x4128 -> original slot 0x543CB8
descriptor 0x4B6870 -> replacement 0x4050 -> original slot 0x543CA8
descriptor 0x4B6898 -> replacement 0x40BC -> original slot 0x543CB0
```

Do not confuse:

- descriptor address with target RVA;
- replacement RVA with target RVA;
- original storage slot with target RVA.

## Hook-controller/decrypt path

The recovered high-level chain is:

```text
encrypted target descriptor
    -> wrapper/secret
    -> Hook controller around 0x35BE08
    -> async/processing block around 0x35B940
    -> decrypt core 0x2129A4
    -> plaintext "0x......."
    -> hex string to uint64 RVA
    -> image base resolver
    -> imageBase + RVA
    -> lower Hook engine
```

Additional controller layers observed during the trace include areas around `0x35B84C`, `0x35B754`, `0x2E2234`, `0x2E53D0`. Treat exact semantic names as unresolved/obfuscated; the call-chain role is more reliable than class/selector spelling.

## Descriptor format

For the three native hook targets:

- size: `0x28`
- `len = 0x0A`
- `flags = 0x01031211`

Observed shape:

```c
struct SecretDescriptor {
    uint32_t plaintextLength;
    uint32_t flags;
    uint8_t  iv[16];
    uint8_t  ciphertext[16];
};
```

The standalone and DEB builds keep the same `len/flags` but use different IV/ciphertext bytes. Therefore ciphertext/hash must never be used as a universal identity.

The post-decrypt controller validates text beginning with `0x` and converts hex digits to a numeric target RVA. Thus the plaintext semantics are known even though the exact three values are not yet available.

## Why exact target RVAs are still missing

Real decrypt core: `0x2129A4`.

The descriptor flags select key slot using the high byte:

```text
0x01031211 >> 24 = 1
```

Related routines/locations recovered:

- key schedule-like AES-128 routine: `0x2117A8`
- block decrypt helper: `0x212520`
- register key slot: `0x213A2C`
- fetch key slot: `0x213AE4`
- key table base: `0x5443C0`
- logical slot-1 entry: `0x5443C8`

The key table is runtime/BSS storage. Slot 1 is populated dynamically. The on-disk dylib gives us algorithm, IV, ciphertext and slot number, but not a simple static key value that can be safely read from file bytes.

Therefore, without runtime key provisioning evidence or observing the real decrypt call, emitting the three plaintext target RVAs would be guessing.

## Why HFAMap 2.4.2 currently misses it

Inspected branch:

`feature/hfamap-v2.4.2-stripped-menu-static-suite`

Pre-documentation HEAD:

`f6849f9b545d1064f2b6fe7787a01bd0b9cc2526`

Relevant file:

`hfamap/src/HFAMapPatchExecutionTrace.m`

The relevant source still:

```c
IMP getter = method_getImplementation(getterMethod);
uintptr_t decryptAddress = (uintptr_t)getter + 0xD00u;
```

For this sample:

```text
secret getter = 0x2117A0
computed candidate = 0x2124A0
real decrypt core = 0x2129A4
```

The source also has a dedicated `HFAProbeKey2Path()` path only for `flags >> 24 == 2`. Path of Kings needs key slot `1`. Therefore v2.4.2 does not currently have the required generic slot-1/callgraph resolver.

Do not “fix” this by changing `+0xD00` to `+0x1204`. That would just replace one hardcoded relation with another.

## Runtime Debug subsystem

The tweak contains a separate hardware-debug engine using Mach exception and ARM64 debug state facilities.

Recovered evidence includes APIs such as:

- `task_set_exception_ports`
- `mach_msg` / `mach_msg_overwrite`
- `thread_get_state`
- `thread_set_state`
- task/thread enumeration/creation support

Useful RVAs for this build:

```text
0x11A354  debug/exception installer
0xFF08C   exception callback/thunk
~0x11A670 exception receiver/thread area
0x124D20  debug-state configuration helper
0x120FE0  WatchpointRegister-related path
0x12117C  BreakpointRegister-related path
0x1263D8  hardware-watchpoint cooldown-related path
```

Strings show both software/instruction and hardware breakpoint concepts. This strongly supports using such a backend for runtime PC/LR/RVA capture instead of high-frequency memory polling when implementing a generic discovery mode.

## Corrections / do-not-repeat mistakes

1. An early `0x211CA4` candidate was rejected after disassembly. Do not reuse it as a function/decrypt entry.
2. `0x543CB8` is original/trampoline pointer storage, not target RVA.
3. `0x4128` is a replacement handler inside the tweak, not target RVA.
4. `0x4B6848/70/98` are descriptor addresses, not target RVAs.
5. Do not infer exact target RVA from `len=10`.
6. Do not use randomized ObjC class/selector names as primary cross-build identity.
7. Do not treat fixed ciphertext as stable across builds.
8. Do not call CI/static reverse evidence “device verified.”

## Next engineering task

Build a generic resolver, preferably as a new version after v2.4.2:

### A. GenericSecretDecryptResolver

- find decrypt via bounded structural/callgraph evidence;
- keep old fingerprint only as a candidate signal, never sole authority;
- derive `slot = flags >> 24` generically;
- observe successful runtime decrypt output when possible;
- validate plaintext by context (`0x...` for hook target descriptors).

### B. GenericKeySlotResolver

- support slot 1/2/N, not `HFAProbeKey2Path()` only;
- record slot registration/provisioning evidence without hardcoding a key;
- fail closed if slot/key lifetime is unresolved.

### C. NativeHookResolver

Produce an analysis record equivalent to:

```text
module/image = ?
targetRVA = decrypted target descriptor
replacementRVA = 0x4128 (or 0x4050/0x40BC)
originalSlotRVA = 0x543CB8 (or CA8/CB0)
```

Only promote to canonical when target identity and runtime evidence are valid.

### D. RuntimeDebugResolver (later/parallel)

Use breakpoint/watchpoint hits to produce bounded records of:

- image identity
- PC/RVA
- LR/RVA
- relevant register snapshot
- trigger reason
- cleanup/restore result

## Required device validation

Minimum useful Path of Kings validation session:

1. Inject a build containing only bounded observation/resolver changes.
2. Capture successful decrypt invocation(s) for the three target descriptors.
3. Log plaintext without altering original secret memory.
4. Confirm all three plaintext values are valid `0x...` RVAs.
5. Resolve target image/module and executable range.
6. Confirm replacement/original tuples match registration evidence.
7. If temporary hooks/breakpoints are used, verify restore/cleanup count is zero failures.
8. Preserve raw logs so another analyst can reproduce the mapping.

## Strict handoff state

At the time of this document:

- reverse research: completed to resolver-design level;
- exact three target plaintext RVAs: pending runtime key/decrypt evidence;
- HFAMap v2.4.2 implementation change: not made;
- commit for resolver: none;
- CI for resolver: none;
- device validation for resolver: none.

The next GPT should continue from the runtime decrypt/key-slot resolver problem, not restart by searching `God Mode` strings.
