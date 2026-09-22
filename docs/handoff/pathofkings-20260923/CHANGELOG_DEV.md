# Path of Kings / HFAMap Research Changelog — 2026-09-23

## Scope

This record covers the reverse-analysis session for the user-supplied Path of Kings tweak samples and its implications for HFAMap. It is an analysis/hand-off record, not a claim that the findings are already implemented or device-validated in HFAMap.

Repository: `a7987083/fenximenu`
Current inspected branch: `feature/hfamap-v2.4.2-stripped-menu-static-suite`
Inspected branch HEAD before this documentation commit: `f6849f9b545d1064f2b6fe7787a01bd0b9cc2526`

## Inputs

- Standalone tweak: `libpathofkings.dylib`
  - SHA256: `a7775bcd7ed38a799c2ba0d1c2dd2588d5cd2c15853d943a059d914f96f37ed6`
  - size: `5749821`
- DEB: `Path of Kings 1.4.1 Jailbreak iOS Hack by iOSGods.com.deb`
  - SHA256: `34a8df5856ffbf57dde51e1d04813c67f68684b82ad155f672db73da43cf580f`
  - embedded dylib: `/Library/MobileSubstrate/DynamicLibraries/pathofkings.dylib`
  - embedded dylib SHA256: `060d9850b4c17d45341f91488737384c9bbf2dcbf4821c3a6ad5d9894a77edf0`
  - embedded dylib size: `5693664`
  - MobileSubstrate filter bundle: `com.TornadoBear.WayOfKings`

The standalone and DEB dylibs are different builds, but their important Mach-O layout and stable runtime structures are highly similar. Obfuscated ObjC class/selector names vary; stable selectors/IMPs and execution structure were used for cross-checking.

## Research timeline / findings

### 1. Three functional mechanisms were separated

The tweak does not use one universal mechanism. Evidence supports three layers:

1. `Static Patch` — APPatch/Jailpatch-style descriptor + `secret` + `setActive:` + memory patch backend.
2. `Runtime Hook` — native target/replacement/original-trampoline style hooks, including an MSHookFunction-capable backend.
3. `Runtime Debug` — hardware breakpoint/watchpoint + ARM64 debug state + Mach exception handling, best treated as a discovery/resolver layer rather than a patch backend.

Recommended HFAMap architecture:

- Execution backend A: `StaticPatchBackend`
- Execution backend B: `RuntimeHookBackend`
- Discovery backend: `RuntimeDebugResolver`

### 2. God Mode / Damage / Defence share one native replacement

The feature strings `God Mode`, `Damage` and `Defence` all lead into replacement RVA `0x4128` in the tweak.

Observed behavior in that replacement:

- `God Mode`: for a captured target/player object, enabled state causes an early return, skipping the original damage path.
- `Damage`: modifies an incoming numeric damage parameter via multiplication before tail-calling the original.
- `Defence`: modifies the incoming damage parameter via division before continuing to the original.

This is not three independent `offset + patch bytes` records. It is a shared native runtime-hook path.

### 3. Three related hook registrations were recovered

The registration site around `0x4304` builds three hook registrations:

| target descriptor | replacement RVA | original/trampoline storage |
|---|---:|---:|
| `0x4B6848` | `0x4128` | `0x543CB8` |
| `0x4B6870` | `0x4050` | `0x543CA8` |
| `0x4B6898` | `0x40BC` | `0x543CB0` |

Important interpretation:

- `0x4128`, `0x4050`, `0x40BC` are replacement RVAs inside the tweak, not target-game RVAs.
- `0x543CB8`, `0x543CA8`, `0x543CB0` are storage slots for original/trampoline pointers, not target-game RVAs.
- `0x4B6848`, `0x4B6870`, `0x4B6898` are encrypted/opaque target descriptors, not target-game RVAs.

### 4. The two helper replacements feed the shared damage logic

`0x4050` captures an object-related pointer from roughly `x0 + 0x50` into a bounded global object table before continuing to its original.

`0x40BC` captures an object-related pointer from roughly `x0 + 0x38` into the same logical table before continuing to its original.

`0x4128` checks whether its current object belongs to that captured set before applying God Mode / Defence behavior. This explains why the three hooks work together.

### 5. The target descriptor format and plaintext semantics were recovered

Each target descriptor is `0x28` bytes and has the observed shape:

```c
struct SecretDescriptor {
    uint32_t plaintextLength;  // 0x0A
    uint32_t flags;            // 0x01031211
    uint8_t  iv[16];           // +0x08
    uint8_t  ciphertext[16];   // +0x18
};
```

The hook controller validates decrypted plaintext as a hexadecimal string beginning with `0x`, converts it to a numeric RVA, obtains an image base, and computes:

`absoluteTarget = imageBase + RVA`

The three descriptors have `plaintextLength = 10`, consistent with a 9-character `0x.......` string plus NUL. Do not infer the exact target RVAs from length alone.

### 6. Real decrypt routine identified; old fixed-delta model disproved

Stable `secret` getter IMP:

- `secret` IMP RVA: `0x2117A0`
- body: loads pointer from object `+0x10`, then returns.

Real descriptor decrypt routine:

- `0x2129A4`

Current HFAMap v2.4.2 `HFADecryptWrapper()` still computes:

`decryptAddress = getter + 0xD00`

For this sample:

- getter = `0x2117A0`
- getter + `0xD00` = `0x2124A0`
- `0x2124A0` fails the current fixed fingerprint and is not the real decrypt entry.

Therefore the current fixed `getter + 0xD00` relationship is not a valid general rule for this sample.

### 7. Encryption/key path narrowed to runtime key slot #1

Reverse analysis identified an AES-128-style path:

- AES-128 key expansion-like routine: `0x2117A8`
- block-decrypt helper: `0x212520`
- key registration routine: `0x213A2C`
- key fetch routine: `0x213AE4`
- key slot table base: `0x5443C0`

For flags `0x01031211`:

`flags >> 24 == 1`

Therefore these descriptors use runtime key slot `1` (logical slot storage at `0x5443C8` for this build).

The slot table resides in zero-initialized runtime storage/BSS. The actual slot-1 key is provisioned at runtime and is not present as a simple static 16-byte constant in the on-disk dylib.

This explains why static offline analysis can recover algorithm, IV, ciphertext and key-slot selection but cannot honestly emit the three target RVAs without either recovering the runtime key provisioning source or observing real runtime decrypt output.

### 8. HFAMap v2.4.2 was checked, not assumed

Latest inspected branch: `feature/hfamap-v2.4.2-stripped-menu-static-suite`.

`HFAMapPatchExecutionTrace.m` still has the same relevant blob as the inspected 2.4.1 path (`d486d48824443965d4fad789bd99724ae568adcb`) and still declares/uses only the dedicated `HFAProbeKey2Path(...)` special case.

Current source behavior:

- reads descriptor `len` and `flags`;
- can derive key-slot number from the high byte;
- has a slot-2-specific probe path;
- still derives decrypt routine using `getter + 0xD00`;
- does not have a generic `HFAProbeKeySlot(slot, ...)` / slot-1 resolver.

Therefore v2.4.2 does not currently close this Path of Kings target-decrypt path.

### 9. Runtime Debug backend is real and independent

Static evidence identifies a hardware-debug chain using APIs such as:

- `task_set_exception_ports`
- `mach_msg` / `mach_msg_overwrite`
- `thread_get_state`
- `thread_set_state`
- thread creation/enumeration support

Useful tweak RVAs recovered during this analysis:

- exception/debug installer: `0x11A354`
- exception callback/thunk: `0xFF08C`
- exception receiver/thread area: approximately `0x11A670`
- debug-state configurator: `0x124D20`
- WatchpointRegister-related area: `0x120FE0`
- BreakpointRegister-related area: `0x12117C`
- watchpoint cooldown-related area: `0x1263D8`

Strings/classes include `WatchpointRegister`, `BreakpointRegister`, `HardwareDebugger.DebugRegister`, `SwiftHooks.BreakpointHookController`, `HardwareBreakpointHookController`, `breakpoint-instruction`, `breakpoint-hardware` and `com.gamegod.hardware-watchpoint-cooldown`.

This supports using Runtime Debug as a future generic discovery mechanism for PC/LR/RVA capture when static resolution is insufficient.

## Corrections made during the session

- An early candidate around `0x211CA4` was considered and then rejected after disassembly; it must not be recorded as a decrypt/method entry.
- `0x543CB8` was clarified as an original/trampoline storage slot, not a target RVA.
- `0x4128` is the tweak replacement RVA, not the target game RVA.
- The three `0x4B68xx` addresses are target descriptor storage, not target RVAs.
- Do not replace `getter + 0xD00` with another fixed delta such as `+0x1204`; that would merely create a new per-sample hardcode.

## Strict state at end of research

- Static reverse-analysis evidence: strong for the chains above.
- Cross-build structural comparison: performed between standalone and DEB dylibs.
- HFAMap source inspection: performed on v2.4.2 branch.
- Source implementation of a new generic resolver: NOT done in this research record.
- CI build of a resolver change: NOT done.
- Device validation of slot-1 capture/decrypt: NOT done.
- Exact three target-game RVAs: NOT yet recovered.
