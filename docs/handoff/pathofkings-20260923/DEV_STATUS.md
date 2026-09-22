# Path of Kings Research — Current Development Status

Date: 2026-09-23
Repository: `a7987083/fenximenu`
Inspected implementation branch: `feature/hfamap-v2.4.2-stripped-menu-static-suite`
Inspected pre-documentation HEAD: `f6849f9b545d1064f2b6fe7787a01bd0b9cc2526`

## Executive status

The Path of Kings sample demonstrates that HFAMap needs to distinguish two execution backends and one discovery backend:

1. `StaticPatchBackend` — APPatch/Jailpatch descriptor -> secret -> module/RVA/bytes -> setActive/memory patch.
2. `RuntimeHookBackend` — target + replacement + original/trampoline, including native function hooks and ObjC/Block variants.
3. `RuntimeDebugResolver` — hardware breakpoint/watchpoint + ARM64 debug state + Mach exception capture, used to discover real executing addresses when static resolution is insufficient.

Runtime Debug should be modeled as a discovery/resolver layer, not treated as equivalent to a byte patch.

## Four visible menu functions currently understood

| menu function | mechanism | current evidence | missing before canonical output |
|---|---|---|---|
| God Mode | Runtime Hook | shared replacement `0x4128`; early return for captured target object | real target-game RVA/module after descriptor decrypt |
| Damage | Runtime Hook | shared replacement `0x4128`; multiply incoming numeric damage | real target-game RVA/module after descriptor decrypt |
| Defence | Runtime Hook | shared replacement `0x4128`; divide incoming numeric damage | real target-game RVA/module after descriptor decrypt |
| Debug Menu | Runtime Debug | breakpoint/watchpoint + Mach exception + ARM64 debug state chain | exact high-level action parameter mapping and device validation |

Do not interpret “4 menus understood” as “4 final canonical offsets/patches recovered.”

## Native hook registration state

| descriptor | replacement | original storage | status |
|---|---:|---:|---|
| `0x4B6848` | `0x4128` | `0x543CB8` | registration recovered; target plaintext pending |
| `0x4B6870` | `0x4050` | `0x543CA8` | registration recovered; target plaintext pending |
| `0x4B6898` | `0x40BC` | `0x543CB0` | registration recovered; target plaintext pending |

All three descriptors are `0x28` bytes with observed `len=0x0A`, `flags=0x01031211`. Their plaintext is parsed by the tweak as a `0x...` hexadecimal RVA string.

## Secret/decrypt state

Confirmed:

- stable `secret` getter IMP: `0x2117A0`
- real decrypt core: `0x2129A4`
- descriptor key slot: `1`
- key slot is runtime-provisioned, not a simple static on-disk key
- AES-128-style key expansion/block-decrypt path identified

Current HFAMap v2.4.2 limitation:

- `HFADecryptWrapper()` still uses `decryptAddress = getter + 0xD00`;
- this resolves to `0x2124A0` for the sample and is wrong;
- source only has a dedicated `HFAProbeKey2Path()` special case;
- Path of Kings descriptors need slot `1`;
- no generic key-slot/decrypt-callgraph resolver exists yet.

## Recommended next implementation

Target next version conceptually:

`GenericSecretDecryptResolver + GenericKeySlotResolver + NativeHookResolver`

Required behavior:

1. Observe/resolve the real decrypt function structurally (callgraph/fingerprint/caller relation), not `getter + fixed_delta`.
2. Read descriptor `len`, `flags`, and `slot = flags >> 24` generically.
3. Prefer observing successful runtime decrypt output rather than copying/reimplementing per-build AES logic when possible.
4. Validate plaintext strictly as expected semantic data (`0x[0-9A-Fa-f]+` for target RVA descriptors).
5. Bind the resulting target RVA to module/image base, replacement RVA and original/trampoline storage.
6. Keep all unresolved candidates `analysisOnly=true` / noncanonical until target identity and runtime evidence are complete.

Suggested logging:

- `[DECRYPT-CANDIDATE]`
- `[KEY-SLOT]`
- `[DECRYPT-CALL]`
- `[DECRYPT-VERIFY]`
- `[NATIVE-HOOK]`
- `[HW-HIT]`

## Validation gates before claiming success

Must obtain at least one real device run that proves:

- slot-1 descriptor decrypt output is captured;
- three target plaintext RVAs are valid;
- module/image base resolution is correct;
- target addresses are executable/readable as expected;
- replacement/original mapping matches the recovered registration site;
- no crash/regression from runtime observation;
- cleanup/restore is complete for any temporary instrumentation.

Current strict state:

- research complete enough to design next resolver: YES
- v2.4.2 source already supports Path of Kings slot-1 path: NO
- implementation committed: NO
- CI compiled: NO
- device validated: NO
- exact three target-game RVAs: PENDING
