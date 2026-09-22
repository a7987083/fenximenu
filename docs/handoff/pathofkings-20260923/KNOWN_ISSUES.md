# Path of Kings / HFAMap — Known Issues and Failure Modes

Date: 2026-09-23

## K1 — HFAMap uses an invalid fixed decrypt-address relation for this sample

Current v2.4.2 code derives:

`decryptAddress = secretGetterIMP + 0xD00`

Observed Path of Kings:

- getter: `0x2117A0`
- fixed-delta candidate: `0x2124A0`
- real decrypt routine: `0x2129A4`

Impact: current fingerprint check skips the descriptor and target plaintext is not recovered.

Required fix: structural/callgraph-based decrypt resolver. Do not replace `+0xD00` with another sample-specific constant.

## K2 — Key-slot implementation is special-cased to slot 2

Current source exposes/uses `HFAProbeKey2Path(...)` only for `flags >> 24 == 2`.

Path of Kings uses:

`flags = 0x01031211 -> slot 1`

Impact: the current special case cannot help these three native-hook target descriptors.

Required fix: generic `slot = flags >> 24` resolver and runtime key/decrypt observation for slot 1/2/N.

## K3 — Runtime AES key is not a simple on-disk constant

Observed key table is runtime storage/BSS around `0x5443C0`; slot 1 is populated dynamically through a registration path around `0x213A2C` and fetched around `0x213AE4`.

Impact: offline file-only AES decryption cannot honestly finish without recovering provisioning or observing runtime decrypt output.

Do not fabricate a key from IV/ciphertext/format constraints.

## K4 — Tweak replacement addresses are easy to mislabel as target-game offsets

Known replacements:

- `0x4128`
- `0x4050`
- `0x40BC`

These are inside `libpathofkings.dylib` and are not target-game RVAs.

Similarly, `0x543CB8`, `0x543CA8`, `0x543CB0` are original/trampoline storage slots.

Impact: naïve export would produce invalid “game offsets.”

Required gate: every target address must carry image identity and provenance.

## K5 — Descriptor addresses are not target RVAs

`0x4B6848`, `0x4B6870`, `0x4B6898` hold encrypted descriptor records. They must be decrypted and resolved relative to a target image base.

Impact: directly exporting these addresses would be wrong.

## K6 — Ciphertext is randomized across related builds

Standalone and DEB dylibs keep matching descriptor structure/flags but use different encrypted bytes/IVs.

Impact: ciphertext hashes or exact bytes are unsuitable as a universal feature identity.

Preferred identity: stable structural/callgraph/selector/IMP semantics plus module UUID/build evidence.

## K7 — Obfuscated ObjC names vary across builds

Related builds showed randomized class/selector identifiers while stable items such as `secret`, `setActive:`, key IMP locations and functional call patterns persisted.

Impact: name-based matching alone is fragile.

Preferred resolver: runtime metadata + stable selector/type/IMP + bounded ARM64/callgraph evidence.

## K8 — Four menu functions are understood, but four canonical outputs are NOT available

Current understanding:

- God Mode -> Runtime Hook path
- Damage -> Runtime Hook path
- Defence -> Runtime Hook path
- Debug Menu -> Runtime Debug path

Missing:

- exact three target-game RVAs for the native hooks;
- device evidence proving slot-1 decrypt capture;
- full Debug Menu action-parameter mapping.

Impact: do not report “4/4 offsets recovered.”

## K9 — Runtime Debug is a discovery layer, not automatically a patch backend

Hardware breakpoint/watchpoint hits can identify PC/LR/RVA but do not alone prove patch bytes or stable method semantics.

Required follow-up after a hit:

- image/UUID resolution;
- function-boundary/callsite analysis;
- method/symbol/metadata correlation when available;
- determine whether final implementation is static patch, ObjC hook, native hook or block/dispatcher.

## K10 — Historical false candidate `0x211CA4`

An early analysis hypothesis considered an address around `0x211CA4`; disassembly showed it was not the correct function/decrypt entry.

Impact: this address must not be revived from conversational history.

Authoritative decrypt routine for the current analyzed build is `0x2129A4`.

## K11 — Current findings are static/reverse evidence, not new device validation

No new HFAMap resolver was implemented, CI-built, or run on device during this research session.

Required wording:

- “identified/recovered in static reverse analysis” — acceptable;
- “implemented” — only after source changes;
- “compiled/CI pass” — only after a build run;
- “device verified” — only after real logs/runtime evidence.

## K12 — Debug subsystem addresses are build-specific RVAs

Recovered debug RVAs (`0x11A354`, `0xFF08C`, `0x124D20`, etc.) are evidence for this tweak build. They must not become global hardcoded constants in HFAMap.

Preferred implementation: identify by structural behavior and imported Mach/debug APIs, then bind per image/build.
