# HFAPatch Consumer Playback

Independent fail-closed playback validator for `com.hfa.patch/v1` packages produced by HFAMapUniversal.

This module is deliberately separate from the v1.9.36 generator. It does not discover or generate mappings. It only consumes an already-generated canonical package plus its `com.hfa.patch.identity/v1` sidecar.

## Files in app Documents

Place these files in the target app's `Documents/` directory:

- the generated `*.hfapatch.json` package;
- the matching `*.hfapatch.identity.json` sidecar;
- `HFAPatchPlayback.command.json` when you want one operation to run.

The consumer writes:

- `HFAPatchPlayback.log` — append-only evidence log;
- `HFAPatchPlayback.result.json` — result of the most recent command;
- `HFAPatchPlayback.command.last.json` — exact consumed command.

The command file is atomically claimed/renamed before execution. A serial 1-second poller allows `apply` and `restore` to be issued in the same game process.

## Command format

```json
{
  "action": "preflight",
  "package": "com.example.game_1.0_1.hfapatch.json",
  "identity": "com.example.game_1.0_1.hfapatch.identity.json",
  "featureIds": ["0"]
}
```

`identity` may be omitted when it uses the standard adjacent filename derived from `*.hfapatch.json`.

Actions:

- `preflight`: verify app package metadata, target identity and every selected patch's current bytes against `original`; write nothing;
- `apply`: require every selected patch to equal `original`, write `enabled`, then read back and verify every write;
- `restore`: require every selected patch to equal `enabled`, write `original`, then read back and verify every write.

If `featureIds` is omitted or empty, every feature is selected. For device validation, test one feature at a time first.

## Fail-closed rules

No write occurs unless all selected patches first pass:

1. canonical schema is exactly `com.hfa.patch/v1`;
2. bundle identifier, short version and build version match the running app when populated;
3. identity sidecar is `com.hfa.patch.identity/v1` with `preferred-mach-o-vmaddr` semantics;
4. sidecar package metadata matches the canonical package;
5. target image resolves to a loaded image;
6. UUID, image name, ARM64 architecture, cputype, cpusubtype, preferred `__TEXT` VM address and cryptid match the sidecar;
7. offset parses as a preferred Mach-O VM address;
8. `original` and `enabled` are valid equal-length hex blobs;
9. every selected address is unique;
10. current memory bytes match the required pre-state (`original` for preflight/apply; `enabled` for restore).

Writes are transactional per command. If a write or readback verification fails, already-written patches are best-effort rolled back to their pre-command bytes and the command fails.

## Device validation sequence

For the current Dragons runtime-record package:

1. inject **only** this consumer into the matching game build for independent playback;
2. copy the known-good package and identity sidecar into `Documents/`;
3. submit `preflight` for feature `0`; result must pass;
4. submit `apply` for feature `0`; result must pass and gameplay behavior must be checked manually;
5. while the same process stays alive, submit `restore` for feature `0`; result must pass and gameplay behavior must return to baseline;
6. repeat for feature `1`, then feature `2`;
7. return `HFAPatchPlayback.log`, the result files, and the consumed command files for evidence review.

The consumer proves identity/byte/apply/revert mechanics. Gameplay semantic confirmation remains a human/device observation and must not be inferred from a successful byte write alone.
