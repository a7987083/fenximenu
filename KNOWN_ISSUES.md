# Known Issues

## Current parser-only line: v1.9.36.3 JSONExport

### v1.9.36.3 device validation is still pending

Status: open / primary validation gate.

The build preserves the v1.9.36 constructor, `run_full_scan()` and resolver core, and CI confirms no Dobby or HFAPatchConsumer linkage. It adds only analysis-layer normalization and read-only target image identity. Device evidence is still required before v1.9.36.3 can be called runtime-confirmed.

### Debug Menu was mis-normalized in v1.9.36.1

Status: confirmed defect / fixed in v1.9.36.2+ / device confirmation pending.

WayOfKings device output proved the raw control type is `kTypeButton`. v1.9.36.1 only recognized `button`, so `Debug Menu` became `control.kind = unknown`. v1.9.36.2+ maps the observed exact source type `kTypeButton` to `button` without changing the underlying resolver evidence.

### Raw source primitive can differ from normalized UI semantics

Status: intentional evidence policy.

The original iGMM diagnostic writer classified the observed Debug Menu record as `executionPrimitive = nativeHook`, while its runtime implementation evidence shows `kind = buttonBlock` with a block handler and one resolved target. v1.9.36.3 does not rewrite or hide the raw source primitive. Instead it adds `normalizedExecutionPrimitive = runtimeAction` in the normalized analysis JSON. Consumers must treat the raw field as source evidence and the normalized field as the analysis-layer interpretation.

### Target identities are analysis evidence, not an execution authorization

Status: permanent rule.

v1.9.36.3 adds read-only UUID/architecture/filetype/preferred-`__TEXT`/cryptid records for images referenced by the generated diagnostics. This is for build matching and analysis quality only. It must not be interpreted as permission to install hooks or execute a generated package.

### iGMM runtime features remain non-canonical static patches

Status: intentional / device behavior confirmed.

WayOfKings uses runtime numeric/native-hook/block behavior. These records remain diagnostic and analysis-only. They are not converted into fabricated `target/offset/original/enabled` static patches.

### v1.9.37 and v1.9.37.1 are retired from the HFAMapUniversal parser mainline

Status: confirmed device startup failure / architecture direction reverted.

Those builds merged the independent playback/runtime consumer and Dobby into the same HFAMapUniversal dylib. Both builds crashed immediately when injected on device. The exact crash instruction has not been established because no `.ips` crash report was supplied, but the product-direction issue is resolved: HFAMapUniversal remains a parser/exporter and no longer embeds that execution engine.

### Stale generated files can confuse device validation

Status: test-environment hazard.

Before testing a new parser version, archive or remove old `*.hfamap.analysis.json`, `*.hfamap.igmm.json`, `*.hfapatch.json`, `*.hfapatch.identity.json`, and old playback logs. Otherwise a prior result can be mistaken for the current scan.

### Canonical structural validity is not sufficient

Status: permanent verification rule.

A static package is trusted only when structure, target identity and original-byte truth all agree. Preferred Mach-O VM address semantics remain required for canonical offsets.

### Original-byte fallback branches remain incompletely runtime-exercised

Status: open.

The v1.9.33 multi-source original-byte readers remain part of the frozen parser core. Their fallback branches still need dedicated runtime evidence on samples where the preferred read path is unavailable.

### Current binary has not yet been regression-tested across all menu families

Status: open.

- WayOfKings/iGMM: v1.9.36.1 parser/export path device-confirmed; v1.9.36.3 pending.
- Runtime-record/static 5 MB family: current v1.9.36.3 regression pending.
- Legacy ~15 MB family: current v1.9.36.3 regression pending.

Do not claim universal coverage until the current parser-only binary passes all three families.

## Current CI delivery

Authoritative candidate:

- binary: `HFAMapUniversal_v1.9.36.3_JSONExport.dylib`
- run: `34906163687`
- artifact: `10372078251`
- binary SHA256: `5078c75833b246067ec3b8c3342db62c06ef80d1fa890363769290549239a546`
- artifact digest: `sha256:f9a3da845862e535dbad8007b1b243fcb87db3de37adf1ee69cc2b275514f3ed`
