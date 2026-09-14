from pathlib import Path

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
legacy = legacy_path.read_text()


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)

# v1.9.36.2 deliberately preserves the v1.9.36 startup path, scan body,
# resolver/decrypt logic and all runtime probes. It only calls an analysis-only
# serializer after run_full_scan() has finished and existing exporters have had
# a chance to write their canonical/diagnostic JSON files.
macro_anchor = '#define M0(r,o,s)'
legacy = once(
    legacy,
    macro_anchor,
    'extern BOOL HFAMapJSONExportLatest(void);\n' + macro_anchor,
    'declare JSON exporter',
)

legacy = once(
    legacy,
    'unsigned int valid=run_full_scan();',
    'unsigned int valid=run_full_scan();(void)HFAMapJSONExportLatest();',
    'export normalized analysis JSON after scan',
)

legacy = once(
    legacy,
    'HFAMap v1.9.36 Architecture Truth',
    'HFAMap v1.9.36.2 JSON Export',
    'update visible panel title',
)
legacy = once(
    legacy,
    'Strict static-patch contract + target-derived architecture identity.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'Stable v1.9.36 parser + analysis-only JSON export.\\nNo playback engine, no Dobby, no runtime takeover.',
    'update visible panel help',
)

legacy_path.write_text(legacy)
print('patched HFAMap v1.9.36.2 JSONExport integration')
