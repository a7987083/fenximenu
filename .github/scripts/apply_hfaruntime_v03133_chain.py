from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03132_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03133_pagezero_rva_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
v02=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    'HFA03133CanonicalTarget',
    'realSegment=strcmp(seg->segname,"__PAGEZERO")!=0',
    '[V03133-RVA-NORMALIZE]',
    '[V03133-MAIN-IMAGE]',
    '[V03133-ANALYZER-PREPASS]',
    '[V03133-LEDGER-BRIDGE]',
    '[V03133-STATIC-CANONICAL]',
    'uuid+rva+original+enabled',
    'HFAMap_StaticCanonical_v03133.json',
]:
    if required not in trace: raise SystemExit('v03133 generated trace missing '+required)
for required in ['HFAAnalyzerV02BeginExportEpoch','HFAAnalyzerV02ScanSelectedImageImpl','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if required not in v02: raise SystemExit('v03133 single-pass regression '+required)
if 'strcmp(value, "main") == 0) return 0;' in trace:
    raise SystemExit('v03133 stale main index-0 assumption remains')
if 'HFAMap RuntimeAnalyzer v0.3.13.3 PageZeroRVAFix' not in ui:
    raise SystemExit('v03133 UI marker missing')
print('v0.3.13.3 generator chain complete')
