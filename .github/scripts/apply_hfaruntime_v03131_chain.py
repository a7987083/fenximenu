from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v0313_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03131_epoch_guard.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03131_rva_bridge_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
v02=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    '[V03131-ANALYZER-PREPASS]',
    '[V03131-LEDGER-BRIDGE]',
    '[V03131-STATIC-CANONICAL]',
    'identity+rva+original+enabled',
    'canonicalTargetIdentity',
    'canonicalRVA',
    'HFAMap_StaticCanonical_v03131.json',
]:
    if required not in trace: raise SystemExit('v03131 generated trace missing '+required)
for required in ['HFAAnalyzerV02BeginExportEpoch','HFAAnalyzerV02ScanSelectedImageImpl','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if required not in v02: raise SystemExit('v03131 analyzer guard missing '+required)
if 'HFAAnalyzerV02BeginExportEpoch();unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();' not in trace:
    raise SystemExit('v03131 export epoch reset missing from canonical prepass')
if 'HFAMap RuntimeAnalyzer v0.3.13.1 SinglePassLedgerBridge' not in ui:
    raise SystemExit('v03131 UI marker missing')
print('v0.3.13.1 generator chain complete')
