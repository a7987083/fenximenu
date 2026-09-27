from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v0313_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03131_callsite_normalize.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03131_single_pass_rva_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    '[V03131-ANALYZER-PREPASS]',
    '[V03131-ANALYZER-REUSE]',
    '[V03131-LEDGER-BRIDGE]',
    '[V03131-STATIC-CANONICAL]',
    'identity+rva+original+enabled',
    'canonicalTargetIdentity',
    'canonicalRVA',
    'HFAMap_StaticCanonical_v03131.json',
]:
    if required not in trace: raise SystemExit('v03131 generated trace missing '+required)
if trace.count('HFAAnalyzerV02ScanSelectedImage();') != 1:
    raise SystemExit('v03131 full analyzer must execute exactly once per finalizer')
if 'HFAMap RuntimeAnalyzer v0.3.13.1 SinglePassLedgerBridge' not in ui:
    raise SystemExit('v03131 UI marker missing')
print('v0.3.13.1 generator chain complete')
