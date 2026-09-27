from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v0312_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v0313_static_backend_ledger_bridge.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v0313_conflict_match_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    'HFA0313BridgeAnalyzerStaticBackends',
    'runtime-analyzer-binary-first',
    'unowned-static-backend',
    '[STATIC-BRIDGE]',
    '[V0313-ANALYZER-PREPASS]',
    '[V0313-LEDGER-BRIDGE]',
    '[V0313-STATIC-CANONICAL]',
    'HFAMap_StaticCanonical_v0313.json',
    'selectedCount',
    'emittedCount',
    'blocked-by-package-conflict',
    'blocked-ledger-parity',
    'runtime+original+enabled',
    'analyzerMatchKey',
]:
    if required not in trace: raise SystemExit('v0313 generated trace missing '+required)
if 'HFAMap RuntimeAnalyzer v0.3.13 StaticBackendLedgerBridge' not in ui:
    raise SystemExit('v0313 UI marker missing')
print('v0.3.13 generator chain complete')
