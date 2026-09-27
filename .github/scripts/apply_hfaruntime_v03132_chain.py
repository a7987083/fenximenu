from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03131_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03132_main_image_identity_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
v02=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    'HFA03132MainImageIndex',
    'MH_EXECUTE',
    'HFA03132CanonicalTarget',
    '[V03132-MAIN-IMAGE]',
    '[V03132-ANALYZER-PREPASS]',
    '[V03132-LEDGER-BRIDGE]',
    '[V03132-STATIC-CANONICAL]',
    'uuid+rva+original+enabled',
    'HFAMap_StaticCanonical_v03132.json',
]:
    if required not in trace: raise SystemExit('v03132 generated trace missing '+required)
for required in ['HFAAnalyzerV02BeginExportEpoch','HFAAnalyzerV02ScanSelectedImageImpl','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if required not in v02: raise SystemExit('v03132 single-pass regression '+required)
if 'strcmp(value, "main") == 0) return 0;' in trace:
    raise SystemExit('v03132 stale main index-0 assumption remains')
if 'HFAMap RuntimeAnalyzer v0.3.13.2 MainImageIdentityFix' not in ui:
    raise SystemExit('v03132 UI marker missing')
print('v0.3.13.2 generator chain complete')
