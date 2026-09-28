from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03133_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_class1_ownership_completion.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
v02=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    '[V03134-EVENT-OWNERSHIP]',
    'HFA03134WrapperSecretRVA',
    'HFA03134OwnershipForBackend',
    'wrapper-secret-rva+event-identifier',
    '[V03134-OWNERSHIP-BRIDGE]',
    '[V03134-LEDGER-BRIDGE]',
    '[V03134-STATIC-CANONICAL]',
    'HFAMap_StaticCanonical_v03134.json',
    'HFA03133CanonicalTarget',
    'realSegment=strcmp(seg->segname,"__PAGEZERO")!=0',
]:
    if required not in trace: raise SystemExit('v03134 generated trace missing '+required)
for required in ['HFAAnalyzerV02BeginExportEpoch','HFAAnalyzerV02ScanSelectedImageImpl','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if required not in v02: raise SystemExit('v03134 analyzer single-pass regression '+required)
if 'HFAMap RuntimeAnalyzer v0.3.13.4 Class1OwnershipCompletion' not in ui:
    raise SystemExit('v03134 UI marker missing')
print('v0.3.13.4 generator chain complete')
