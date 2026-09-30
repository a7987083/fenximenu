from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03139_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031310_object_return_taint.py')],cwd=ROOT)

generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['[V031310-DERIVED]','[V031310-RETURN]','[V031310-IDFIELD-LOAD]','[V031310-OBJECT-SUMMARY]','derivedObjectEvents','@"objectReturnAware":@YES']:
    if token not in generic: raise SystemExit('missing generic token '+token)
for token in ['[V03139-STACK]','[V03139-STACK-SUMMARY]','@"stackAware":@YES']:
    if token not in generic: raise SystemExit('missing v03139 token '+token)
for token in ['identifierDiscriminator','senderIdentifierDataflow']:
    if token not in exporter: raise SystemExit('missing exporter token '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.10 ObjectReturnTaintResolver' not in ui:
    raise SystemExit('v031310 UI marker missing')
print('v0.3.13.10 generator chain complete')
