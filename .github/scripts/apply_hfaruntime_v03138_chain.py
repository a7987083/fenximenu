from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03137_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03138_sender_identifier_dataflow.py')],cwd=ROOT)

generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['HFA03138IdentifierDiscriminator','HFA03138SenderIdentifierDataflow','[V03138-IDFIELD]','[V03138-IDFIELD-LOAD]','senderIdentifierDataflow']:
    if token not in generic: raise SystemExit('missing generic token '+token)
for token in ['identifierDiscriminator','senderIdentifierDataflow']:
    if token not in exporter: raise SystemExit('missing exporter token '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.8 SenderIdentifierDataflowResolver' not in ui:
    raise SystemExit('v03138 UI marker missing')
print('v0.3.13.8 generator chain complete')
