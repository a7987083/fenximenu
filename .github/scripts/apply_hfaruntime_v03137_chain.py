from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03136_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03137_unified_feature_truth_sender_dataflow.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['[V03137-FEATURE-TRUTH]','HFAFeatureDefinitionTitleSnapshot']:
    if token not in trace: raise SystemExit('missing trace token '+token)
for token in ['[V03137-FEATURE-TRUTH-MERGE]','senderState','HFAFeatureDefinitionTitleSnapshot']:
    if token not in exporter: raise SystemExit('missing exporter token '+token)
for token in ['[V03137-SENDER]','HFA03137SenderSnapshot','@"senderState"']:
    if token not in generic: raise SystemExit('missing generic token '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.7 UnifiedFeatureTruthSenderDataflow' not in ui:
    raise SystemExit('v03137 UI marker missing')
print('v0.3.13.7 generator chain complete')
