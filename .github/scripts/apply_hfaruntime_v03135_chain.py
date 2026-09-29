from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03134_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03135_runtime_value_resolver.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03135_compile_fix.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in ['[V03135-TITLE-MERGE]','HFA03135LabelScore']:
    if required not in trace: raise SystemExit('v03135 trace missing '+required)
for required in ['[V03135-RUNTIME-VALUE]','currentValue','runtimeValueProbe','HFA03135ProbeImplementation','HFA03135SemanticKind']:
    if required not in generic: raise SystemExit('v03135 generic missing '+required)
if 'HFAMap RuntimeAnalyzer v0.3.13.5 RuntimeValueResolver' not in ui:
    raise SystemExit('v03135 UI marker missing')
print('v0.3.13.5 generator chain complete')
