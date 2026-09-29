from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03135_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03136_unified_runtime_value_bridge.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03136_compile_fix.py')],cwd=ROOT)

profiler=(ROOT/'hfamap'/'src'/'HFAMapJailpatchRuntimeProfiler.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in ['[V03136-JAILPATCH-DEFINITION-BRIDGE]','HFARegisterFeatureDefinition']:
    if required not in profiler: raise SystemExit('v03136 profiler missing '+required)
for required in ['[V03136-RUNTIME-MERGE]','currentValue','runtimeValueProbe','HFA03136ObservedTitleScore']:
    if required not in exporter: raise SystemExit('v03136 exporter missing '+required)
for required in ['[V03136-RUNTIME-VALUE]','[V03136-RUNTIME-CALL]','[V03136-RUNTIME-MEM]','HFA03136ProbeImplementation','indirectCalls','candidateOnly']:
    if required not in generic: raise SystemExit('v03136 generic missing '+required)
if 'HFAMap RuntimeAnalyzer v0.3.13.6 UnifiedRuntimeValueBridge' not in ui:
    raise SystemExit('v03136 UI marker missing')
print('v0.3.13.6 generator chain complete')
