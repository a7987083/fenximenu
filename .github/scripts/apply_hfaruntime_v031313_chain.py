from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031312_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031313_runtime_modification_truth.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031313_truth_semantics_fix.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031313_bundle_log_bridge.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
truth=(ROOT/'hfamap'/'src'/'HFAMapRuntimeModificationTruth.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
make=(ROOT/'hfamap'/'Makefile').read_text()
for token in ['[V031313-TRUTH-FILE]','runtimeModificationTruth','HFARuntimeModificationTruthBuild','startupMods=%u']:
    if token not in trace: raise SystemExit('missing generated trace token '+token)
for token in ['[V031313-PATCH-STATE]','[V031313-HOOK-STATE]','[V031313-TRUTH-SUMMARY]','runtime-semantic','originalSlotRVA','menuFeatureCount','startupFeatureCount','startupModificationCount','effectiveFeatureCount','startupGroups']:
    if token not in truth: raise SystemExit('missing truth token '+token)
for token in ['[V031312-CROSSIMAGE]','[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
    if token not in generic: raise SystemExit('regression token missing '+token)
if 'src/HFAMapRuntimeModificationTruth.m' not in make: raise SystemExit('truth source not in Makefile')
if 'HFAMap RuntimeAnalyzer v0.3.13.13 RuntimeModificationTruthResolver' not in ui: raise SystemExit('v031313 UI marker missing')
print('v0.3.13.13 generator chain complete')
