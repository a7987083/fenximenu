from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031313_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031314_modification_semantic.py')],cwd=ROOT)

truth=(ROOT/'hfamap'/'src'/'HFAMapRuntimeModificationTruth.m').read_text()
trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['HFAMapIL2CPPRuntimeResolver.h','HFATIL2CPPSemantic','[V031314-IL2CPP-TARGET]','discoveredFeatureCount','startupOwnedFeatureCount','startupAppliedFeatureCount','installedModificationCount','activeFeatureCountKnown','activeFeatureStateComplete','effectiveFeatureCountDeprecated','il2cppRuntime']:
    if token not in truth: raise SystemExit('v031314 generated truth missing '+token)
for token in ['[V031314-TRUTH-SUMMARY]','[V031314-MOD-SEMANTIC]','[V031314-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031314.json']:
    if token not in trace: raise SystemExit('v031314 generated trace missing '+token)
for token in ['[V031312-CROSSIMAGE]','[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
    if token not in generic: raise SystemExit('v031314 regression token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.14 ModificationSemanticResolver' not in ui: raise SystemExit('v031314 UI marker missing')
# v031313 Learn.log bridge emitted literal backslash+n; the new generated source must contain C newline escapes, not double escapes.
for line in trace.splitlines():
    if '[V031313-' in line or '[V031314-' in line:
        if '\\\\n"' in line: raise SystemExit('literal backslash-n regression in bundle log bridge')
print('v0.3.13.14 generator chain complete')
