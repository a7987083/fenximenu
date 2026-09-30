from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031315_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031316_truth_stabilizer_native_classifier.py')],cwd=ROOT)

truth=(ROOT/'hfamap'/'src'/'HFAMapRuntimeModificationTruth.m').read_text()
trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['HFATStructuralHookBackend','HFATNativeTargetClassify','[V031316-HOOK-INGEST]','[V031316-TARGET-CLASS]','structural-hook-evidence','nativeTarget','com.hfa.runtime-modification-truth/v0.3.13.16']:
    if token not in truth: raise SystemExit('v031316 generated truth missing '+token)
for token in ['[V031316-TRUTH-SUMMARY]','[V031316-MOD-SEMANTIC]','[V031316-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031316.json']:
    if token not in trace: raise SystemExit('v031316 generated trace missing '+token)
for token in ['[V031315-IL2CPP-CONTAINMENT]','[V031312-CROSSIMAGE]','[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    corpus=(ROOT/'hfamap'/'src'/'HFAMapIL2CPPRuntimeResolver.m').read_text()+(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
    if token not in corpus: raise SystemExit('v031316 regression token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.16 TruthStabilizerNativeClassifier' not in ui: raise SystemExit('v031316 UI marker missing')
print('v0.3.13.16 generator chain complete')
