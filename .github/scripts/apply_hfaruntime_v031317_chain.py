from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031316_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031317_native_entry_semantic.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031317_compile_fix.py')],cwd=ROOT)

truth=(ROOT/'hfamap'/'src'/'HFAMapRuntimeModificationTruth.m').read_text()
trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['HFATNativeEntrySemantic','[V031317-NATIVE-ENTRY]','[V031317-NATIVE-EDGE]','nativeEntrySemantic','HFATBundleLog','com.hfa.runtime-modification-truth/v0.3.13.17','[V031316-HOOK-INGEST]','[V031316-TARGET-CLASS]','static NSDictionary *HFATIL2CPPSemantic(uintptr_t address);']:
    if token not in truth: raise SystemExit('v031317 generated truth missing '+token)
for token in ['[V031317-TRUTH-SUMMARY]','[V031317-MOD-SEMANTIC]','[V031317-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031317.json']:
    if token not in trace: raise SystemExit('v031317 generated trace missing '+token)
for token in ['[V031315-IL2CPP-CONTAINMENT]','[V031312-CROSSIMAGE]','[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    corpus=(ROOT/'hfamap'/'src'/'HFAMapIL2CPPRuntimeResolver.m').read_text()+(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
    if token not in corpus: raise SystemExit('v031317 regression token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.17 NativeEntrySemanticResolver' not in ui: raise SystemExit('v031317 UI marker missing')
print('v0.3.13.17 generator chain complete')
