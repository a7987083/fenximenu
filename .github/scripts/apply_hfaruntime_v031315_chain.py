from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031314_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031315_method_containment.py')],cwd=ROOT)

hdr=(ROOT/'hfamap'/'src'/'HFAMapIL2CPPRuntimeResolver.h').read_text()
impl=(ROOT/'hfamap'/'src'/'HFAMapIL2CPPRuntimeResolver.m').read_text()
truth=(ROOT/'hfamap'/'src'/'HFAMapRuntimeModificationTruth.m').read_text()
trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['HFAIL2CPPResolveContainingAddress']:
    if token not in hdr: raise SystemExit('v031315 header missing '+token)
for token in ['[V031315-IL2CPP-CONTAINMENT]','containmentResolveCount','containmentHitCount','offsetInMethod','boundedByNextMethod','candidateOnly','confidence']:
    if token not in impl: raise SystemExit('v031315 implementation missing '+token)
for token in ['HFAIL2CPPResolveContainingAddress','[V031315-IL2CPP-TARGET]','com.hfa.runtime-modification-truth/v0.3.13.15']:
    if token not in truth: raise SystemExit('v031315 truth missing '+token)
for token in ['[V031315-TRUTH-SUMMARY]','[V031315-MOD-SEMANTIC]','[V031315-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031315.json']:
    if token not in trace: raise SystemExit('v031315 trace missing '+token)
for token in ['[V031312-CROSSIMAGE]','[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
    if token not in generic: raise SystemExit('v031315 regression token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.15 MethodContainmentResolver' not in ui: raise SystemExit('v031315 UI marker missing')
print('v0.3.13.15 generator chain complete')
