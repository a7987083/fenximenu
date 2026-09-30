from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031310_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031311_hybrid_il2cpp.py')],cwd=ROOT)

generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
resolver=(ROOT/'hfamap'/'src'/'HFAMapIL2CPPRuntimeResolver.m').read_text()
makefile=(ROOT/'hfamap'/'Makefile').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['[V031311-HYBRID]','HFAIL2CPPResolveNativeAddress']:
    if token not in generic: raise SystemExit('missing generic token '+token)
for token in ['[V031311-IL2CPP]','[V031311-IL2CPP-HIT]','[V031311-IL2CPP-MISS]','il2cpp_domain_get','il2cpp_class_get_methods','MethodInfo[%lu]']:
    if token not in resolver: raise SystemExit('missing resolver token '+token)
if 'root[@"il2cppRuntime"] = HFAIL2CPPResolverStatus();' not in exporter:
    raise SystemExit('missing exporter il2cppRuntime status')
if 'src/HFAMapIL2CPPRuntimeResolver.m' not in makefile:
    raise SystemExit('resolver source not wired into Makefile')
if 'HFAMap RuntimeAnalyzer v0.3.13.11 HybridIL2CPPRuntimeResolver' not in ui:
    raise SystemExit('v031311 UI marker missing')
for token in ['[V031310-DERIVED]','[V031310-RETURN]','[V03139-STACK]']:
    if token not in generic: raise SystemExit('missing inherited token '+token)
print('v0.3.13.11 generator chain complete')
