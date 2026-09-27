from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v0310_chain.py')],cwd=ROOT)
for name in [
    'hfamap_runtime_analyzer_v0311_adr_block_nested.py',
    'hfamap_runtime_analyzer_v0311_notification_prefilter.py',
    'hfamap_runtime_analyzer_v0311_fulltext_xref.py',
    'hfamap_runtime_analyzer_v0311_consumer_graph.py',
    'hfamap_runtime_analyzer_v0311_compile_fixes.py',
]:
    subprocess.check_call(['python3',str(S/name)],cwd=ROOT)

src=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
dis=(ROOT/'hfamap'/'src'/'HFAMap5MDispatcherResolver.m').read_text()
for required in ['HFAV0311FullTextStateXrefCandidates','HFAV0311ConsumerGraph','HFAMap_RuntimeAnalyzer_v0311.json','com.hfa.runtime-analyzer/v0.3.11','[V0311-SCAN-END]']:
    if required not in src: raise SystemExit('v0311 runtime source missing '+required)
for required in ['HFA0311ResolveNearbyBlockInvoke','HFA0311SelectorTextXrefs','[V0311-BLOCK-INVOKE]','[V0311-NOTIFY-XREF]']:
    if required not in dis: raise SystemExit('v0311 dispatcher source missing '+required)
print('v0.3.11 generator chain complete')
