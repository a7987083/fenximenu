from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v039_chain.py')],cwd=ROOT)
for name in ['hfamap_runtime_analyzer_v0310_block_observer_invoke.py','hfamap_runtime_analyzer_v0310_consumer_graph.py']:
    subprocess.check_call(['python3',str(S/name)],cwd=ROOT)

p=ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m'
text=p.read_text()
for required in ['HFAV0310ConsumerGraph','HFAMap_RuntimeAnalyzer_v0310.json','com.hfa.runtime-analyzer/v0.3.10']:
    if required not in text: raise SystemExit('v0310 generated source missing '+required)
d=ROOT/'hfamap'/'src'/'HFAMap5MDispatcherResolver.m'
dt=d.read_text()
for required in ['HFA0310ResolveNearbyBlockInvoke','[V0310-BLOCK-INVOKE]','block-invoke-static']:
    if required not in dt: raise SystemExit('v0310 dispatcher missing '+required)
print('v0.3.10 generator chain complete')
