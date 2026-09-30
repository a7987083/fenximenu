from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031311_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031312_cross_image.py')],cwd=ROOT)

generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
resolver=(ROOT/'hfamap'/'src'/'HFAMapCrossImageResolver.m').read_text()
exporter=(ROOT/'hfamap'/'src'/'HFAMapJSONExport.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['[V031312-CROSSIMAGE]','[V031312-BLR]','crossImageCall','HFACrossImageResolveTarget','HFACrossImageResolveBLRCallsite']:
    if token not in generic: raise SystemExit('missing generic token '+token)
for token in ['ADRP+LDR+BR','ADRP+ADD+LDR+BR','LDR-literal+BR','ADRP+LDR+BLR','crossImage']:
    if token not in resolver: raise SystemExit('missing resolver token '+token)
if 'crossImageRuntime' not in exporter: raise SystemExit('missing exporter crossImageRuntime')
if 'HFAMap RuntimeAnalyzer v0.3.13.12 CrossImageCallResolver' not in ui: raise SystemExit('v031312 UI marker missing')
for token in ['[V031311-HYBRID]','[V031310-RETURN]','[V03139-STACK]']:
    if token not in generic: raise SystemExit('regression token missing '+token)
print('v0.3.13.12 generator chain complete')
