from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031317_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031318_budget_dedup.py')],cwd=ROOT)

cross=(ROOT/'hfamap'/'src'/'HFAMapCrossImageResolver.m').read_text()
generic=(ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for token in ['gCrossTargetCache','uniqueResolveCount','cacheHitCount','gCrossBLRCache','blrCacheHitCount']:
    if token not in cross: raise SystemExit('v031318 cross token missing '+token)
for token in ['[V031318-BUDGET]','hfa031318DepthCap','HFA031318CrossLogOnce','@"budgetExceeded"']:
    if token not in generic: raise SystemExit('v031318 generic token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.18 AnalysisBudgetAndDedup' not in ui: raise SystemExit('v031318 UI marker missing')
for p in (ROOT/'hfamap'/'src').glob('*.m'):
    if 'Documents/HFAMap_Learn.log' in p.read_text(): raise SystemExit('legacy Learn.log path remains in '+str(p))
print('v0.3.13.18 generator chain complete')
