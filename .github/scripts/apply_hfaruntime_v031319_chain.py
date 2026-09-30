from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031318_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v031319_c4m0_config_owner.py')],cwd=ROOT)

make=(ROOT/'hfamap'/'Makefile').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
resolver=(ROOT/'hfamap'/'src'/'HFAMapC4M0ConfigOwnerResolver.m').read_text()
if 'src/HFAMapC4M0ConfigOwnerResolver.m' not in make:raise SystemExit('v031319 source missing')
if 'v0.3.13.19 C4M0ConfigOwnerResolver' not in ui:raise SystemExit('v031319 UI marker missing')
for token in ['loadConfig:','loadPolicies','ownerImageCount','candidateCount','readOnly']:
    if token not in resolver:raise SystemExit('v031319 resolver token missing '+token)
print('v0.3.13.19 generator chain complete')
