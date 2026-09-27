from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v0311_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v0312_static_canonical_completion.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    'HFA0312FeatureIdentityForKey',
    '[STATIC-LEDGER]',
    '[STATIC-DISPOSITION]',
    '[STATIC-CONFLICT]',
    '[STATIC-AUDIT]',
    '[PACKAGE-MIRROR]',
    '[V0312-STATIC-CANONICAL]',
    'HFAMap_StaticCanonical_v0312.json',
    'fail-closed-no-silent-drop',
]:
    if required not in trace: raise SystemExit('v0312 generated trace missing '+required)
if 'HFAWritePatchPackage(exportFeatures,exportTargets,ledger,featureDispositions,conflicts)' not in trace:
    raise SystemExit('v0312 final package bridge missing')
if 'HFAMap RuntimeAnalyzer v0.3.12 StaticCanonicalCompletion' not in ui:
    raise SystemExit('v0312 UI marker missing')
print('v0.3.12 generator chain complete')
