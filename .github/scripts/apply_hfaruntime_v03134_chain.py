from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v03133_chain.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_class1_ownership_completion.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_conflict_export_fix.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_static_ownership_fix.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_auto_select_unique_candidate.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_orphan_caller_recovery.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_object_table_recovery.py')],cwd=ROOT)
subprocess.check_call(['python3',str(S/'hfamap_runtime_analyzer_v03134_feature_catalog_startup.py')],cwd=ROOT)

trace=(ROOT/'hfamap'/'src'/'HFAMapPatchExecutionTrace.m').read_text()
v02=(ROOT/'hfamap'/'src'/'HFAMapRuntimeAnalyzerV02.m').read_text()
family=(ROOT/'hfamap'/'src'/'HFAMapFamilyRuntimeResolver.m').read_text()
applocal=(ROOT/'hfamap'/'src'/'HFAMapAppLocalResolver.m').read_text()
ui=(ROOT/'hfamap'/'src'/'HFAMapCyberUI.m').read_text()
for required in [
    'HFA03134WrapperSecretRVA',
    'HFA03134OwnershipForBackend',
    '[V03134-STATIC-OWNERSHIP]',
    'static-wrapper-secret-rva',
    'static-singleton-feature-definition',
    'ownership=static-structural',
    '[V03134-OWNERSHIP-BRIDGE]',
    '[V03134-LEDGER-BRIDGE]',
    '[V03134-STATIC-CANONICAL]',
    '[V03134-CONFLICT-FILTER]',
    '[V03134-ORPHAN-RECOVERY]',
    '[V03134-CALLER-RECOVERY]',
    '[V03134-OBJECT-TABLE]',
    '[V03134-STARTUP-OWNERSHIP]',
    'static-caller-registration-key',
    'static-object-table-registration-key',
    'staticObjectTableEvidence',
    'startup-static-support',
    'mach-o-mod-init',
    'exported-with-conflicts-filtered',
    'HFAMap_StaticCanonical_v03134.json',
    'HFA03133CanonicalTarget',
    'realSegment=strcmp(seg->segname,"__PAGEZERO")!=0',
]:
    if required not in trace: raise SystemExit('v03134 generated trace missing '+required)
if '[V03134-EVENT-OWNERSHIP]' in trace:
    raise SystemExit('v03134 runtime-event ownership regression')
if 'status=@"blocked-conflict"' in trace:
    raise SystemExit('v03134 whole-package conflict block regression')
for required in ['[V03134-STATIC-FEATURE]','identifier-fallback','[V03134-FEATURE-CATALOG]','hidden-or-not-instantiated','catalogFeatures','hiddenFeatures']:
    if required not in family: raise SystemExit('v03134 family catalog missing '+required)
for required in ['[AUTO-SELECT] candidates=1','found.count == 1','found.count > 1','manualSelectionRequired=0']:
    if required not in applocal: raise SystemExit('v03134 unique candidate auto-select missing '+required)
for required in ['HFAAnalyzerV02BeginExportEpoch','HFAAnalyzerV02ScanSelectedImageImpl','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if required not in v02: raise SystemExit('v03134 analyzer single-pass regression '+required)
if 'HFAMap RuntimeAnalyzer v0.3.13.4 Class1OwnershipCompletion' not in ui:
    raise SystemExit('v03134 UI marker missing')
print('v0.3.13.4 generator chain complete')
