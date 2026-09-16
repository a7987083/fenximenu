from pathlib import Path

FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
MAKEFILE = Path('hfamap/Makefile')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)

family = FAMILY.read_text()
trace = TRACE.read_text()
makefile = MAKEFILE.read_text()
cyber = CYBER.read_text()
app = APPLOCAL.read_text()
exporter = EXPORTER.read_text()

# Runtime-family bridge: collect evidence only from already-selected 5M objects.
decl_anchor = 'extern void HFACyberUIAppendLog(NSString *text);\n'
family = once(
    family,
    decl_anchor,
    decl_anchor +
    'extern void HFA5MDispatcherReset(void);\n'
    'extern void HFA5MDispatcherObserveFeatureArray(id menuTarget, NSArray *features);\n'
    'extern void HFA5MDispatcherObserveAction(id sender, id target, SEL action);\n',
    'declare 5M dispatcher resolver',
)

family = once(
    family,
    '            HFARegisterIGMMFeatureArray(owner, features);\n',
    '            HFA5MDispatcherObserveFeatureArray(owner, features);\n'
    '            HFARegisterIGMMFeatureArray(owner, features);\n',
    'observe 5M feature array',
)

family = once(
    family,
    '            HFAGenericMenuObserveAction(control, target, action);\n',
    '            if (strcmp(context->family, "runtime-5m") == 0)\n'
    '                HFA5MDispatcherObserveAction(control, target, action);\n'
    '            HFAGenericMenuObserveAction(control, target, action);\n',
    'observe 5M action',
)

family = once(
    family,
    '        HFAJailpatchResetProfilerState();\n        HFAFamilyClearCurrentOutputs();\n',
    '        HFAJailpatchResetProfilerState();\n'
    '        HFA5MDispatcherReset();\n'
    '        HFAFamilyClearCurrentOutputs();\n',
    'reset dispatcher state',
)

# iGMM exporter: merge per-identifier dispatcher/notification/block evidence at
# export time, after all UI actions have been observed.
pending_anchor = 'static id gPendingIGMMMenuTarget = nil;\n'
trace = once(
    trace,
    pending_anchor,
    'extern NSDictionary *HFA5MDispatcherEvidenceForIdentifier(NSString *identifier);\n' + pending_anchor,
    'declare dispatcher evidence exporter',
)

handler_anchor = '''        NSDictionary *handler = HFAIGMMBlockMetadata(d[@"kButtonTapHandler"]);\n        if (handler) runtime[@"handler"] = handler;\n'''
trace = once(
    trace,
    handler_anchor,
    handler_anchor +
    '        NSDictionary *dispatcherEvidence = HFA5MDispatcherEvidenceForIdentifier(identifier);\n'
    '        if (dispatcherEvidence.count) runtime[@"dispatcherEvidence"] = dispatcherEvidence;\n',
    'attach dispatcher evidence',
)

# Build graph.
files_line = next((line for line in makefile.splitlines() if line.startswith('HFAMapUniversal_FILES = ')), None)
if not files_line:
    raise SystemExit('Makefile files line missing')
new_files = files_line
if 'src/HFAMap5MDispatcherResolver.m' not in new_files:
    new_files += ' src/HFAMap5MDispatcherResolver.m'
makefile = makefile.replace(files_line, new_files, 1)

# Visible analyzer/version markers only. Do not change schemas.
for old, new in (
    ('HFAMapUniversal v1.9.37 CleanFamilyResolver', 'HFAMapUniversal v1.9.37.1 5MDispatcherResolver'),
    ('v1.9.37 CleanFamilyResolver', 'v1.9.37.1 5MDispatcherResolver'),
):
    app = app.replace(old, new)
    cyber = cyber.replace(old, new)
    exporter = exporter.replace(old, new)

# Hard generation checks.
for required in (
    'HFA5MDispatcherObserveFeatureArray',
    'HFA5MDispatcherObserveAction',
    'HFA5MDispatcherReset',
):
    if required not in family:
        raise SystemExit(f'missing family integration: {required}')
if 'dispatcherEvidence' not in trace or 'HFA5MDispatcherEvidenceForIdentifier' not in trace:
    raise SystemExit('dispatcher evidence not wired into iGMM exporter')
if 'src/HFAMap5MDispatcherResolver.m' not in makefile:
    raise SystemExit('dispatcher resolver not linked')

FAMILY.write_text(family)
TRACE.write_text(trace)
MAKEFILE.write_text(makefile)
CYBER.write_text(cyber)
APPLOCAL.write_text(app)
EXPORTER.write_text(exporter)
print('patched v1.9.37.1 5MDispatcherResolver: identifier -> action -> dispatcher -> notification evidence')
