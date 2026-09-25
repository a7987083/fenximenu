from pathlib import Path

ROOT = Path('hfamap')
FAMILY = ROOT / 'src/HFAMapFamilyRuntimeResolver.m'
EXPORTER = ROOT / 'src/HFAMapJSONExport.m'
DISPATCH = ROOT / 'src/HFAMap5MDispatcherResolver.m'
MAKEFILE = ROOT / 'Makefile'

family = FAMILY.read_text()
exporter = EXPORTER.read_text()
dispatch = DISPATCH.read_text()
make = MAKEFILE.read_text()

proto = 'extern unsigned HFAOwnershipV04Analyze(void);\n'
if proto.strip() not in family:
    anchor = 'extern void HFACyberUIAppendLog(NSString *text);\n'
    if anchor not in family:
        raise SystemExit('family extern anchor missing')
    family = family.replace(anchor, anchor + proto, 1)

if '[V04-ANALYZER]' not in family:
    anchor = '        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-END]'
    pos = family.find(anchor)
    if pos < 0:
        raise SystemExit('family final log anchor missing')
    code = '''        unsigned ownershipFeatures = HFAOwnershipV04Analyze();\n        HFAFamilyLog([NSString stringWithFormat:@"[V04-ANALYZER] family=%s image=%s ownershipFeatures=%u",\n                      family, image, ownershipFeatures]);\n'''
    family = family[:pos] + code + family[pos:]

proto = 'extern BOOL HFAOwnershipV04MergeLatestAnalysis(void);\n'
if proto.strip() not in exporter:
    anchor = '#import <Foundation/Foundation.h>\n'
    if anchor not in exporter:
        raise SystemExit('exporter import anchor missing')
    exporter = exporter.replace(anchor, anchor + proto, 1)

if '[V04-ANALYSIS-MERGE]' not in exporter:
    cleanup_anchor = '        NSUInteger removed = HFAJSONCleanupSuccessfulIntermediates(docs, identityName, igmmName);'
    p = exporter.find(cleanup_anchor)
    if p < 0:
        raise SystemExit('export success cleanup anchor missing')
    ret = exporter.find('        return YES;', p)
    if ret < 0:
        raise SystemExit('export success return missing')
    code = '''        BOOL v04Merged = HFAOwnershipV04MergeLatestAnalysis();\n        HFAJSONLog([NSString stringWithFormat:@"[V04-ANALYSIS-MERGE] merged=%d", v04Merged ? 1 : 0]);\n'''
    exporter = exporter[:ret] + code + exporter[ret:]

old = '    copy[@"downstreamCallbackResolved"] = @(blocks.count > 0);'
if old in dispatch:
    new = '''    NSArray *bridges = [copy[@"observerBridges"] isKindOfClass:[NSArray class]] ? copy[@"observerBridges"] : @[];\n    copy[@"observerRegistrationResolved"] = @(bridges.count > 0);\n    copy[@"downstreamCallbackResolved"] = @(blocks.count > 0);'''
    dispatch = dispatch.replace(old, new, 1)

if 'HFAMapOwnershipResolverV04.m' not in make:
    marker = 'HFAMapUniversal_FILES = '
    p = make.find(marker)
    if p < 0:
        raise SystemExit('Makefile files anchor missing')
    e = make.find('\n', p)
    make = make[:e] + ' src/HFAMapOwnershipResolverV04.m' + make[e:]

for token in ('HFAOwnershipV04Analyze', '[V04-ANALYZER]'):
    if token not in family:
        raise SystemExit(f'missing family token {token}')
for token in ('HFAOwnershipV04MergeLatestAnalysis', '[V04-ANALYSIS-MERGE]'):
    if token not in exporter:
        raise SystemExit(f'missing exporter token {token}')
if 'HFAMapOwnershipResolverV04.m' not in make:
    raise SystemExit('v0.4 source not in Makefile')

FAMILY.write_text(family)
EXPORTER.write_text(exporter)
DISPATCH.write_text(dispatch)
MAKEFILE.write_text(make)
print('v0.4 ownership wiring applied')
