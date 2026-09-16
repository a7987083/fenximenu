from pathlib import Path

TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')
APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')

trace = TRACE.read_text()
exporter = EXPORTER.read_text()
app = APPLOCAL.read_text()
family = FAMILY.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()

# Allow a package even when all features are runtime-only and there are no
# static target images.
old_guard = '    if (!features.count || !targets.count) return;\n'
if old_guard in trace:
    trace = trace.replace(old_guard, '    if (!features.count) return;\n', 1)
elif '    if (!features.count) return;\n' not in trace:
    raise SystemExit('package feature guard missing')

# Append every discovered feature definition that static mapping export did not
# already emit. This makes HFAFeatureDefinition the feature-catalog truth and
# prevents Fuel/Boost-style runtime items from disappearing.
finalize_pos = trace.find('unsigned HFAPatchTraceFinalizeScan(void)')
if finalize_pos < 0:
    raise SystemExit('HFAPatchTraceFinalizeScan missing')
write_anchor = '    HFAWritePatchPackage(exportFeatures, exportTargets);\n'
write_pos = trace.find(write_anchor, finalize_pos)
if write_pos < 0:
    raise SystemExit('final package write anchor missing')
if '[FEATURE-CATALOG-APPEND]' not in trace:
    catalog = r'''    unsigned runtimeCatalogFeatures = 0;
    for (unsigned definitionIndex = 0; definitionIndex < gFeatureDefinitionCount; definitionIndex++) {
        HFAFeatureDefinition *definition = &gFeatureDefinitions[definitionIndex];
        if (!definition->identifier[0] || !definition->label[0]) continue;
        NSString *featureID = [NSString stringWithUTF8String:definition->identifier];
        if (!featureID.length) continue;
        BOOL alreadyExported = NO;
        for (NSDictionary *existing in exportFeatures) {
            NSString *existingID = [existing[@"id"] isKindOfClass:[NSString class]] ? existing[@"id"] : @"";
            if ([existingID isEqualToString:featureID]) { alreadyExported = YES; break; }
        }
        if (alreadyExported) continue;
        NSString *featureTitle = [NSString stringWithUTF8String:definition->label];
        [exportFeatures addObject:@{
            @"id": featureID,
            @"title": featureTitle ?: featureID,
            @"group": @"Imported",
            @"defaultEnabled": @NO,
            @"backend": @"runtime-observed",
            @"analysisKind": @"runtime-observed-feature",
            @"canonicalEligible": @NO,
            @"canonicalReason": @"runtime-feature-no-static-mapping",
            @"executionPrimitive": @"runtimeAction",
            @"patches": @[]
        }];
        runtimeCatalogFeatures++;
        HFALog("[FEATURE-CATALOG-APPEND] identifier=%s title=\"%s\" backend=runtime-observed patches=0\n",
               definition->identifier, definition->label);
    }
    HFALog("[FEATURE-CATALOG] definitions=%u exported=%lu runtimeOnly=%u\n",
           gFeatureDefinitionCount, (unsigned long)exportFeatures.count,
           runtimeCatalogFeatures);
'''
    trace = trace[:write_pos] + catalog + trace[write_pos:]

# Preserve mixed feature metadata when hfapatch is converted to analysis JSON.
old_meta = '''        record[@"analysisKind"] = @"canonical-byte-patch";
        record[@"canonicalEligible"] = @YES;
        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        record[@"patches"] = patches;'''
if old_meta in exporter:
    exporter = exporter.replace(old_meta, '''        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        NSString *analysisKind = [feature[@"analysisKind"] isKindOfClass:[NSString class]]
            ? feature[@"analysisKind"] : (patches.count ? @"canonical-byte-patch" : @"runtime-observed-feature");
        record[@"analysisKind"] = analysisKind;
        record[@"canonicalEligible"] = feature[@"canonicalEligible"]
            ? @([feature[@"canonicalEligible"] boolValue]) : @(patches.count > 0);
        if ([feature[@"backend"] isKindOfClass:[NSString class]]) record[@"backend"] = feature[@"backend"];
        if ([feature[@"executionPrimitive"] isKindOfClass:[NSString class]]) record[@"executionPrimitive"] = feature[@"executionPrimitive"];
        if ([feature[@"canonicalReason"] isKindOfClass:[NSString class]]) record[@"canonicalReason"] = feature[@"canonicalReason"];
        if ([feature[@"runtime"] isKindOfClass:[NSDictionary class]]) record[@"runtimeEvidence"] = feature[@"runtime"];
        record[@"patches"] = patches;''', 1)
elif 'patches.count ? @"canonical-byte-patch"' not in exporter:
    raise SystemExit('canonical conversion anchor missing')

# v1.9.37.9 regression: observed records have valid identifiers but often an
# empty label. Do not discard them solely because the UI label getter failed.
old_filter = '        if (!identifier.length || !label.length) continue;\n'
if old_filter in exporter:
    exporter = exporter.replace(old_filter,
        '        if (!identifier.length) continue;\n        if (!label.length) label = identifier;\n', 1)
if '!identifier.length || !label.length' in exporter:
    raise SystemExit('old empty-label filter remains')

# Successful runs keep only Learn.log + final hfapatch + final analysis.
# On failure this helper is never reached, so diagnostics remain available.
function_anchor = 'BOOL HFAMapJSONExportLatest(void) {'
if 'HFAJSONCleanupSuccessfulIntermediates' not in exporter:
    if function_anchor not in exporter:
        raise SystemExit('HFAMapJSONExportLatest missing')
    cleanup = r'''
static NSUInteger HFAJSONCleanupSuccessfulIntermediates(NSString *docs,
                                                         NSString *identityName,
                                                         NSString *igmmName) {
    if (!docs.length) return 0;
    NSArray<NSString *> *names = @[
        @"HFAMap_AppLocalCandidates.json",
        @"HFAMap_ClassMetadata.json",
        @"HFAMap_JailpatchMap.jsonl",
        @"HFAMap_Mapping.log",
        @"HFAMap_MenuMap.jsonl",
        identityName ?: @"",
        igmmName ?: @""
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSUInteger removed = 0;
    for (NSString *name in names) {
        if (!name.length) continue;
        NSString *path = [docs stringByAppendingPathComponent:name];
        if (![fm fileExistsAtPath:path]) continue;
        NSError *error = nil;
        if ([fm removeItemAtPath:path error:&error]) removed++;
        else HFAJSONLog([NSString stringWithFormat:@"[ARTIFACT-CLEANUP-FAIL] file=%@ error=%@",
                         name, error.localizedDescription ?: @"unknown"]);
    }
    return removed;
}

'''
    exporter = exporter.replace(function_anchor, cleanup + function_anchor, 1)

if '[ARTIFACT-CLEANUP] status=pass' not in exporter:
    pass_log = '[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu'
    p = exporter.find(pass_log)
    if p < 0:
        raise SystemExit('JSON export pass log missing')
    ret = exporter.find('        return YES;', p)
    if ret < 0:
        raise SystemExit('JSON export success return missing')
    cleanup_call = '''        NSUInteger removed = HFAJSONCleanupSuccessfulIntermediates(docs, identityName, igmmName);
        HFAJSONLog([NSString stringWithFormat:@"[ARTIFACT-CLEANUP] status=pass removed=%lu keep=HFAMap_Learn.log,%@,%@",
                    (unsigned long)removed, canonicalName, name]);
'''
    exporter = exporter[:ret] + cleanup_call + exporter[ret:]

# Version markers.
for old in ('HFAMapUniversal v1.9.37.9 CompleteFeatureExport', 'v1.9.37.9 CompleteFeatureExport'):
    new = 'HFAMapUniversal v1.9.37.10 UnifiedFeatureModel' if old.startswith('HFAMapUniversal') else 'v1.9.37.10 UnifiedFeatureModel'
    trace = trace.replace(old, new)
    exporter = exporter.replace(old, new)
    app = app.replace(old, new)
    family = family.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)

for token in ('[FEATURE-CATALOG-APPEND]', '[FEATURE-CATALOG]', '@"patches": @[]', '@"backend": @"runtime-observed"'):
    if token not in trace:
        raise SystemExit(f'missing catalog token {token}')
for token in ('HFAJSONCleanupSuccessfulIntermediates', '[ARTIFACT-CLEANUP]', 'if (!label.length) label = identifier;'):
    if token not in exporter:
        raise SystemExit(f'missing exporter token {token}')

TRACE.write_text(trace)
EXPORTER.write_text(exporter)
APPLOCAL.write_text(app)
FAMILY.write_text(family)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
print('patched v1.9.37.10: unified feature catalog + 3-file success output')
