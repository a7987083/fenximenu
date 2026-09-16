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

# ---------------------------------------------------------------------------
# Unified hfapatch catalog.
# Static feature extraction remains unchanged. After static mappings are built,
# append every discovered HFAFeatureDefinition that has not yet been exported.
# Runtime-only entries carry patches=[] instead of disappearing from the file.
# ---------------------------------------------------------------------------
old_guard = '    if (!features.count || !targets.count) return;\n'
if old_guard in trace:
    trace = trace.replace(old_guard, '    if (!features.count) return;\n', 1)
elif '    if (!features.count) return;\n' not in trace:
    raise SystemExit('HFAWritePatchPackage guard not found')

finalize_pos = trace.find('unsigned HFAPatchTraceFinalizeScan(void)')
if finalize_pos < 0:
    raise SystemExit('HFAPatchTraceFinalizeScan missing')
end_marker = '    HFALog("[FULL-SCAN-END] groups=%u mappings=%u valid=%u unresolved=%u\\n",'
end_pos = trace.find(end_marker, finalize_pos)
if end_pos < 0:
    raise SystemExit('FULL-SCAN-END anchor missing')

catalog_code = r'''    unsigned runtimeCatalogFeatures = 0;
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
if '[FEATURE-CATALOG-APPEND]' not in trace:
    trace = trace[:end_pos] + catalog_code + trace[end_pos:]

# ---------------------------------------------------------------------------
# Exporter: preserve runtime-only metadata from hfapatch and fix .9 label gate.
# ---------------------------------------------------------------------------
old_meta = '''        record[@"analysisKind"] = @"canonical-byte-patch";
        record[@"canonicalEligible"] = @YES;
        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        record[@"patches"] = patches;'''
if old_meta in exporter:
    new_meta = '''        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        NSString *analysisKind = [feature[@"analysisKind"] isKindOfClass:[NSString class]]
            ? feature[@"analysisKind"] : (patches.count ? @"canonical-byte-patch" : @"runtime-observed-feature");
        record[@"analysisKind"] = analysisKind;
        record[@"canonicalEligible"] = feature[@"canonicalEligible"]
            ? @([feature[@"canonicalEligible"] boolValue]) : @(patches.count > 0);
        if ([feature[@"backend"] isKindOfClass:[NSString class]]) record[@"backend"] = feature[@"backend"];
        if ([feature[@"executionPrimitive"] isKindOfClass:[NSString class]])
            record[@"executionPrimitive"] = feature[@"executionPrimitive"];
        if ([feature[@"canonicalReason"] isKindOfClass:[NSString class]])
            record[@"canonicalReason"] = feature[@"canonicalReason"];
        if ([feature[@"runtime"] isKindOfClass:[NSDictionary class]])
            record[@"runtimeEvidence"] = feature[@"runtime"];
        record[@"patches"] = patches;'''
    exporter = exporter.replace(old_meta, new_meta, 1)
elif 'runtime-observed-feature' not in exporter or 'record[@"patches"] = patches;' not in exporter:
    raise SystemExit('canonical feature conversion anchor missing')

old_filter = '        if (!identifier.length || !label.length) continue;\n'
if old_filter in exporter:
    exporter = exporter.replace(old_filter,
        '        if (!identifier.length) continue;\n        if (!label.length) label = identifier;\n', 1)
if '!identifier.length || !label.length' in exporter:
    raise SystemExit('old observed label filter still present')

# ---------------------------------------------------------------------------
# Successful export cleanup: keep only Learn.log + hfapatch + analysis.
# Failure paths never call cleanup, preserving all intermediate evidence.
# ---------------------------------------------------------------------------
function_anchor = 'BOOL HFAMapJSONExportLatest(void) {'
cleanup_helper = r'''
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
if 'HFAJSONCleanupSuccessfulIntermediates' not in exporter:
    if function_anchor not in exporter:
        raise SystemExit('HFAMapJSONExportLatest missing')
    exporter = exporter.replace(function_anchor, cleanup_helper + function_anchor, 1)

success_fragment = '''        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no", (unsigned long)targetIdentities.count]);
        return YES;'''
if '[ARTIFACT-CLEANUP] status=pass' not in exporter:
    if success_fragment not in exporter:
        raise SystemExit('successful JSON export return anchor missing')
    success_replacement = '''        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no", (unsigned long)targetIdentities.count]);
        NSUInteger removed = HFAJSONCleanupSuccessfulIntermediates(docs, identityName, igmmName);
        HFAJSONLog([NSString stringWithFormat:@"[ARTIFACT-CLEANUP] status=pass removed=%lu keep=HFAMap_Learn.log,%@,%@",
                    (unsigned long)removed, canonicalName, name]);
        return YES;'''
    exporter = exporter.replace(success_fragment, success_replacement, 1)

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
        raise SystemExit(f'missing trace token {token}')
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
