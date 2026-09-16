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
# 1) Unified feature catalog: every discovered feature definition is exported.
# Static patch features retain patches; runtime-only features retain action
# evidence and an empty patches array instead of disappearing from hfapatch.
# ---------------------------------------------------------------------------
old_struct = '''typedef struct {
    char label[256];
    char identifier[96];
    char key[128];
} HFAFeatureDefinition;'''
new_struct = '''typedef struct {
    char label[256];
    char identifier[96];
    char key[128];
    char runtimeTargetClass[192];
    char runtimeAction[192];
    char runtimeImage[256];
    uintptr_t runtimeRVA;
} HFAFeatureDefinition;'''
if old_struct not in trace:
    raise SystemExit('feature definition struct anchor missing')
trace = trace.replace(old_struct, new_struct, 1)

helper_anchor = '''static HFAFeatureDefinition *HFAFeatureDefinitionForKey(const char *key) {
    if (!key || !*key) return NULL;
    for (unsigned i = 0; i < gFeatureDefinitionCount; i++)
        if (strcmp(gFeatureDefinitions[i].key, key) == 0)
            return &gFeatureDefinitions[i];
    return NULL;
}
'''
if helper_anchor not in trace:
    raise SystemExit('feature lookup helper anchor missing')
helper_extra = helper_anchor + '''
static HFAFeatureDefinition *HFAFeatureDefinitionForIdentifier(const char *identifier) {
    if (!identifier || !*identifier) return NULL;
    for (unsigned i = 0; i < gFeatureDefinitionCount; i++)
        if (strcmp(gFeatureDefinitions[i].identifier, identifier) == 0)
            return &gFeatureDefinitions[i];
    return NULL;
}
'''
trace = trace.replace(helper_anchor, helper_extra, 1)

observe_anchor = '''    HFALog("[ACTION-IMP] event=%u targetClass=%s selector=%s image=%s rva=%llX\\n",
           gEvent, class_getName(cls), sel_getName(action), image,
           (unsigned long long)rva);
    HFAInstallStateQueriesForImage(image);
}'''
if observe_anchor not in trace:
    raise SystemExit('action observe anchor missing')
observe_new = '''    HFALog("[ACTION-IMP] event=%u targetClass=%s selector=%s image=%s rva=%llX\\n",
           gEvent, class_getName(cls), sel_getName(action), image,
           (unsigned long long)rva);
    HFAFeatureDefinition *definition = HFAFeatureDefinitionForIdentifier(gIdentifier);
    if (definition) {
        snprintf(definition->runtimeTargetClass, sizeof(definition->runtimeTargetClass), "%s", class_getName(cls) ?: "?");
        snprintf(definition->runtimeAction, sizeof(definition->runtimeAction), "%s", sel_getName(action) ?: "?");
        snprintf(definition->runtimeImage, sizeof(definition->runtimeImage), "%s", image ?: "?");
        definition->runtimeRVA = rva;
        HFALog("[FEATURE-RUNTIME] identifier=%s title=\\\"%s\\\" targetClass=%s action=%s image=%s rva=%llX\\n",
               definition->identifier, definition->label,
               definition->runtimeTargetClass, definition->runtimeAction,
               definition->runtimeImage, (unsigned long long)definition->runtimeRVA);
    }
    HFAInstallStateQueriesForImage(image);
}'''
trace = trace.replace(observe_anchor, observe_new, 1)

# hfapatch may contain only runtime features, so targets are optional.
old_guard = '    if (!features.count || !targets.count) return;\n'
if old_guard not in trace:
    raise SystemExit('patch package guard missing')
trace = trace.replace(old_guard, '    if (!features.count) return;\n', 1)

old_init = '''    NSMutableArray *exportFeatures = [NSMutableArray array];
    NSMutableDictionary *exportTargets = [NSMutableDictionary dictionary];'''
new_init = '''    NSMutableArray *exportFeatures = [NSMutableArray array];
    NSMutableSet<NSString *> *exportedFeatureIDs = [NSMutableSet set];
    NSMutableDictionary *exportTargets = [NSMutableDictionary dictionary];
    unsigned canonicalFeatureCount = 0;
    unsigned runtimeFeatureCount = 0;'''
if old_init not in trace:
    raise SystemExit('finalize init anchor missing')
trace = trace.replace(old_init, new_init, 1)

old_static_append = '''            [exportFeatures addObject:@{ @"id": featureID,
                                         @"title": featureTitle,
                                         @"group": @"Imported",
                                         @"defaultEnabled": @NO,
                                         @"patches": exportPatches }];'''
new_static_append = '''            [exportFeatures addObject:@{ @"id": featureID,
                                         @"title": featureTitle,
                                         @"group": @"Imported",
                                         @"defaultEnabled": @NO,
                                         @"backend": @"canonical-byte-patch",
                                         @"analysisKind": @"canonical-byte-patch",
                                         @"canonicalEligible": @YES,
                                         @"patches": exportPatches }];
            [exportedFeatureIDs addObject:featureID];
            canonicalFeatureCount++;'''
if old_static_append not in trace:
    raise SystemExit('static feature append anchor missing')
trace = trace.replace(old_static_append, new_static_append, 1)

end_anchor = '''    HFALog("[FULL-SCAN-END] groups=%u mappings=%u valid=%u unresolved=%u\\n",
           groups, emitted, validParts, emitted - validParts);
    HFAWritePatchPackage(exportFeatures, exportTargets);
    return validParts;
}'''
if end_anchor not in trace:
    raise SystemExit('finalize end anchor missing')
end_new = '''    for (unsigned i = 0; i < gFeatureDefinitionCount; i++) {
        HFAFeatureDefinition *definition = &gFeatureDefinitions[i];
        if (!definition->identifier[0] || !definition->label[0]) continue;
        NSString *featureID = [NSString stringWithUTF8String:definition->identifier];
        if (!featureID.length || [exportedFeatureIDs containsObject:featureID]) continue;
        NSString *featureTitle = [NSString stringWithUTF8String:definition->label];
        NSMutableDictionary *runtime = [NSMutableDictionary dictionary];
        if (definition->runtimeTargetClass[0])
            runtime[@"targetClass"] = [NSString stringWithUTF8String:definition->runtimeTargetClass];
        if (definition->runtimeAction[0])
            runtime[@"action"] = [NSString stringWithUTF8String:definition->runtimeAction];
        if (definition->runtimeImage[0])
            runtime[@"implementation"] = @{
                @"image": [NSString stringWithUTF8String:definition->runtimeImage],
                @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)definition->runtimeRVA]
            };
        BOOL haveRuntimeAction = definition->runtimeAction[0] != 0;
        NSMutableDictionary *feature = [@{
            @"id": featureID,
            @"title": featureTitle ?: featureID,
            @"group": @"Imported",
            @"defaultEnabled": @NO,
            @"backend": haveRuntimeAction ? @"runtime-action" : @"runtime-unresolved",
            @"analysisKind": haveRuntimeAction ? @"runtime-observed-action" : @"runtime-observed-feature",
            @"canonicalEligible": @NO,
            @"canonicalReason": haveRuntimeAction ? @"runtime-action-not-static-bytes" : @"runtime-feature-no-static-mapping",
            @"executionPrimitive": haveRuntimeAction ? @"runtimeAction" : @"unresolved",
            @"patches": @[]
        } mutableCopy];
        if (runtime.count) feature[@"runtime"] = runtime;
        [exportFeatures addObject:feature];
        [exportedFeatureIDs addObject:featureID];
        runtimeFeatureCount++;
        HFALog("[FEATURE-CATALOG-APPEND] identifier=%s title=\\\"%s\\\" backend=%s action=%s image=%s rva=%llX\\n",
               definition->identifier, definition->label,
               haveRuntimeAction ? "runtime-action" : "runtime-unresolved",
               definition->runtimeAction[0] ? definition->runtimeAction : "?",
               definition->runtimeImage[0] ? definition->runtimeImage : "?",
               (unsigned long long)definition->runtimeRVA);
    }
    HFALog("[FEATURE-CATALOG] definitions=%u exported=%lu canonical=%u runtime=%u\\n",
           gFeatureDefinitionCount, (unsigned long)exportFeatures.count,
           canonicalFeatureCount, runtimeFeatureCount);
    HFALog("[FULL-SCAN-END] groups=%u mappings=%u valid=%u unresolved=%u\\n",
           groups, emitted, validParts, emitted - validParts);
    HFAWritePatchPackage(exportFeatures, exportTargets);
    return validParts;
}'''
trace = trace.replace(end_anchor, end_new, 1)

# ---------------------------------------------------------------------------
# 2) JSON export understands mixed hfapatch entries. Canonical features retain
# canonical metadata; runtime-only entries remain runtime features.
# Also fix v1.9.37.9's label-empty observed filter.
# ---------------------------------------------------------------------------
old_canonical_meta = '''        record[@"analysisKind"] = @"canonical-byte-patch";
        record[@"canonicalEligible"] = @YES;
        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        record[@"patches"] = patches;'''
new_canonical_meta = '''        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
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
if old_canonical_meta not in exporter:
    raise SystemExit('canonical export metadata anchor missing')
exporter = exporter.replace(old_canonical_meta, new_canonical_meta, 1)

old_observed_filter = '        if (!identifier.length || !label.length) continue;\n'
if old_observed_filter not in exporter:
    raise SystemExit('v19379 observed label filter anchor missing')
exporter = exporter.replace(old_observed_filter, '        if (!identifier.length) continue;\n        if (!label.length) label = identifier;\n', 1)

# ---------------------------------------------------------------------------
# 3) Successful export leaves only three normal user-facing files:
# Learn.log, final hfapatch.json, final analysis.json. Intermediate evidence is
# kept automatically when export fails because cleanup only runs after success.
# ---------------------------------------------------------------------------
cleanup_helper_anchor = 'BOOL HFAMapJSONExportLatest(void) {'
cleanup_helpers = r'''
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
if cleanup_helper_anchor not in exporter:
    raise SystemExit('JSON export function anchor missing')
if 'HFAJSONCleanupSuccessfulIntermediates' not in exporter:
    exporter = exporter.replace(cleanup_helper_anchor, cleanup_helpers + cleanup_helper_anchor, 1)

success_anchor = '''        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no", (unsigned long)targetIdentities.count]);
        return YES;'''
if success_anchor not in exporter:
    raise SystemExit('JSON export success anchor missing')
success_new = '''        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no", (unsigned long)targetIdentities.count]);
        NSUInteger removed = HFAJSONCleanupSuccessfulIntermediates(docs, identityName, igmmName);
        HFAJSONLog([NSString stringWithFormat:@"[ARTIFACT-CLEANUP] status=pass removed=%lu keep=HFAMap_Learn.log,%@,%@",
                    (unsigned long)removed, canonicalName, name]);
        return YES;'''
exporter = exporter.replace(success_anchor, success_new, 1)

# Visible version markers.
for old, new in (
    ('HFAMapUniversal v1.9.37.9 CompleteFeatureExport', 'HFAMapUniversal v1.9.37.10 UnifiedFeatureModel'),
    ('v1.9.37.9 CompleteFeatureExport', 'v1.9.37.10 UnifiedFeatureModel'),
):
    for label, value in [('trace', trace), ('exporter', exporter), ('app', app), ('family', family), ('cyber', cyber), ('legacy', legacy)]:
        pass
    trace = trace.replace(old, new)
    exporter = exporter.replace(old, new)
    app = app.replace(old, new)
    family = family.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)

# Invariants.
for token in (
    'runtimeTargetClass', 'HFAFeatureDefinitionForIdentifier', '[FEATURE-RUNTIME]',
    '[FEATURE-CATALOG-APPEND]', '[FEATURE-CATALOG]', 'runtime-action',
    '@"patches": @[]', 'exportedFeatureIDs',
):
    if token not in trace:
        raise SystemExit(f'missing unified catalog token: {token}')
for token in (
    'HFAJSONCleanupSuccessfulIntermediates', '[ARTIFACT-CLEANUP]',
    'runtimeEvidence', 'if (!identifier.length) continue;', 'if (!label.length) label = identifier;',
):
    if token not in exporter:
        raise SystemExit(f'missing export/cleanup token: {token}')

TRACE.write_text(trace)
EXPORTER.write_text(exporter)
APPLOCAL.write_text(app)
FAMILY.write_text(family)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
print('patched v1.9.37.10: unified feature catalog + successful artifact cleanup')
