from pathlib import Path

FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')
APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')

family = FAMILY.read_text()
exporter = EXPORTER.read_text()
app = APPLOCAL.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()

# ---------------------------------------------------------------------------
# Start every FamilyResolver execution with a fresh observed-menu JSONL file.
# HFAMap_MenuMap.jsonl is written by GenericMenuResolver as controls/actions are
# observed. Truncating it here avoids carrying stale feature IDs from a previous
# scan while keeping GenericMenuResolver itself unchanged.
# ---------------------------------------------------------------------------
reset_anchor = '        HFAGenericMenuResetScanState();\n'
if reset_anchor not in family:
    raise SystemExit('generic reset anchor missing')
if 'HFAMap_MenuMap.jsonl' not in family:
    family = family.replace(
        reset_anchor,
        reset_anchor +
        '        NSString *observedMenuPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_MenuMap.jsonl"];\n'
        '        [[NSFileManager defaultManager] removeItemAtPath:observedMenuPath error:nil];\n'
        '        HFAFamilyLog(@"[OBSERVED-RESET] file=HFAMap_MenuMap.jsonl");\n',
        1,
    )

# ---------------------------------------------------------------------------
# Export helper: parse current-scan GenericMenuResolver JSONL into a stable
# feature list. menu-item records provide identity/title/kind; action records
# enrich the same identifier with target/action/RVA evidence. No target method
# is executed here; this is file-only export processing.
# ---------------------------------------------------------------------------
helper_anchor = 'BOOL HFAMapJSONExportLatest(void) {'
if helper_anchor not in exporter:
    raise SystemExit('export function anchor missing')

helpers = r'''
static NSString *HFAJSONObservedControlKind(NSString *kind) {
    if ([kind isEqualToString:@"switch"]) return @"toggle";
    if ([kind isEqualToString:@"button"]) return @"button";
    if ([kind isEqualToString:@"slider"]) return @"number";
    return @"unknown";
}

static NSArray *HFAJSONObservedFeatures(NSString *path, NSUInteger *recordCountOut) {
    if (recordCountOut) *recordCountOut = 0;
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return @[];
    NSString *text = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
    if (!text.length) return @[];

    NSMutableDictionary<NSString *, NSMutableDictionary *> *byID = [NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *order = [NSMutableArray array];
    NSUInteger parsed = 0;
    NSArray<NSString *> *lines = [text componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
    for (NSString *line in lines) {
        if (!line.length) continue;
        NSData *lineData = [line dataUsingEncoding:NSUTF8StringEncoding];
        if (!lineData.length) continue;
        id value = [NSJSONSerialization JSONObjectWithData:lineData options:0 error:nil];
        if (![value isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *row = (NSDictionary *)value;
        NSString *record = [row[@"record"] isKindOfClass:[NSString class]] ? row[@"record"] : @"";
        if (![record isEqualToString:@"menu-item"] && ![record isEqualToString:@"action"]) continue;
        NSString *identifier = [row[@"identifier"] isKindOfClass:[NSString class]] ? row[@"identifier"] : @"";
        NSString *label = [row[@"label"] isKindOfClass:[NSString class]] ? row[@"label"] : @"";
        if (!identifier.length || !label.length) continue;
        parsed++;

        NSMutableDictionary *feature = byID[identifier];
        if (!feature) {
            feature = [NSMutableDictionary dictionary];
            feature[@"id"] = identifier;
            feature[@"title"] = label;
            feature[@"group"] = @"Imported";
            feature[@"analysisKind"] = @"runtime-observed-feature";
            feature[@"canonicalEligible"] = @NO;
            feature[@"canonicalReason"] = @"runtime-observed-no-static-mapping";
            feature[@"normalizedCanonicalReason"] = @"runtime-observed-no-static-mapping";
            byID[identifier] = feature;
            [order addObject:identifier];
        } else if (label.length) {
            feature[@"title"] = label;
        }

        NSString *kind = [row[@"kind"] isKindOfClass:[NSString class]] ? row[@"kind"] : @"";
        if (kind.length) feature[@"control"] = @{ @"kind": HFAJSONObservedControlKind(kind) };
        NSString *image = [row[@"image"] isKindOfClass:[NSString class]] ? row[@"image"] : @"";
        if (image.length) feature[@"menuImage"] = image;

        if ([record isEqualToString:@"action"]) {
            NSString *targetClass = [row[@"targetClass"] isKindOfClass:[NSString class]] ? row[@"targetClass"] : @"";
            NSString *action = [row[@"action"] isKindOfClass:[NSString class]] ? row[@"action"] : @"";
            NSDictionary *implementation = [row[@"implementation"] isKindOfClass:[NSDictionary class]] ? row[@"implementation"] : @{};
            NSMutableDictionary *runtime = [NSMutableDictionary dictionary];
            if (targetClass.length) runtime[@"targetClass"] = targetClass;
            if (action.length) runtime[@"action"] = action;
            if (implementation.count) runtime[@"implementation"] = implementation;
            feature[@"runtimeEvidence"] = runtime;
            feature[@"analysisKind"] = @"runtime-observed-action";
            feature[@"executionPrimitive"] = @"runtimeAction";
            feature[@"normalizedExecutionPrimitive"] = @"runtimeAction";
            feature[@"canonicalReason"] = @"runtime-action-not-static-bytes";
            feature[@"normalizedCanonicalReason"] = @"runtime-action-not-static-bytes";
        }
    }

    if (recordCountOut) *recordCountOut = parsed;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:order.count];
    for (NSString *identifier in order) {
        NSDictionary *feature = byID[identifier];
        if (feature) [out addObject:feature];
    }
    return out;
}

static void HFAJSONMergeFeatures(NSMutableArray *destination,
                                 NSMutableSet<NSString *> *seenIDs,
                                 NSArray *incoming,
                                 NSUInteger *addedOut,
                                 NSUInteger *dedupedOut) {
    NSUInteger added = 0, deduped = 0;
    for (NSDictionary *feature in incoming) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *identifier = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : @"";
        if (!identifier.length) continue;
        if ([seenIDs containsObject:identifier]) {
            deduped++;
            continue;
        }
        [seenIDs addObject:identifier];
        [destination addObject:feature];
        added++;
    }
    if (addedOut) *addedOut = added;
    if (dedupedOut) *dedupedOut = deduped;
}

'''
if 'HFAJSONObservedFeatures(' not in exporter:
    exporter = exporter.replace(helper_anchor, helpers + helper_anchor, 1)

# Add observed path/read alongside canonical and IGMM sources.
old_paths = '''        NSString *igmmName = [prefix stringByAppendingString:@".hfamap.igmm.json"];
        NSString *canonicalPath = [docs stringByAppendingPathComponent:canonicalName];
        NSString *identityPath = [docs stringByAppendingPathComponent:identityName];
        NSString *igmmPath = [docs stringByAppendingPathComponent:igmmName];

        NSDictionary *canonical = HFAJSONRead(canonicalPath);
        NSDictionary *igmm = HFAJSONRead(igmmPath);
        BOOL haveIdentity = [[NSFileManager defaultManager] fileExistsAtPath:identityPath];

        NSMutableArray *features = [NSMutableArray array];
        NSMutableArray *sources = [NSMutableArray array];
        if ([canonical[@"schema"] isEqual:@"com.hfa.patch/v1"]) {
            [features addObjectsFromArray:HFAJSONCanonicalFeatures(canonical)];
            [sources addObject:@{ @"kind": @"canonical", @"file": canonicalName,
                                  @"schema": @"com.hfa.patch/v1" }];
        }
        if ([igmm[@"schema"] isEqual:@"com.hfa.igmm.runtime/v1"]) {
            [features addObjectsFromArray:HFAJSONIGMMFeatures(igmm)];
            [sources addObject:@{ @"kind": @"igmm-diagnostic", @"file": igmmName,
                                  @"schema": @"com.hfa.igmm.runtime/v1" }];
        }
'''
new_paths = '''        NSString *igmmName = [prefix stringByAppendingString:@".hfamap.igmm.json"];
        NSString *observedName = @"HFAMap_MenuMap.jsonl";
        NSString *canonicalPath = [docs stringByAppendingPathComponent:canonicalName];
        NSString *identityPath = [docs stringByAppendingPathComponent:identityName];
        NSString *igmmPath = [docs stringByAppendingPathComponent:igmmName];
        NSString *observedPath = [docs stringByAppendingPathComponent:observedName];

        NSDictionary *canonical = HFAJSONRead(canonicalPath);
        NSDictionary *igmm = HFAJSONRead(igmmPath);
        NSUInteger observedRecords = 0;
        NSArray *observed = HFAJSONObservedFeatures(observedPath, &observedRecords);
        BOOL haveIdentity = [[NSFileManager defaultManager] fileExistsAtPath:identityPath];

        NSMutableArray *features = [NSMutableArray array];
        NSMutableSet<NSString *> *seenFeatureIDs = [NSMutableSet set];
        NSMutableArray *sources = [NSMutableArray array];
        NSUInteger canonicalAdded = 0, canonicalDeduped = 0;
        NSUInteger igmmAdded = 0, igmmDeduped = 0;
        NSUInteger observedAdded = 0, observedDeduped = 0;
        if ([canonical[@"schema"] isEqual:@"com.hfa.patch/v1"]) {
            HFAJSONMergeFeatures(features, seenFeatureIDs, HFAJSONCanonicalFeatures(canonical), &canonicalAdded, &canonicalDeduped);
            [sources addObject:@{ @"kind": @"canonical", @"file": canonicalName,
                                  @"schema": @"com.hfa.patch/v1" }];
        }
        if ([igmm[@"schema"] isEqual:@"com.hfa.igmm.runtime/v1"]) {
            HFAJSONMergeFeatures(features, seenFeatureIDs, HFAJSONIGMMFeatures(igmm), &igmmAdded, &igmmDeduped);
            [sources addObject:@{ @"kind": @"igmm-diagnostic", @"file": igmmName,
                                  @"schema": @"com.hfa.igmm.runtime/v1" }];
        }
        if (observed.count) {
            HFAJSONMergeFeatures(features, seenFeatureIDs, observed, &observedAdded, &observedDeduped);
            [sources addObject:@{ @"kind": @"observed-runtime", @"file": observedName,
                                  @"schema": @"com.hfa.menu-map/jsonl" }];
            HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT-OBSERVED] records=%lu unique=%lu added=%lu deduped=%lu canonicalAdded=%lu igmmAdded=%lu",
                        (unsigned long)observedRecords, (unsigned long)observed.count,
                        (unsigned long)observedAdded, (unsigned long)observedDeduped,
                        (unsigned long)canonicalAdded, (unsigned long)igmmAdded]);
        }
'''
if old_paths not in exporter:
    raise SystemExit('export source merge block changed')
exporter = exporter.replace(old_paths, new_paths, 1)

# Include observed runtime implementation images in identity resolution.
old_collect = '''        HFAJSONCollectImages(canonical, imageNames);
        HFAJSONCollectImages(igmm, imageNames);'''
new_collect = '''        HFAJSONCollectImages(canonical, imageNames);
        HFAJSONCollectImages(igmm, imageNames);
        HFAJSONCollectImages(observed, imageNames);'''
if old_collect not in exporter:
    raise SystemExit('image collection block missing')
exporter = exporter.replace(old_collect, new_collect, 1)

# Visible analyzer/version markers.
exporter = exporter.replace('HFAMapUniversal v1.9.36.4 JSONExport', 'HFAMapUniversal v1.9.37.9 CompleteFeatureExport')
for old, new in (
    ('HFAMapUniversal v1.9.37.8 StructuralRelationExpansion', 'HFAMapUniversal v1.9.37.9 CompleteFeatureExport'),
    ('v1.9.37.8 StructuralRelationExpansion', 'v1.9.37.9 CompleteFeatureExport'),
):
    app = app.replace(old, new)
    family = family.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)
    exporter = exporter.replace(old, new)

# Generation invariants.
required_export = (
    'HFAJSONObservedFeatures', 'HFAJSONMergeFeatures', 'HFAMap_MenuMap.jsonl',
    'runtime-observed-feature', 'runtime-observed-action', 'runtimeAction',
    'JSON-EXPORT-OBSERVED', 'observed-runtime', 'seenFeatureIDs',
)
for token in required_export:
    if token not in exporter:
        raise SystemExit(f'missing v19379 export token: {token}')
for token in ('[OBSERVED-RESET]', 'HFAMap_MenuMap.jsonl'):
    if token not in family:
        raise SystemExit(f'missing current-scan reset token: {token}')

FAMILY.write_text(family)
EXPORTER.write_text(exporter)
APPLOCAL.write_text(app)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
print('patched v1.9.37.9: merge canonical + IGMM + current observed runtime features by identifier')
