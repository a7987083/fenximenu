from pathlib import Path

APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')


def function_span(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        line_start = text.rfind('\n', 0, i) + 1
        prefix = text[line_start:i].strip()
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi) and prefix and not prefix.startswith(('if', 'for', 'while', 'return')):
            depth = 0
            for j in range(brace, len(text)):
                if text[j] == '{':
                    depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0:
                        return line_start, j + 1
            raise SystemExit(f'{name}: closing brace not found')
        pos = i + len(needle)


def replace_named_function(text, name, replacement):
    start, end = function_span(text, name)
    return text[:start] + replacement + text[end:]


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)


app = APPLOCAL.read_text()
legacy = LEGACY.read_text()
cyber = CYBER.read_text()
exporter = EXPORTER.read_text()

# Discovery v2: only app-local .dylib files, but search the whole .app tree and
# merge exact dyld-loaded app-local .dylib paths as a second evidence source.
# No process-wide class enumeration, no framework-executable fallback, no size
# family heuristics.
helper_anchor = 'static void HFAAppLocalAddMachO(NSMutableArray<NSString *> *paths, NSString *path) {'
helper_replacement = r'''static BOOL HFAAppLocalPathInsideBundle(NSString *path) {
    if (!path.length) return NO;
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    NSString *standard = path.stringByStandardizingPath;
    if (!bundle.length || !standard.length) return NO;
    NSString *prefix = [bundle stringByAppendingString:@"/"];
    return [standard hasPrefix:prefix];
}

static BOOL HFAAppLocalMergeDiscoveredDylib(NSMutableDictionary<NSString *, NSMutableDictionary *> *records,
                                             NSString *path,
                                             NSString *source,
                                             int loadedIndex) {
    if (!records || !path.length || !source.length) return NO;
    if (![path.pathExtension.lowercaseString isEqualToString:@"dylib"]) return NO;
    NSString *standard = path.stringByStandardizingPath;
    if (!HFAAppLocalPathInsideBundle(standard)) return NO;
    if ([standard.lastPathComponent containsString:@"HFAMapUniversal"]) return NO;
    BOOL directory = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:standard isDirectory:&directory] || directory) return NO;
    NSData *data = [NSData dataWithContentsOfFile:standard options:NSDataReadingMappedIfSafe error:nil];
    if (!HFAAppLocalIsMachOData(data)) return NO;

    NSMutableDictionary *record = records[standard];
    if (!record) {
        record = [@{ @"path": standard,
                     @"image": standard.lastPathComponent ?: @"?",
                     @"sources": [NSMutableArray array],
                     @"dyldIndex": @(-1) } mutableCopy];
        records[standard] = record;
#if !__has_feature(objc_arc)
        [record release];
#endif
    }
    NSMutableArray *sources = record[@"sources"];
    if (![sources containsObject:source]) [sources addObject:source];
    if (loadedIndex >= 0) record[@"dyldIndex"] = @(loadedIndex);
    return YES;
}'''
app = replace_named_function(app, 'HFAAppLocalAddMachO', helper_replacement)

enumerator = r'''static NSArray<NSDictionary *> *HFAAppLocalEnumerateBundleMachOs(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSMutableDictionary<NSString *, NSMutableDictionary *> *records = [NSMutableDictionary dictionary];
    unsigned diskHits = 0;
    unsigned dyldHits = 0;

    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:bundle];
    for (NSString *relative in enumerator) {
        if (![relative.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        NSString *path = [bundle stringByAppendingPathComponent:relative];
        if (HFAAppLocalMergeDiscoveredDylib(records, path, @"disk", -1)) diskHits++;
    }

    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if (!path.length || !HFAAppLocalPathInsideBundle(path)) continue;
        if (![path.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        if (HFAAppLocalMergeDiscoveredDylib(records, path, @"dyld", (int)i)) dyldHits++;
    }

    NSArray<NSDictionary *> *result = [records.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"path"] compare:b[@"path"]];
    }];
    HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY-V2] diskHits=%u dyldHits=%u uniqueDylibs=%lu",
                    diskHits, dyldHits, (unsigned long)result.count]);
    for (NSDictionary *record in result) {
        NSArray *sources = record[@"sources"];
        HFAAppLocalLog([NSString stringWithFormat:@"[DYLIB] path=%@ sources=%@ dyldIndex=%@",
                        record[@"path"], [sources componentsJoinedByString:@","], record[@"dyldIndex"]]);
    }
    return result;
}'''
app = replace_named_function(app, 'HFAAppLocalEnumerateBundleMachOs', enumerator)

scan = r'''unsigned HFAAppLocalScanCandidates(void) {
    @autoreleasepool {
        NSArray<NSDictionary *> *discovered = HFAAppLocalEnumerateBundleMachOs();
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] app-local dylibs=%lu", (unsigned long)discovered.count]);
        NSMutableArray<NSDictionary *> *found = [NSMutableArray array];
        for (NSDictionary *discovery in discovered) {
            NSString *path = discovery[@"path"];
            NSData *data = HFAAppLocalMappedData(path);
            if (!data.length) continue;
            NSMutableDictionary *record = [[HFAAppLocalFingerprint(path, data) mutableCopy] autorelease];
            record[@"discoverySources"] = discovery[@"sources"] ?: @[];
            record[@"discoveryDyldIndex"] = discovery[@"dyldIndex"] ?: @(-1);
            if (![record[@"score"] unsignedIntValue]) {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] image=%@ path=%@ sources=%@ reason=no-known-family-structure",
                                record[@"image"], record[@"path"],
                                [record[@"discoverySources"] componentsJoinedByString:@","]]);
                continue;
            }
            [found addObject:record];
            HFAAppLocalLog([NSString stringWithFormat:@"[CANDIDATE] image=%@ family=%@ variant=%@ score=%@ classes=%@ loaded=%@ loadedIndex=%@ sources=%@ path=%@",
                            record[@"image"], record[@"family"], record[@"variant"], record[@"score"],
                            record[@"objcClassCount"], [record[@"loaded"] boolValue] ? @"yes" : @"no",
                            record[@"loadedIndex"], [record[@"discoverySources"] componentsJoinedByString:@","],
                            record[@"path"]]);
            for (NSString *hit in record[@"evidence"])
                HFAAppLocalLog([NSString stringWithFormat:@"  [HIT] %@", hit]);
        }

        [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            BOOL la = [a[@"loaded"] boolValue], lb = [b[@"loaded"] boolValue];
            if (la != lb) return la ? NSOrderedAscending : NSOrderedDescending;
            NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
            if (sa != sb) return sa > sb ? NSOrderedAscending : NSOrderedDescending;
            return [a[@"path"] compare:b[@"path"]];
        }];

        NSMutableArray<NSDictionary *> *deduped = [NSMutableArray array];
        NSMutableSet<NSNumber *> *loadedIndexes = [NSMutableSet set];
        NSMutableSet<NSString *> *unloadedPaths = [NSMutableSet set];
        for (NSDictionary *record in found) {
            int loadedIndex = [record[@"loadedIndex"] intValue];
            if (loadedIndex >= 0) {
                NSNumber *key = @(loadedIndex);
                if ([loadedIndexes containsObject:key]) continue;
                [loadedIndexes addObject:key];
            } else {
                NSString *key = [record[@"path"] stringByStandardizingPath];
                if ([unloadedPaths containsObject:key]) continue;
                [unloadedPaths addObject:key];
            }
            [deduped addObject:record];
        }

        NSDictionary *primary = nil;
        for (NSDictionary *record in deduped) {
            if ([record[@"loaded"] boolValue]) { primary = record; break; }
        }
        if (!primary && deduped.count) primary = deduped.firstObject;

        @synchronized([NSObject class]) {
#if !__has_feature(objc_arc)
            [gHFAAppLocalCandidates release];
#endif
            gHFAAppLocalCandidates = [deduped mutableCopy];
            gHFAAppLocalPrimaryImage[0] = 0;
            gHFAAppLocalPrimaryFamily[0] = 0;
            gHFAAppLocalPrimaryVariant[0] = 0;
            gHFAAppLocalPrimaryPath[0] = 0;
            gHFAAppLocalPrimaryLoadedIndex = -1;
            if (primary) {
                snprintf(gHFAAppLocalPrimaryImage, sizeof(gHFAAppLocalPrimaryImage), "%s",
                         [primary[@"image"] UTF8String] ?: "");
                snprintf(gHFAAppLocalPrimaryFamily, sizeof(gHFAAppLocalPrimaryFamily), "%s",
                         [primary[@"family"] UTF8String] ?: "");
                snprintf(gHFAAppLocalPrimaryVariant, sizeof(gHFAAppLocalPrimaryVariant), "%s",
                         [primary[@"variant"] UTF8String] ?: "");
                snprintf(gHFAAppLocalPrimaryPath, sizeof(gHFAAppLocalPrimaryPath), "%s",
                         [primary[@"path"] UTF8String] ?: "");
                gHFAAppLocalPrimaryLoadedIndex = [primary[@"loadedIndex"] intValue];
            }
        }

        HFAAppLocalWriteIndex(deduped, discovered.count);
        if (primary) {
            HFAAppLocalLog([NSString stringWithFormat:@"[SELECT] primary=%@ family=%@ variant=%@ score=%@ loaded=%@ index=%@ path=%@ sources=%@",
                            primary[@"image"], primary[@"family"], primary[@"variant"], primary[@"score"],
                            [primary[@"loaded"] boolValue] ? @"yes" : @"no", primary[@"loadedIndex"],
                            primary[@"path"], [primary[@"discoverySources"] componentsJoinedByString:@","]]);
            NSString *displayFamily = [primary[@"family"] isEqual:@"runtime-5m"] ? @"Runtime-5M" :
                                      ([primary[@"family"] isEqual:@"legacy-ap"] ? @"Legacy-AP" : primary[@"family"]);
            HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 已识别：%@ | %@ | %@",
                                  primary[@"image"], displayFamily, primary[@"variant"]]);
        } else {
            HFAAppLocalLog(@"[SELECT] no known family dylib found");
            HFACyberUIAppendLog(@"❌ 没有识别到已知菜单 dylib");
        }
        return (unsigned)deduped.count;
    }
}'''
app = replace_named_function(app, 'HFAAppLocalScanCandidates', scan)

# Candidate-index schema/version: retain old field for downstream compatibility,
# add explicit v2 discovery count and use structure names in visible output.
app = app.replace('@"schema": @"com.hfa.app-local-candidates/v1"', '@"schema": @"com.hfa.app-local-candidates/v2"')
app = app.replace('@"scannedMachOCount": @(scannedCount),', '@"scannedMachOCount": @(scannedCount),\n        @"discoveredDylibCount": @(scannedCount),')

for old, new in (
    ('HFAMapUniversal v1.9.37.2 5MDualBackendFix', 'HFAMapUniversal v1.9.37.3 AppLocalDylibDiscoveryV2'),
    ('v1.9.37.2 5MDualBackendFix', 'v1.9.37.3 AppLocalDylibDiscoveryV2'),
    ('HFAMap v1.9.37 CleanFamilyResolver', 'HFAMap v1.9.37.3 AppLocalDylibDiscoveryV2'),
):
    app = app.replace(old, new)
    legacy = legacy.replace(old, new)
    cyber = cyber.replace(old, new)
    exporter = exporter.replace(old, new)

# Hard generation checks.
required = (
    '[DISCOVERY-V2]',
    '[DYLIB] path=',
    'enumeratorAtPath:bundle',
    '_dyld_image_count()',
    'HFAAppLocalPathInsideBundle',
    'path.pathExtension.lowercaseString',
    'discoverySources',
    'com.hfa.app-local-candidates/v2',
    'discoveredDylibCount',
)
for token in required:
    if token not in app:
        raise SystemExit(f'missing discovery v2 token: {token}')
for forbidden in ('objc_getClassList', '_dyld_register_func_for_add_image', 'size=%.2fMB'):
    if forbidden in app:
        raise SystemExit(f'forbidden discovery regression: {forbidden}')
if 'Frameworks' in function_span.__name__:  # no-op, keeps linter quiet
    pass

APPLOCAL.write_text(app)
LEGACY.write_text(legacy)
CYBER.write_text(cyber)
EXPORTER.write_text(exporter)
print('patched v1.9.37.3 AppLocalDylibDiscoveryV2: recursive app-local dylib discovery + dyld merge')
