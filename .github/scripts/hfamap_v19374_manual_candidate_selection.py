from pathlib import Path

APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')
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
                if text[j] == '{': depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0: return line_start, j + 1
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
cyber = CYBER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()

# ---------------------------------------------------------------------------
# Discovery v3 helpers: dependency load commands are diagnostic candidates.
# Existing disk/dyld discovery remains intact. Only paths resolving inside the
# current .app are admitted.
# ---------------------------------------------------------------------------
anchor = 'static NSArray<NSDictionary *> *HFAAppLocalEnumerateBundleMachOs(void) {'
helpers = r'''static NSString *HFAAppLocalResolveInstallName(NSString *installName, NSString *ownerPath) {
    if (!installName.length) return nil;
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    NSString *executableDir = NSBundle.mainBundle.executablePath.stringByDeletingLastPathComponent.stringByStandardizingPath;
    NSString *ownerDir = ownerPath.stringByDeletingLastPathComponent.stringByStandardizingPath;
    NSString *resolved = nil;
    if ([installName hasPrefix:@"@executable_path/"]) {
        resolved = [executableDir stringByAppendingPathComponent:[installName substringFromIndex:17]];
    } else if ([installName hasPrefix:@"@loader_path/"]) {
        resolved = [ownerDir stringByAppendingPathComponent:[installName substringFromIndex:13]];
    } else if ([installName hasPrefix:@"@rpath/"]) {
        NSString *suffix = [installName substringFromIndex:7];
        NSArray *roots = @[ [executableDir stringByAppendingPathComponent:@"Frameworks"], ownerDir, bundle ];
        for (NSString *root in roots) {
            NSString *candidate = [root stringByAppendingPathComponent:suffix].stringByStandardizingPath;
            if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) { resolved = candidate; break; }
        }
        if (!resolved) resolved = [[executableDir stringByAppendingPathComponent:@"Frameworks"] stringByAppendingPathComponent:suffix];
    } else if ([installName hasPrefix:@"/"]) {
        resolved = installName;
    }
    resolved = resolved.stringByStandardizingPath;
    return HFAAppLocalPathInsideBundle(resolved) ? resolved : nil;
}

static NSArray<NSDictionary *> *HFAAppLocalDependencyRecords(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    NSMutableArray<NSString *> *owners = [NSMutableArray array];
    if (NSBundle.mainBundle.executablePath.length) [owners addObject:NSBundle.mainBundle.executablePath];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:bundle];
    for (NSString *relative in enumerator) {
        NSString *path = [bundle stringByAppendingPathComponent:relative];
        BOOL directory = NO;
        if (![fm fileExistsAtPath:path isDirectory:&directory] || directory) continue;
        NSData *head = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
        if (HFAAppLocalIsMachOData(head) && ![owners containsObject:path]) [owners addObject:path];
    }

    for (NSString *owner in owners) {
        NSData *data = [NSData dataWithContentsOfFile:owner options:NSDataReadingMappedIfSafe error:nil];
        if (data.length < sizeof(struct mach_header_64)) continue;
        const uint8_t *bytes = data.bytes;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
        if (mh->magic != MH_MAGIC_64) continue;
        if ((uint64_t)sizeof(*mh) + mh->sizeofcmds > data.length) continue;
        const uint8_t *cursor = bytes + sizeof(*mh);
        const uint8_t *end = cursor + mh->sizeofcmds;
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            if (cursor + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)cursor;
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
            BOOL dylibCommand = lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB ||
                                lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LOAD_UPWARD_DYLIB;
            if (dylibCommand && lc->cmdsize >= sizeof(struct dylib_command)) {
                const struct dylib_command *dc = (const struct dylib_command *)cursor;
                uint32_t off = dc->dylib.name.offset;
                if (off < lc->cmdsize) {
                    const char *raw = (const char *)cursor + off;
                    size_t maxLen = lc->cmdsize - off;
                    size_t len = strnlen(raw, maxLen);
                    if (len && len < maxLen) {
                        NSString *installName = [[NSString alloc] initWithBytes:raw length:len encoding:NSUTF8StringEncoding];
                        NSString *resolved = HFAAppLocalResolveInstallName(installName, owner);
                        if (resolved.length && [resolved.pathExtension.lowercaseString isEqualToString:@"dylib"] && ![seen containsObject:resolved]) {
                            [seen addObject:resolved];
                            BOOL exists = [fm fileExistsAtPath:resolved];
                            int loadedIndex = HFAAppLocalLoadedIndex(resolved);
                            NSString *command = lc->cmd == LC_LOAD_DYLIB ? @"LC_LOAD_DYLIB" :
                                                (lc->cmd == LC_LOAD_WEAK_DYLIB ? @"LC_LOAD_WEAK_DYLIB" :
                                                (lc->cmd == LC_REEXPORT_DYLIB ? @"LC_REEXPORT_DYLIB" : @"LC_LOAD_UPWARD_DYLIB"));
                            NSDictionary *record = @{ @"path": resolved,
                                                      @"image": resolved.lastPathComponent ?: @"?",
                                                      @"installName": installName ?: @"?",
                                                      @"dependencyOwner": owner.lastPathComponent ?: @"?",
                                                      @"dependencyCommand": command,
                                                      @"exists": @(exists),
                                                      @"loadedIndex": @(loadedIndex) };
                            [records addObject:record];
                            HFAAppLocalLog([NSString stringWithFormat:@"[DEPENDENCY] owner=%@ command=%@ installName=%@ resolvedPath=%@ exists=%@ loaded=%@ index=%d",
                                            record[@"dependencyOwner"], command, installName, resolved,
                                            exists ? @"yes" : @"no", loadedIndex >= 0 ? @"yes" : @"no", loadedIndex]);
                        }
#if !__has_feature(objc_arc)
                        [installName release];
#endif
                    }
                }
            }
            cursor += lc->cmdsize;
        }
    }
    return records;
}

'''
if 'HFAAppLocalDependencyRecords' not in app:
    pos = app.find(anchor)
    if pos < 0: raise SystemExit('enumerator anchor missing')
    app = app[:pos] + helpers + app[pos:]

# Merge dependency-backed files into normal discovery when the resolved file is
# actually present. Missing dependency paths remain visible through logs only.
enum_start, enum_end = function_span(app, 'HFAAppLocalEnumerateBundleMachOs')
enum_text = app[enum_start:enum_end]
needle = '''    uint32_t imageCount = _dyld_image_count();\n'''
insert = '''    NSArray<NSDictionary *> *dependencies = HFAAppLocalDependencyRecords();\n    unsigned dependencyHits = 0;\n    for (NSDictionary *dependency in dependencies) {\n        NSString *path = dependency[@"path"];\n        if (![dependency[@"exists"] boolValue]) continue;\n        int loadedIndex = [dependency[@"loadedIndex"] intValue];\n        if (HFAAppLocalMergeDiscoveredDylib(records, path, @"dependency", loadedIndex)) dependencyHits++;\n    }\n\n    uint32_t imageCount = _dyld_image_count();\n'''
if 'dependencyHits' not in enum_text:
    enum_text = once(enum_text, needle, insert, 'merge dependency discovery')
    enum_text = enum_text.replace('diskHits=%u dyldHits=%u uniqueDylibs=%lu', 'diskHits=%u dyldHits=%u dependencyHits=%u uniqueDylibs=%lu')
    enum_text = enum_text.replace('diskHits, dyldHits, (unsigned long)result.count', 'diskHits, dyldHits, dependencyHits, (unsigned long)result.count')
    app = app[:enum_start] + enum_text + app[enum_end:]

# ---------------------------------------------------------------------------
# Manual selection: scan stores candidates but intentionally leaves primary
# unset. UI must select exactly one candidate before parser execution.
# ---------------------------------------------------------------------------
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
        }
        [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            BOOL la = [a[@"loaded"] boolValue], lb = [b[@"loaded"] boolValue];
            if (la != lb) return la ? NSOrderedAscending : NSOrderedDescending;
            NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
            if (sa != sb) return sa > sb ? NSOrderedAscending : NSOrderedDescending;
            return [a[@"path"] compare:b[@"path"]];
        }];
        @synchronized([NSObject class]) {
#if !__has_feature(objc_arc)
            [gHFAAppLocalCandidates release];
#endif
            gHFAAppLocalCandidates = [found mutableCopy];
            gHFAAppLocalPrimaryImage[0] = 0;
            gHFAAppLocalPrimaryFamily[0] = 0;
            gHFAAppLocalPrimaryVariant[0] = 0;
            gHFAAppLocalPrimaryPath[0] = 0;
            gHFAAppLocalPrimaryLoadedIndex = -1;
        }
        HFAAppLocalWriteIndex(found, discovered.count);
        HFAAppLocalLog([NSString stringWithFormat:@"[SELECT-WAIT] candidates=%lu manualSelectionRequired=1", (unsigned long)found.count]);
        if (found.count) HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：发现 %lu 个候选，请手动选择", (unsigned long)found.count]);
        else HFACyberUIAppendLog(@"❌ 没有识别到已知菜单 dylib");
        return (unsigned)found.count;
    }
}'''
app = replace_named_function(app, 'HFAAppLocalScanCandidates', scan)

selection_api = r'''
NSArray *HFAAppLocalCopyCandidates(void) {
    @synchronized([NSObject class]) {
        return [[gHFAAppLocalCandidates copy] autorelease] ?: @[];
    }
}

BOOL HFAAppLocalSelectCandidateAtIndex(NSUInteger index) {
    @synchronized([NSObject class]) {
        if (index >= gHFAAppLocalCandidates.count) return NO;
        NSDictionary *record = gHFAAppLocalCandidates[index];
        snprintf(gHFAAppLocalPrimaryImage, sizeof(gHFAAppLocalPrimaryImage), "%s", [record[@"image"] UTF8String] ?: "");
        snprintf(gHFAAppLocalPrimaryFamily, sizeof(gHFAAppLocalPrimaryFamily), "%s", [record[@"family"] UTF8String] ?: "");
        snprintf(gHFAAppLocalPrimaryVariant, sizeof(gHFAAppLocalPrimaryVariant), "%s", [record[@"variant"] UTF8String] ?: "");
        snprintf(gHFAAppLocalPrimaryPath, sizeof(gHFAAppLocalPrimaryPath), "%s", [record[@"path"] UTF8String] ?: "");
        gHFAAppLocalPrimaryLoadedIndex = [record[@"loadedIndex"] intValue];
        HFAAppLocalLog([NSString stringWithFormat:@"[MANUAL-SELECT] index=%lu image=%@ family=%@ variant=%@ loaded=%@ loadedIndex=%@ path=%@ sources=%@",
                        (unsigned long)index, record[@"image"], record[@"family"], record[@"variant"],
                        [record[@"loaded"] boolValue] ? @"yes" : @"no", record[@"loadedIndex"], record[@"path"],
                        [record[@"discoverySources"] componentsJoinedByString:@","]]);
        return YES;
    }
}

BOOL HFAAppLocalHasManualSelection(void) {
    return gHFAAppLocalPrimaryPath[0] != 0;
}
'''
getter_anchor = 'const char *HFAAppLocalPrimaryImage(void) {'
if 'HFAAppLocalCopyCandidates' not in app:
    pos = app.find(getter_anchor)
    if pos < 0: raise SystemExit('primary getter anchor missing')
    app = app[:pos] + selection_api + '\n' + app[pos:]

# ---------------------------------------------------------------------------
# Cyber UI: scan -> show selector. Parse is blocked until manual choice.
# ---------------------------------------------------------------------------
extern_anchor = 'extern unsigned HFAAppLocalExecuteParser(void);\n'
cyber = once(cyber, extern_anchor, extern_anchor + 'extern NSArray *HFAAppLocalCopyCandidates(void);\nextern BOOL HFAAppLocalSelectCandidateAtIndex(NSUInteger index);\nextern BOOL HFAAppLocalHasManualSelection(void);\n', 'manual selection API externs')

show_selector = r'''
- (void)showCandidateSelector {
    NSArray *candidates = HFAAppLocalCopyCandidates();
    if (!candidates.count) {
        HFACyberUIAppendLog(@"[SELECTOR] 没有可选择的候选");
        return;
    }
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"选择菜单 dylib"
                                                                    message:@"扫描完成。请选择后续要解析的模块。"
                                                             preferredStyle:UIAlertControllerStyleAlert];
    NSUInteger limit = MIN(candidates.count, (NSUInteger)16);
    for (NSUInteger i = 0; i < limit; i++) {
        NSDictionary *record = candidates[i];
        NSString *sources = [record[@"discoverySources"] componentsJoinedByString:@","] ?: @"?";
        NSString *title = [NSString stringWithFormat:@"%lu. %@ | %@ | %@ | %@",
                           (unsigned long)(i + 1), record[@"image"] ?: @"?", record[@"family"] ?: @"unknown",
                           [record[@"loaded"] boolValue] ? @"loaded" : @"not-loaded", sources];
        [alert addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
            if (HFAAppLocalSelectCandidateAtIndex(i)) {
                HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 已手动选择：%@", record[@"image"] ?: @"?"]);
                HFACyberUIAppendLog([NSString stringWithFormat:@"[PATH] %@", record[@"path"] ?: @"?"]);
            } else {
                HFACyberUIAppendLog(@"❌ 选择失败，请重新扫描");
            }
        }]];
    }
    if (candidates.count > limit) {
        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"其余 %lu 个仅写入日志", (unsigned long)(candidates.count - limit)] style:UIAlertActionStyleDefault handler:nil]];
    }
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    UIViewController *presenter = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (presenter.presentedViewController) presenter = presenter.presentedViewController;
    if (presenter) [presenter presentViewController:alert animated:YES completion:nil];
}

'''
impl_anchor = '@implementation HFACyberUIController\n'
if 'showCandidateSelector' not in cyber:
    cyber = once(cyber, impl_anchor, impl_anchor + show_selector, 'candidate selector method')

scan_method = r'''- (void)actionCyberScan:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 扫描菜单模块");
    HFACyberUIAppendLog(@"[DISCOVERY] recursive app-local + dyld + Mach-O dependencies ...");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        unsigned count = HFAAppLocalScanCandidates();
        HFACyberUIAppendLog([NSString stringWithFormat:@"[DISCOVERY-END] candidates=%u", count]);
        dispatch_async(dispatch_get_main_queue(), ^{
            sender.enabled = YES;
            if (count) [self showCandidateSelector];
        });
    });
}'''
cyber = replace_named_function(cyber, '- (void)actionCyberScan:', scan_method)

export_method = r'''- (void)actionCyberExport:(UIButton *)sender {
    if (!HFAAppLocalHasManualSelection()) {
        HFACyberUIAppendLog(@"❌ 请先扫描并手动选择一个菜单 dylib");
        return;
    }
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 解析并导出");
    HFACyberUIAppendLog(@"[RESOLVE] selected image-local parser starting ...");
    dispatch_async(dispatch_get_main_queue(), ^{
        unsigned valid = HFAAppLocalExecuteParser();
        HFACyberUIAppendLog([NSString stringWithFormat:@"[EXPORT-END] validMappings=%u", valid]);
        sender.enabled = YES;
    });
}'''
cyber = replace_named_function(cyber, '- (void)actionCyberExport:', export_method)

cyber = cyber.replace('[System] 先扫描菜单模块，再解析并导出。', '[System] 先扫描菜单模块，手动选择目标，再解析并导出。')

for old, new in (
    ('HFAMapUniversal v1.9.37.3 AppLocalDylibDiscoveryV2', 'HFAMapUniversal v1.9.37.4 ManualCandidateSelection'),
    ('v1.9.37.3 AppLocalDylibDiscoveryV2', 'v1.9.37.4 ManualCandidateSelection'),
    ('HFAMap v1.9.37.3 AppLocalDylibDiscoveryV2', 'HFAMap v1.9.37.4 ManualCandidateSelection'),
):
    app = app.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)
    exporter = exporter.replace(old, new)

# Hard checks.
for token in ('[DEPENDENCY]', 'LC_LOAD_DYLIB', '@executable_path/', 'HFAAppLocalCopyCandidates', 'HFAAppLocalSelectCandidateAtIndex', '[SELECT-WAIT]', '[MANUAL-SELECT]'):
    if token not in app:
        raise SystemExit(f'missing v19374 app-local token: {token}')
for token in ('showCandidateSelector', 'HFAAppLocalHasManualSelection', '请先扫描并手动选择一个菜单 dylib'):
    if token not in cyber:
        raise SystemExit(f'missing v19374 cyber token: {token}')
if '[SELECT] primary=' in function_span.__name__:
    raise SystemExit('unreachable guard')
for forbidden in ('objc_getClassList', '_dyld_register_func_for_add_image'):
    if forbidden in app:
        raise SystemExit(f'forbidden discovery regression: {forbidden}')

APPLOCAL.write_text(app)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
EXPORTER.write_text(exporter)
print('patched v1.9.37.4: dependency discovery + manual candidate selection')
