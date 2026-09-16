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
        if brace >= 0 and (semi < 0 or brace < semi) and prefix and not prefix.startswith(('if','for','while','return')):
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


app = APPLOCAL.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()

merge = r'''static BOOL HFAAppLocalMergeDiscoveredDylib(NSMutableDictionary<NSString *, NSMutableDictionary *> *records,
                                             NSString *path,
                                             NSString *source,
                                             int loadedIndex) {
    if (!records || !path.length || !source.length) return NO;
    if (![path.pathExtension.lowercaseString isEqualToString:@"dylib"]) return NO;
    NSString *standard = HFAAppLocalCanonicalPath(path);
    if (!HFAAppLocalPathInsideBundle(standard)) return NO;
    if ([standard.lastPathComponent containsString:@"HFAMapUniversal"]) return NO;

    BOOL validMachO = NO;
    BOOL diskAvailable = NO;
    BOOL directory = NO;
    if ([[NSFileManager defaultManager] fileExistsAtPath:standard isDirectory:&directory] && !directory) {
        NSData *data = [NSData dataWithContentsOfFile:standard options:NSDataReadingMappedIfSafe error:nil];
        validMachO = HFAAppLocalIsMachOData(data);
        diskAvailable = validMachO;
    }
    if (!validMachO && loadedIndex >= 0 && (uint32_t)loadedIndex < _dyld_image_count()) {
        const struct mach_header *mh = _dyld_get_image_header((uint32_t)loadedIndex);
        validMachO = mh && mh->magic == MH_MAGIC_64;
    }
    if (!validMachO) return NO;

    NSMutableDictionary *record = records[standard];
    if (!record) {
        record = [@{ @"path": standard,
                     @"image": standard.lastPathComponent ?: @"?",
                     @"sources": [NSMutableArray array],
                     @"dyldIndex": @(loadedIndex >= 0 ? loadedIndex : -1),
                     @"diskAvailable": @(diskAvailable) } mutableCopy];
        records[standard] = record;
#if !__has_feature(objc_arc)
        [record release];
#endif
    }
    NSMutableArray *sources = record[@"sources"];
    if (![sources containsObject:source]) [sources addObject:source];
    if (loadedIndex >= 0) record[@"dyldIndex"] = @(loadedIndex);
    if (diskAvailable) record[@"diskAvailable"] = @YES;
    return YES;
}'''
app = replace_named_function(app, 'HFAAppLocalMergeDiscoveredDylib', merge)

# Add in-memory section fingerprint helpers before the static file fingerprint.
anchor = 'static NSDictionary *HFAAppLocalFingerprint(NSString *path, NSData *data) {'
helpers = r'''static BOOL HFAAppLocalMemoryContains(const uint8_t *bytes, uint64_t size, const char *needle) {
    if (!bytes || !size || !needle || !needle[0]) return NO;
    size_t n = strlen(needle);
    if (!n || size < n) return NO;
    for (uint64_t i = 0; i + n <= size; i++) {
        if (bytes[i] == (uint8_t)needle[0] && memcmp(bytes + i, needle, n) == 0) return YES;
    }
    return NO;
}

static BOOL HFAAppLocalLoadedImageHas(int loadedIndex, const char *needle) {
    if (loadedIndex < 0 || (uint32_t)loadedIndex >= _dyld_image_count()) return NO;
    const struct mach_header *raw = _dyld_get_image_header((uint32_t)loadedIndex);
    if (!raw || raw->magic != MH_MAGIC_64) return NO;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)raw;
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)loadedIndex);
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc || lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            uint64_t required = sizeof(*seg) + (uint64_t)seg->nsects * sizeof(*sec);
            if (required <= lc->cmdsize) {
                for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                    if (!sec->size || sec->size > (128ULL * 1024ULL * 1024ULL)) continue;
                    uint32_t stype = sec->flags & SECTION_TYPE;
                    if (stype == S_ZEROFILL || stype == S_GB_ZEROFILL || stype == S_THREAD_LOCAL_ZEROFILL) continue;
                    const uint8_t *sectionBytes = (const uint8_t *)(uintptr_t)(sec->addr + slide);
                    if (HFAAppLocalMemoryContains(sectionBytes, sec->size, needle)) return YES;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static unsigned HFAAppLocalLoadedObjCClassCount(int loadedIndex) {
    if (loadedIndex < 0 || (uint32_t)loadedIndex >= _dyld_image_count()) return 0;
    const struct mach_header *raw = _dyld_get_image_header((uint32_t)loadedIndex);
    if (!raw || raw->magic != MH_MAGIC_64) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)raw;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    unsigned count = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc || lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            uint64_t required = sizeof(*seg) + (uint64_t)seg->nsects * sizeof(*sec);
            if (required <= lc->cmdsize) {
                for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                    if (strncmp(sec->sectname, "__objc_classlist", 16) == 0 && sec->size % sizeof(uint64_t) == 0)
                        count += (unsigned)(sec->size / sizeof(uint64_t));
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return count;
}

static NSDictionary *HFAAppLocalFingerprintLoaded(NSString *path, int loadedIndex) {
    NSMutableArray<NSString *> *evidence = [NSMutableArray array];
#define HFA_MEM_HAS(x) HFAAppLocalLoadedImageHas(loadedIndex, x)
    BOOL appPatch = HFA_MEM_HAS("APPatchItem");
    BOOL secretInt = HFA_MEM_HAS("IGSecretInt");
    BOOL secretData = HFA_MEM_HAS("IGSecretData");
    BOOL secretString = HFA_MEM_HAS("IGSecretString");
    BOOL subpatch = HFA_MEM_HAS("APSubpatchManager");
    BOOL codePatch = HFA_MEM_HAS("IGCodePatch");
    BOOL customSwitch = HFA_MEM_HAS("customSwitch");
    BOOL modslider = HFA_MEM_HAS("modslider");
    BOOL modtext = HFA_MEM_HAS("modtext");
    BOOL typeButton = HFA_MEM_HAS("kTypeButton");
    BOOL identifier = HFA_MEM_HAS("identifier");
    BOOL label = HFA_MEM_HAS("label");
    BOOL appKeyMetadata = HFA_MEM_HAS(".app-key-metadata-");
    BOOL validator = HFA_MEM_HAS("JailpatchConfigValidator");
    BOOL runtimeTable = HFA_MEM_HAS("Jailpatch runtime table");
    BOOL jailpatch = HFA_MEM_HAS("jailpatch");
#undef HFA_MEM_HAS
    struct EvidenceToken { BOOL hit; const char *name; } hits[] = {
        {appPatch,"legacy:APPatchItem"},{secretInt,"legacy:IGSecretInt"},{secretData,"legacy:IGSecretData"},
        {secretString,"legacy:IGSecretString"},{subpatch,"legacy:APSubpatchManager"},{codePatch,"legacy:IGCodePatch"},
        {customSwitch,"runtime:customSwitch"},{modslider,"runtime:modslider"},{modtext,"runtime:modtext"},
        {typeButton,"runtime:kTypeButton"},{identifier,"runtime:identifier"},{label,"runtime:label"},
        {appKeyMetadata,"runtime:.app-key-metadata-"},{validator,"runtime:JailpatchConfigValidator"},
        {runtimeTable,"runtime:Jailpatch runtime table"},{jailpatch,"runtime:jailpatch"}
    };
    for (unsigned i = 0; i < sizeof(hits)/sizeof(hits[0]); i++) if (hits[i].hit)
        [evidence addObject:[NSString stringWithUTF8String:hits[i].name]];
    BOOL legacyCore = appPatch && secretInt && (secretData || subpatch || codePatch);
    BOOL runtimeCore = customSwitch && modtext && typeButton && identifier && label;
    NSString *family=@"unknown", *variant=@"unknown"; unsigned score=0;
    unsigned objcClassCount = HFAAppLocalLoadedObjCClassCount(loadedIndex);
    if (legacyCore) { family=@"legacy-ap"; variant=@"A"; score=100; }
    else if (runtimeCore) {
        family=@"runtime-5m";
        if (objcClassCount >= 201) variant=@"B-extended";
        else if (!validator && !runtimeTable) variant=@"C-alternate";
        else if (validator && runtimeTable) variant=@"A-standard";
        else variant=@"unclassified";
        score = appKeyMetadata ? 100 : 90;
    }
    if (objcClassCount) [evidence addObject:[NSString stringWithFormat:@"objc:classes=%u", objcClassCount]];
    [evidence addObject:@"source:loaded-memory"];
    return @{ @"path": path ?: @"", @"image": path.lastPathComponent ?: @"?", @"family": family,
              @"variant": variant, @"score": @(score), @"objcClassCount": @(objcClassCount),
              @"loaded": @YES, @"loadedIndex": @(loadedIndex), @"evidence": evidence };
}

'''
if 'HFAAppLocalFingerprintLoaded' not in app:
    pos = app.find(anchor)
    if pos < 0: raise SystemExit('fingerprint anchor missing')
    app = app[:pos] + helpers + app[pos:]

# Replace discovery so loaded dyld paths are admitted even when the backing file
# is no longer visible. Dependency loadedIndex is converted back to dyld's exact
# path, avoiding /var vs /private/var ambiguity.
enum_start, enum_end = function_span(app, 'HFAAppLocalEnumerateBundleMachOs')
enum_text = app[enum_start:enum_end]
old_dep = '''    for (NSDictionary *dependency in dependencies) {\n        NSString *path = dependency[@"path"];\n        if (![dependency[@"exists"] boolValue]) continue;\n        int loadedIndex = [dependency[@"loadedIndex"] intValue];\n        if (HFAAppLocalMergeDiscoveredDylib(records, path, @"dependency", loadedIndex)) dependencyHits++;\n    }'''
new_dep = '''    for (NSDictionary *dependency in dependencies) {\n        NSString *path = dependency[@"path"];\n        int loadedIndex = [dependency[@"loadedIndex"] intValue];\n        if (loadedIndex >= 0 && (uint32_t)loadedIndex < _dyld_image_count()) {\n            const char *rawLoaded = _dyld_get_image_name((uint32_t)loadedIndex);\n            if (rawLoaded) path = [NSString stringWithUTF8String:rawLoaded];\n        } else if (![dependency[@"exists"] boolValue]) {\n            continue;\n        }\n        if (HFAAppLocalMergeDiscoveredDylib(records, path, @"dependency", loadedIndex)) dependencyHits++;\n    }'''
if old_dep not in enum_text: raise SystemExit('dependency merge block not found')
enum_text = enum_text.replace(old_dep, new_dep, 1)
app = app[:enum_start] + enum_text + app[enum_end:]

scan = r'''unsigned HFAAppLocalScanCandidates(void) {
    @autoreleasepool {
        NSArray<NSDictionary *> *discovered = HFAAppLocalEnumerateBundleMachOs();
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] app-local dylibs=%lu", (unsigned long)discovered.count]);
        NSMutableArray<NSDictionary *> *found = [NSMutableArray array];
        for (NSDictionary *discovery in discovered) {
            NSString *path = discovery[@"path"];
            int dyldIndex = [discovery[@"dyldIndex"] intValue];
            NSData *data = HFAAppLocalMappedData(path);
            NSMutableDictionary *record = nil;
            if (data.length) {
                record = [[HFAAppLocalFingerprint(path, data) mutableCopy] autorelease];
            } else if (dyldIndex >= 0) {
                record = [[HFAAppLocalFingerprintLoaded(path, dyldIndex) mutableCopy] autorelease];
                HFAAppLocalLog([NSString stringWithFormat:@"[MEMORY-FINGERPRINT] image=%@ loadedIndex=%d path=%@", path.lastPathComponent, dyldIndex, path]);
            } else {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] image=%@ path=%@ reason=no-disk-data-and-not-loaded", path.lastPathComponent, path]);
                continue;
            }
            record[@"discoverySources"] = discovery[@"sources"] ?: @[];
            record[@"discoveryDyldIndex"] = discovery[@"dyldIndex"] ?: @(-1);
            record[@"diskAvailable"] = discovery[@"diskAvailable"] ?: @(data.length > 0);
            if (![record[@"score"] unsignedIntValue]) {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] image=%@ path=%@ sources=%@ reason=no-known-family-structure",
                                record[@"image"], record[@"path"], [record[@"discoverySources"] componentsJoinedByString:@","]]);
                continue;
            }
            [found addObject:record];
            HFAAppLocalLog([NSString stringWithFormat:@"[CANDIDATE] image=%@ family=%@ variant=%@ score=%@ classes=%@ loaded=%@ loadedIndex=%@ disk=%@ sources=%@ path=%@",
                            record[@"image"], record[@"family"], record[@"variant"], record[@"score"], record[@"objcClassCount"],
                            [record[@"loaded"] boolValue]?@"yes":@"no", record[@"loadedIndex"],
                            [record[@"diskAvailable"] boolValue]?@"yes":@"no", [record[@"discoverySources"] componentsJoinedByString:@","], record[@"path"]]);
            for (NSString *hit in record[@"evidence"]) HFAAppLocalLog([NSString stringWithFormat:@"  [HIT] %@", hit]);
        }
        [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            BOOL la=[a[@"loaded"] boolValue], lb=[b[@"loaded"] boolValue];
            if (la != lb) return la ? NSOrderedAscending : NSOrderedDescending;
            NSInteger sa=[a[@"score"] integerValue], sb=[b[@"score"] integerValue];
            if (sa != sb) return sa > sb ? NSOrderedAscending : NSOrderedDescending;
            return [a[@"path"] compare:b[@"path"]];
        }];
        @synchronized([NSObject class]) {
#if !__has_feature(objc_arc)
            [gHFAAppLocalCandidates release];
#endif
            gHFAAppLocalCandidates = [found mutableCopy];
            gHFAAppLocalPrimaryImage[0]=0; gHFAAppLocalPrimaryFamily[0]=0; gHFAAppLocalPrimaryVariant[0]=0; gHFAAppLocalPrimaryPath[0]=0; gHFAAppLocalPrimaryLoadedIndex=-1;
        }
        HFAAppLocalWriteIndex(found, discovered.count);
        HFAAppLocalLog([NSString stringWithFormat:@"[SELECT-WAIT] candidates=%lu manualSelectionRequired=1", (unsigned long)found.count]);
        if (found.count) HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：发现 %lu 个候选，请手动选择", (unsigned long)found.count]);
        else HFACyberUIAppendLog(@"❌ 没有识别到已知菜单 dylib");
        return (unsigned)found.count;
    }
}'''
app = replace_named_function(app, 'HFAAppLocalScanCandidates', scan)

for old,new in (
    ('HFAMapUniversal v1.9.37.5 LoadedMachODependencyDiscovery','HFAMapUniversal v1.9.37.6 LoadedImageFingerprint'),
    ('v1.9.37.5 LoadedMachODependencyDiscovery','v1.9.37.6 LoadedImageFingerprint'),
):
    app=app.replace(old,new); cyber=cyber.replace(old,new); legacy=legacy.replace(old,new); exporter=exporter.replace(old,new)

for token in ('[MEMORY-FINGERPRINT]','source:loaded-memory','HFAAppLocalFingerprintLoaded','diskAvailable','[SELECT-WAIT]','[MANUAL-SELECT]'):
    if token not in app: raise SystemExit(f'missing v19376 token: {token}')
for forbidden in ('objc_getClassList','_dyld_register_func_for_add_image'):
    if forbidden in app: raise SystemExit(f'forbidden regression: {forbidden}')

APPLOCAL.write_text(app); CYBER.write_text(cyber); LEGACY.write_text(legacy); EXPORTER.write_text(exporter)
print('patched v1.9.37.6: loaded-but-file-missing dylib discovery + in-memory family fingerprint')
