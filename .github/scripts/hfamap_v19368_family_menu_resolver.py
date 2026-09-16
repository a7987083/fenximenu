from pathlib import Path

APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')


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
exp = EXPORTER.read_text()
legacy = LEGACY.read_text()

objc_counter = r'''static unsigned HFAAppLocalStaticObjCClassCount(NSData *data) {
    if (data.length < sizeof(struct mach_header_64)) return 0;
    const uint8_t *bytes = data.bytes;
    const struct mach_header_64 *header = (const struct mach_header_64 *)bytes;
    if (header->magic != MH_MAGIC_64) return 0;
    if ((uint64_t)sizeof(*header) + header->sizeofcmds > data.length) return 0;
    const uint8_t *cursor = bytes + sizeof(*header);
    const uint8_t *commandsEnd = cursor + header->sizeofcmds;
    unsigned count = 0;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > commandsEnd) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commandsEnd) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            uint64_t required = sizeof(*seg) + (uint64_t)seg->nsects * sizeof(*sec);
            if (required <= lc->cmdsize) {
                for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                    if (strncmp(sec->sectname, "__objc_classlist", 16) != 0) continue;
                    if (sec->size % sizeof(uint64_t) != 0) continue;
                    count += (unsigned)(sec->size / sizeof(uint64_t));
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return count;
}

'''
anchor = 'static NSDictionary *HFAAppLocalFingerprint(NSString *path, NSData *data) {'
if 'HFAAppLocalStaticObjCClassCount' not in app:
    pos = app.find(anchor)
    if pos < 0:
        raise SystemExit('AppLocal fingerprint anchor missing')
    app = app[:pos] + objc_counter + app[pos:]

fingerprint = r'''static NSDictionary *HFAAppLocalFingerprint(NSString *path, NSData *data) {
    NSMutableArray<NSString *> *evidence = [NSMutableArray array];

    BOOL appPatch = HFAAppLocalDataHas(data, "APPatchItem");
    BOOL secretInt = HFAAppLocalDataHas(data, "IGSecretInt");
    BOOL secretData = HFAAppLocalDataHas(data, "IGSecretData");
    BOOL secretString = HFAAppLocalDataHas(data, "IGSecretString");
    BOOL subpatch = HFAAppLocalDataHas(data, "APSubpatchManager");
    BOOL codePatch = HFAAppLocalDataHas(data, "IGCodePatch");

    BOOL customSwitch = HFAAppLocalDataHas(data, "customSwitch");
    BOOL modslider = HFAAppLocalDataHas(data, "modslider");
    BOOL modtext = HFAAppLocalDataHas(data, "modtext");
    BOOL typeButton = HFAAppLocalDataHas(data, "kTypeButton");
    BOOL identifier = HFAAppLocalDataHas(data, "identifier");
    BOOL label = HFAAppLocalDataHas(data, "label");
    BOOL appKeyMetadata = HFAAppLocalDataHas(data, ".app-key-metadata-");
    BOOL validator = HFAAppLocalDataHas(data, "JailpatchConfigValidator");
    BOOL runtimeTable = HFAAppLocalDataHas(data, "Jailpatch runtime table");
    BOOL jailpatch = HFAAppLocalDataHas(data, "jailpatch");

    struct EvidenceToken { BOOL hit; const char *name; } hits[] = {
        {appPatch, "legacy:APPatchItem"}, {secretInt, "legacy:IGSecretInt"},
        {secretData, "legacy:IGSecretData"}, {secretString, "legacy:IGSecretString"},
        {subpatch, "legacy:APSubpatchManager"}, {codePatch, "legacy:IGCodePatch"},
        {customSwitch, "runtime:customSwitch"}, {modslider, "runtime:modslider"},
        {modtext, "runtime:modtext"}, {typeButton, "runtime:kTypeButton"},
        {identifier, "runtime:identifier"}, {label, "runtime:label"},
        {appKeyMetadata, "runtime:.app-key-metadata-"},
        {validator, "runtime:JailpatchConfigValidator"},
        {runtimeTable, "runtime:Jailpatch runtime table"}, {jailpatch, "runtime:jailpatch"}
    };
    for (unsigned i = 0; i < sizeof(hits) / sizeof(hits[0]); i++)
        if (hits[i].hit) [evidence addObject:[NSString stringWithUTF8String:hits[i].name]];

    BOOL legacyCore = appPatch && secretInt && (secretData || subpatch || codePatch);
    BOOL runtimeCore = customSwitch && modtext && typeButton && identifier && label;

    NSString *family = @"unknown";
    NSString *variant = @"unknown";
    unsigned score = 0;
    unsigned objcClassCount = HFAAppLocalStaticObjCClassCount(data);

    if (legacyCore) {
        family = @"legacy-ap";
        variant = @"A";
        score = 100;
    } else if (runtimeCore) {
        family = @"runtime-5m";
        if (objcClassCount >= 201) variant = @"B-extended";
        else if (!validator && !runtimeTable) variant = @"C-alternate";
        else if (validator && runtimeTable) variant = @"A-standard";
        else variant = @"unclassified";
        score = appKeyMetadata ? 100 : 90;
    }

    if (objcClassCount)
        [evidence addObject:[NSString stringWithFormat:@"objc:classes=%u", objcClassCount]];

    int loadedIndex = HFAAppLocalLoadedIndex(path);
    return @{
        @"path": path,
        @"image": path.lastPathComponent ?: @"?",
        @"family": family,
        @"variant": variant,
        @"score": @(score),
        @"objcClassCount": @(objcClassCount),
        @"loaded": @(loadedIndex >= 0),
        @"loadedIndex": @(loadedIndex),
        @"evidence": evidence
    };
}'''
app = replace_named_function(app, 'HFAAppLocalFingerprint', fingerprint)

enumerator = r'''static NSArray<NSString *> *HFAAppLocalEnumerateBundleMachOs(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];

    NSArray<NSString *> *root = [fm contentsOfDirectoryAtPath:bundle error:nil] ?: @[];
    for (NSString *name in root) {
        if (![name.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        NSString *path = [bundle stringByAppendingPathComponent:name];
        BOOL directory = NO;
        if ([fm fileExistsAtPath:path isDirectory:&directory] && !directory)
            HFAAppLocalAddMachO(paths, path);
    }

    NSString *frameworks = [bundle stringByAppendingPathComponent:@"Frameworks"];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:frameworks];
    for (NSString *relative in enumerator) {
        if (![relative.pathExtension.lowercaseString isEqualToString:@"dylib"]) continue;
        NSString *path = [frameworks stringByAppendingPathComponent:relative];
        BOOL directory = NO;
        if ([fm fileExistsAtPath:path isDirectory:&directory] && !directory)
            HFAAppLocalAddMachO(paths, path);
    }
    return paths;
}'''
app = replace_named_function(app, 'HFAAppLocalEnumerateBundleMachOs', enumerator)

scan = r'''unsigned HFAAppLocalScanCandidates(void) {
    @autoreleasepool {
        NSArray<NSString *> *machOs = HFAAppLocalEnumerateBundleMachOs();
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] app-local dylibs=%lu", (unsigned long)machOs.count]);
        NSMutableArray<NSDictionary *> *found = [NSMutableArray array];
        for (NSString *path in machOs) {
            NSData *data = HFAAppLocalMappedData(path);
            if (!data.length) continue;
            NSDictionary *record = HFAAppLocalFingerprint(path, data);
            unsigned score = [record[@"score"] unsignedIntValue];
            if (!score) {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] %@ reason=no-known-family-structure", record[@"image"]]);
                continue;
            }
            HFAAppLocalLog([NSString stringWithFormat:@"[CANDIDATE] %@ family=%@ variant=%@ score=%u classes=%@ loaded=%@",
                            record[@"image"], record[@"family"], record[@"variant"], score,
                            record[@"objcClassCount"], [record[@"loaded"] boolValue] ? @"yes" : @"no"]);
            for (NSString *hit in record[@"evidence"])
                HFAAppLocalLog([NSString stringWithFormat:@"  [HIT] %@", hit]);
            [found addObject:record];
        }
        [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
            if (sa > sb) return NSOrderedAscending;
            if (sa < sb) return NSOrderedDescending;
            return [a[@"image"] compare:b[@"image"]];
        }];
        @synchronized([NSObject class]) {
            gHFAAppLocalCandidates = [found mutableCopy];
            gHFAAppLocalPrimaryImage[0] = 0;
            if (found.count) {
                NSString *image = found.firstObject[@"image"];
                snprintf(gHFAAppLocalPrimaryImage, sizeof(gHFAAppLocalPrimaryImage), "%s", image.UTF8String ?: "");
            }
        }
        HFAAppLocalWriteIndex(found, machOs.count);
        if (found.count)
            HFAAppLocalLog([NSString stringWithFormat:@"[SELECT] primary=%@ family=%@ variant=%@ score=%@",
                            found.firstObject[@"image"], found.firstObject[@"family"],
                            found.firstObject[@"variant"], found.firstObject[@"score"]]);
        else
            HFAAppLocalLog(@"[SELECT] no known 5M/13M family dylib found");
        return (unsigned)found.count;
    }
}'''
app = replace_named_function(app, 'HFAAppLocalScanCandidates', scan)
app = app.replace('HFAMapUniversal v1.9.36.7 AppLocalMenuResolver',
                  'HFAMapUniversal v1.9.36.8 FamilyMenuResolver')

index_helper = r'''static NSDictionary *HFAJSONMenuIndex(NSArray *features) {
    NSMutableDictionary *byIdentifier = [NSMutableDictionary dictionary];
    NSMutableDictionary *byTitle = [NSMutableDictionary dictionary];
    for (NSDictionary *feature in features) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *identifier = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : @"";
        NSString *title = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : @"";
        if (identifier.length) byIdentifier[identifier] = feature;
        if (title.length && identifier.length) {
            NSMutableArray *ids = [byTitle[title] isKindOfClass:[NSArray class]] ? [byTitle[title] mutableCopy] : [NSMutableArray array];
            if (![ids containsObject:identifier]) [ids addObject:identifier];
            byTitle[title] = ids;
        }
    }
    return @{ @"lookupOrder": @[ @"identifier", @"title" ],
              @"byIdentifier": byIdentifier,
              @"byTitle": byTitle };
}

'''
json_anchor = 'BOOL HFAMapJSONExportLatest(void) {'
if 'HFAJSONMenuIndex' not in exp:
    pos = exp.find(json_anchor)
    if pos < 0:
        raise SystemExit('JSON export anchor missing')
    exp = exp[:pos] + index_helper + exp[pos:]

root_anchor = '        if (targetIdentities.count) root[@"targetIdentities"] = targetIdentities;\n'
if 'root[@"menuIndex"]' not in exp:
    exp = once(exp, root_anchor,
               root_anchor + '        root[@"menuIndex"] = HFAJSONMenuIndex(features);\n',
               'add menu index')
exp = exp.replace('HFAMapUniversal v1.9.36.7 AppLocalMenuResolver',
                  'HFAMapUniversal v1.9.36.8 FamilyMenuResolver')
exp = exp.replace('HFAMapUniversal v1.9.36.6 JSONExport LazyScan',
                  'HFAMapUniversal v1.9.36.8 FamilyMenuResolver')
exp = exp.replace('HFAMapUniversal v1.9.36.4 JSONExport',
                  'HFAMapUniversal v1.9.36.8 FamilyMenuResolver')

legacy = legacy.replace('HFAMap v1.9.36.7 AppLocalMenuResolver',
                        'HFAMap v1.9.36.8 FamilyMenuResolver')
legacy = legacy.replace('HFAMap v1.9.36.6 JSON Export LazyScan',
                        'HFAMap v1.9.36.8 FamilyMenuResolver')

for forbidden in ('legacy-15mb', 'jailpatch-v2'):
    if forbidden in app:
        raise SystemExit(f'old top-level family remains: {forbidden}')
if 'size=%.2fMB' in app or 'record[@"size"]' in app:
    raise SystemExit('size-based candidate logic remains')
if 'objc_getClassList' in app:
    raise SystemExit('process-wide ObjC enumeration introduced')
for required in ('runtime-5m', 'legacy-ap', 'A-standard', 'B-extended', 'C-alternate'):
    if required not in app:
        raise SystemExit(f'missing family marker: {required}')
if 'root[@"menuIndex"] = HFAJSONMenuIndex(features);' not in exp:
    raise SystemExit('menu index not wired')

APPLOCAL.write_text(app)
EXPORTER.write_text(exp)
LEGACY.write_text(legacy)
print('patched v1.9.36.8 FamilyMenuResolver: dylib-only app-local family detection + exact title/id JSON index')
