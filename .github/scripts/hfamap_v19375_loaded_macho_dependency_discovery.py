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


app = APPLOCAL.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()

# Canonicalize /var vs /private/var (and similar symlinked bundle prefixes)
# before deciding whether a loaded image belongs to the current app.
canonical_helpers = r'''static NSString *HFAAppLocalCanonicalPath(NSString *path) {
    if (!path.length) return @"";
    NSString *standard = path.stringByStandardizingPath;
    NSString *resolved = standard.stringByResolvingSymlinksInPath;
    return resolved.length ? resolved : standard;
}

static BOOL HFAAppLocalPathInsideBundle(NSString *path) {
    if (!path.length) return NO;
    NSString *bundle = HFAAppLocalCanonicalPath(NSBundle.mainBundle.bundlePath);
    NSString *candidate = HFAAppLocalCanonicalPath(path);
    if (!bundle.length || !candidate.length) return NO;
    NSString *prefix = [bundle stringByAppendingString:@"/"];
    return [candidate hasPrefix:prefix];
}'''
app = replace_named_function(app, 'HFAAppLocalPathInsideBundle', canonical_helpers)

# v1.9.37.4 only discovered dependency owners from files that NSFileManager
# could enumerate. EarntoDieRogue showed diskHits=0, so UnityFramework was never
# examined. v1.9.37.5 reads LC_*_DYLIB directly from app-local dyld image headers
# as the primary dependency-owner source, then keeps the disk pass as fallback.
dependency_function = r'''static NSArray<NSDictionary *> *HFAAppLocalDependencyRecords(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];

    void (^collectHeader)(const struct mach_header *, NSString *, NSString *, int) =
    ^(const struct mach_header *rawHeader, NSString *owner, NSString *source, int ownerIndex) {
        if (!rawHeader || !owner.length || !source.length) return;
        if (rawHeader->magic != MH_MAGIC_64) return;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)rawHeader;
        const uint8_t *cursor = (const uint8_t *)(mh + 1);
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            const struct load_command *lc = (const struct load_command *)cursor;
            if (!lc || lc->cmdsize < sizeof(struct load_command)) break;
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
                        if (resolved.length && [resolved.pathExtension.lowercaseString isEqualToString:@"dylib"]) {
                            NSString *command = lc->cmd == LC_LOAD_DYLIB ? @"LC_LOAD_DYLIB" :
                                                (lc->cmd == LC_LOAD_WEAK_DYLIB ? @"LC_LOAD_WEAK_DYLIB" :
                                                (lc->cmd == LC_REEXPORT_DYLIB ? @"LC_REEXPORT_DYLIB" : @"LC_LOAD_UPWARD_DYLIB"));
                            NSString *key = [NSString stringWithFormat:@"%@|%@|%@", HFAAppLocalCanonicalPath(owner), command, HFAAppLocalCanonicalPath(resolved)];
                            if (![seen containsObject:key]) {
                                [seen addObject:key];
                                BOOL exists = [fm fileExistsAtPath:resolved];
                                int loadedIndex = HFAAppLocalLoadedIndex(resolved);
                                NSDictionary *record = @{ @"path": resolved,
                                                          @"image": resolved.lastPathComponent ?: @"?",
                                                          @"installName": installName ?: @"?",
                                                          @"dependencyOwner": owner.lastPathComponent ?: @"?",
                                                          @"dependencyOwnerPath": owner,
                                                          @"dependencyOwnerIndex": @(ownerIndex),
                                                          @"dependencySource": source,
                                                          @"dependencyCommand": command,
                                                          @"exists": @(exists),
                                                          @"loadedIndex": @(loadedIndex) };
                                [records addObject:record];
                                HFAAppLocalLog([NSString stringWithFormat:@"[DEPENDENCY] source=%@ owner=%@ ownerIndex=%d command=%@ installName=%@ resolvedPath=%@ exists=%@ loaded=%@ index=%d",
                                                source, record[@"dependencyOwner"], ownerIndex, command, installName, resolved,
                                                exists ? @"yes" : @"no", loadedIndex >= 0 ? @"yes" : @"no", loadedIndex]);
                            }
                        }
#if !__has_feature(objc_arc)
                        [installName release];
#endif
                    }
                }
            }
            cursor += lc->cmdsize;
        }
    };

    unsigned loadedOwners = 0;
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *rawName = _dyld_get_image_name(i);
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!rawName || !header) continue;
        NSString *owner = [NSString stringWithUTF8String:rawName];
        if (!owner.length || !HFAAppLocalPathInsideBundle(owner)) continue;
        if ([owner.lastPathComponent containsString:@"HFAMapUniversal"]) continue;
        loadedOwners++;
        HFAAppLocalLog([NSString stringWithFormat:@"[OWNER-DYLD] index=%u image=%@ path=%@", i, owner.lastPathComponent, owner]);
        collectHeader(header, owner, @"dyld-header", (int)i);
    }

    unsigned diskOwners = 0;
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
        const struct mach_header_64 *mh = (const struct mach_header_64 *)data.bytes;
        if (mh->magic != MH_MAGIC_64) continue;
        if ((uint64_t)sizeof(*mh) + mh->sizeofcmds > data.length) continue;
        diskOwners++;
        HFAAppLocalLog([NSString stringWithFormat:@"[OWNER-DISK] image=%@ path=%@", owner.lastPathComponent, owner]);
        collectHeader((const struct mach_header *)mh, owner, @"disk-macho", -1);
    }

    HFAAppLocalLog([NSString stringWithFormat:@"[DEPENDENCY-OWNERS] dyld=%u disk=%u records=%lu",
                    loadedOwners, diskOwners, (unsigned long)records.count]);
    return records;
}'''
app = replace_named_function(app, 'HFAAppLocalDependencyRecords', dependency_function)

for old, new in (
    ('HFAMapUniversal v1.9.37.4 ManualCandidateSelection', 'HFAMapUniversal v1.9.37.5 LoadedMachODependencyDiscovery'),
    ('v1.9.37.4 ManualCandidateSelection', 'v1.9.37.5 LoadedMachODependencyDiscovery'),
):
    app = app.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)
    exporter = exporter.replace(old, new)

required = (
    '[OWNER-DYLD]',
    '[OWNER-DISK]',
    '[DEPENDENCY-OWNERS]',
    'dyld-header',
    '_dyld_get_image_header',
    'stringByResolvingSymlinksInPath',
    '[SELECT-WAIT]',
    '[MANUAL-SELECT]',
)
for token in required:
    if token not in app:
        raise SystemExit(f'missing v19375 token: {token}')
for forbidden in ('objc_getClassList', '_dyld_register_func_for_add_image'):
    if forbidden in app:
        raise SystemExit(f'forbidden regression: {forbidden}')

APPLOCAL.write_text(app)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
EXPORTER.write_text(exporter)
print('patched v1.9.37.5: loaded app-local Mach-O dependency discovery via dyld headers')
