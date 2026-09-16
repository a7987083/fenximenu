from pathlib import Path

APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
GENERIC = Path('hfamap/src/HFAMapGenericMenuResolver.m')
TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
PROFILER = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
MAKEFILE = Path('hfamap/Makefile')


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
generic = GENERIC.read_text()
trace = TRACE.read_text()
profiler = PROFILER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()
cyber = CYBER.read_text()
makefile = MAKEFILE.read_text()

# ---------------------------------------------------------------------------
# App-local identity/context: exact loaded path only; family becomes an actual
# parser input, not just a diagnostic label.
# ---------------------------------------------------------------------------
primary_anchor = 'static char gHFAAppLocalPrimaryImage[512];\n'
primary_state = primary_anchor + (
    'static char gHFAAppLocalPrimaryFamily[32];\n'
    'static char gHFAAppLocalPrimaryVariant[32];\n'
    'static char gHFAAppLocalPrimaryPath[1024];\n'
    'static int gHFAAppLocalPrimaryLoadedIndex = -1;\n'
)
if 'gHFAAppLocalPrimaryFamily' not in app:
    app = once(app, primary_anchor, primary_state, 'add primary family context')

loaded_index = r'''static int HFAAppLocalLoadedIndex(NSString *candidatePath) {
    if (!candidatePath.length) return -1;
    NSString *standard = candidatePath.stringByStandardizingPath;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if ([path.stringByStandardizingPath isEqualToString:standard]) return (int)i;
    }
    return -1;
}'''
app = replace_named_function(app, 'HFAAppLocalLoadedIndex', loaded_index)

scan = r'''unsigned HFAAppLocalScanCandidates(void) {
    @autoreleasepool {
        NSArray<NSString *> *machOs = HFAAppLocalEnumerateBundleMachOs();
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] app-local dylibs=%lu", (unsigned long)machOs.count]);
        NSMutableArray<NSDictionary *> *found = [NSMutableArray array];
        for (NSString *path in machOs) {
            NSData *data = HFAAppLocalMappedData(path);
            if (!data.length) continue;
            NSDictionary *record = HFAAppLocalFingerprint(path, data);
            if (![record[@"score"] unsignedIntValue]) {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] %@ reason=no-known-family-structure", record[@"image"]]);
                continue;
            }
            [found addObject:record];
            HFAAppLocalLog([NSString stringWithFormat:@"[CANDIDATE] %@ family=%@ variant=%@ score=%@ classes=%@ loaded=%@ loadedIndex=%@",
                            record[@"image"], record[@"family"], record[@"variant"], record[@"score"],
                            record[@"objcClassCount"], [record[@"loaded"] boolValue] ? @"yes" : @"no",
                            record[@"loadedIndex"]]);
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
        HFAAppLocalWriteIndex(deduped, machOs.count);
        if (primary) {
            HFAAppLocalLog([NSString stringWithFormat:@"[SELECT] primary=%@ family=%@ variant=%@ score=%@ loaded=%@ index=%@",
                            primary[@"image"], primary[@"family"], primary[@"variant"], primary[@"score"],
                            [primary[@"loaded"] boolValue] ? @"yes" : @"no", primary[@"loadedIndex"]]);
            NSString *displayFamily = [primary[@"family"] isEqual:@"runtime-5m"] ? @"5M 家族" :
                                      ([primary[@"family"] isEqual:@"legacy-ap"] ? @"13M 家族" : primary[@"family"]);
            HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 已识别：%@ | %@ | %@",
                                  primary[@"image"], displayFamily, primary[@"variant"]]);
        } else {
            HFAAppLocalLog(@"[SELECT] no known family dylib found");
            HFACyberUIAppendLog(@"❌ 没有识别到 5M / 13M 菜单模块");
        }
        return (unsigned)deduped.count;
    }
}'''
app = replace_named_function(app, 'HFAAppLocalScanCandidates', scan)

getters_anchor = '''const char *HFAAppLocalPrimaryImage(void) {
    return gHFAAppLocalPrimaryImage[0] ? gHFAAppLocalPrimaryImage : NULL;
}
'''
getters = getters_anchor + r'''

const char *HFAAppLocalPrimaryFamily(void) {
    return gHFAAppLocalPrimaryFamily[0] ? gHFAAppLocalPrimaryFamily : NULL;
}

const char *HFAAppLocalPrimaryVariant(void) {
    return gHFAAppLocalPrimaryVariant[0] ? gHFAAppLocalPrimaryVariant : NULL;
}

const char *HFAAppLocalPrimaryPath(void) {
    return gHFAAppLocalPrimaryPath[0] ? gHFAAppLocalPrimaryPath : NULL;
}

int HFAAppLocalPrimaryLoadedIndex(void) {
    return gHFAAppLocalPrimaryLoadedIndex;
}
'''
if 'const char *HFAAppLocalPrimaryFamily(void)' not in app:
    app = once(app, getters_anchor, getters, 'add app-local family getters')

# Keep detailed detector logs in the file; the live panel receives explicit
# Chinese summaries only.
app = app.replace('        HFACyberUIAppendLog(line);\n', '')
app = app.replace('HFAMapUniversal v1.9.36.8 FamilyMenuResolver',
                  'HFAMapUniversal v1.9.37 CleanFamilyResolver')

# ---------------------------------------------------------------------------
# Generic object resolver: reset per scan, accept the real label property, and
# preserve IGSecretString instead of silently discarding it.
# ---------------------------------------------------------------------------
label_fn = r'''static NSString *HFALabelForObject(id object) {
    NSString *label = HFASafeStringGetter(object, "label");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "text");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "currentTitle");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "title");
    if (label.length) return label;
    label = HFASafeStringGetter(object, "accessibilityLabel");
    if (label.length) return label;
    @try {
        if ([object respondsToSelector:sel_registerName("titleLabel")]) {
            id titleLabel = ((id (*)(id, SEL))objc_msgSend)(object, sel_registerName("titleLabel"));
            label = HFASafeStringGetter(titleLabel, "text");
            if (label.length) return label;
        }
    } @catch (__unused id exception) {}
    return nil;
}'''
generic = replace_named_function(generic, 'HFALabelForObject', label_fn)

generic = generic.replace(
    'if (value && (strcmp(kind, "IGSecretInt") == 0 || strcmp(kind, "IGSecretData") == 0))\n                HFARegisterPatchSecret(owner ?: object, value, kind);',
    'if (value && (strcmp(kind, "IGSecretInt") == 0 || strcmp(kind, "IGSecretData") == 0 || strcmp(kind, "IGSecretString") == 0))\n                HFARegisterPatchSecret(owner ?: object, value, kind);'
)

reset_generic = r'''void HFAGenericMenuResetScanState(void) {
    memset(gSeenObjects, 0, sizeof(gSeenObjects));
    memset(gSeenClasses, 0, sizeof(gSeenClasses));
    gSeenObjectCount = 0;
    gSeenClassCount = 0;
    gScanGeneration++;
    HFAGenericLog("[GENERIC-RESET] generation=%u\n", gScanGeneration);
}

'''
if 'void HFAGenericMenuResetScanState(void)' not in generic:
    pos = generic.find('void HFAGenericMenuObserveAction(')
    if pos < 0: raise SystemExit('generic action anchor missing')
    generic = generic[:pos] + reset_generic + generic[pos:]

generic = generic.replace('HFAMap v1.9.36 ArchitectureTruth', 'HFAMap v1.9.37 CleanFamilyResolver')

# ---------------------------------------------------------------------------
# Jailpatch profiler: its seen sets must be generation-local.
# ---------------------------------------------------------------------------
reset_profiler = r'''void HFAJailpatchResetProfilerState(void) {
    memset(gHFAJPTargets, 0, sizeof(gHFAJPTargets));
    memset(gHFAJPObjects, 0, sizeof(gHFAJPObjects));
    memset(gHFAJPClasses, 0, sizeof(gHFAJPClasses));
    gHFAJPTargetCount = 0;
    gHFAJPObjectCount = 0;
    gHFAJPClassCount = 0;
    HFAJPLog("[JAILPATCH-RESET]\n");
}

'''
if 'void HFAJailpatchResetProfilerState(void)' not in profiler:
    pos = profiler.find('__attribute__((constructor))')
    if pos < 0: raise SystemExit('profiler constructor anchor missing')
    profiler = profiler[:pos] + reset_profiler + profiler[pos:]

# ---------------------------------------------------------------------------
# Patch/decrypt state: keep the proven decrypt routine, remove the obsolete key
# discovery probe from production, and preserve signature wrappers.
# ---------------------------------------------------------------------------
trace = trace.replace('extern void HFAProbeKey2Path(uintptr_t getterAddress);\n', '')
trace = trace.replace('    if ((flags >> 24) == 2u)\n        HFAProbeKey2Path((uintptr_t)getter);\n', '')
trace = trace.replace('        HFAProbeKey2Path((uintptr_t)getter);\n', '')

if 'id signatureWrapper;' not in trace:
    trace = once(trace, '    id patchWrapper;\n', '    id patchWrapper;\n    id signatureWrapper;\n', 'add signature wrapper')

register_secret = r'''void HFARegisterPatchSecret(id owner, id wrapper, const char *kind) {
    HFADescriptor *d = HFADescriptorFor(owner, 1);
    if (!d || !wrapper || !kind) return;
    d->seenEvent = gEvent;
    Method m = class_getInstanceMethod(object_getClass(wrapper), sel_registerName("secret"));
    Dl_info info = {0};
    if (m && dladdr((void *)method_getImplementation(m), &info) && info.dli_fname)
        snprintf(d->sourceImage, sizeof(d->sourceImage), "%s", HFABase(info.dli_fname));
    if (strstr(kind, "Int")) d->offsetWrapper = wrapper;
    else if (strstr(kind, "Data")) d->patchWrapper = wrapper;
    else if (strstr(kind, "String")) d->signatureWrapper = wrapper;
}'''
trace = replace_named_function(trace, 'HFARegisterPatchSecret', register_secret)

pending_anchor = 'static NSArray *gPendingIGMMFeatures = nil;\n'
reset_trace = pending_anchor + r'''

void HFAPatchTraceResetAnalysis(void) {
    memset(gDescriptors, 0, sizeof(gDescriptors));
    memset(gFeatureDefinitions, 0, sizeof(gFeatureDefinitions));
    memset(gStateSites, 0, sizeof(gStateSites));
    gDescriptorCount = 0;
    gFeatureDefinitionCount = 0;
    gStateSiteCount = 0;
    gEvent = 0;
    gExecutedEvent = 0;
    gFeature[0] = 0;
    gFeatureDesc[0] = 0;
    gTarget[0] = 0;
    gIdentifier[0] = 0;
    gWantedKey[0] = 0;
    gDetectedTarget[0] = 0;
    gPendingIGMMMenuTarget = nil;
    gPendingIGMMFeatures = nil;
    HFALog("[ANALYSIS-RESET] descriptors=0 features=0\n");
}
'''
if 'void HFAPatchTraceResetAnalysis(void)' not in trace:
    trace = once(trace, pending_anchor, reset_trace, 'add trace analysis reset')

# ---------------------------------------------------------------------------
# Normal execution now calls the family dispatcher; the old AUTO scanner and
# global sendAction swizzle are no longer normal-path entry points.
# ---------------------------------------------------------------------------
legacy_decl = 'extern unsigned int HFAFamilyResolveCurrentUI(void);\n'
if legacy_decl not in legacy:
    anchor = 'extern unsigned int HFAAppLocalInspectCandidates(void);\n'
    if anchor not in legacy: raise SystemExit('legacy app-local declaration anchor missing')
    legacy = once(legacy, anchor, anchor + legacy_decl, 'declare family resolver')

execute = r'''unsigned int HFAAppLocalExecuteParser(void){
    gAttached=1;gFound[0]=0;
    const char*candidate=HFAAppLocalPrimaryImage();
    if(!candidate||!*candidate){HFAAppLocalScanCandidates();candidate=HFAAppLocalPrimaryImage();}
    const char*family=HFAAppLocalPrimaryFamily();
    if(!candidate||!*candidate||!family||!*family){
        logf("[FAMILY-EXECUTE] status=no-primary\n");
        HFACyberUIAppendLog(ns("❌ 没有可解析的目标模块"));
        return 0;
    }
    HFAPatchTraceSetTarget(candidate);
    logf("[FAMILY-EXECUTE-BEGIN] primary=%s family=%s\n",candidate,family);
    unsigned int observed=HFAFamilyResolveCurrentUI();
    unsigned int valid=HFAPatchTraceFinalizeScan();
    BOOL exported=HFAMapJSONExportLatest();
    logf("[FAMILY-EXECUTE-END] primary=%s family=%s observed=%u validMappings=%u json=%d\n",
         candidate,family,observed,valid,(int)exported);
    if(exported)HFACyberUIAppendLog(ns("✅ JSON 导出完成"));
    else HFACyberUIAppendLog(ns("⚠️ 本次没有生成可导出的功能数据"));
    return valid?valid:observed;
}'''
legacy = replace_named_function(legacy, 'HFAAppLocalExecuteParser', execute)

tick = r'''static void tick(id self,SEL c,id timer){
    (void)self;(void)c;(void)timer;id w=win();if(!w)return;
    if(!gMade)mkui(w);
    if(gMade&&gWindow!=w){if(gPanel)M1(void,w,"addSubview:",id,gPanel);if(gButton)M1(void,w,"addSubview:",id,gButton);gWindow=w;}
    if(gMade){HFACyberUIBringToFront(w);if(gButton)M1(void,w,"bringSubviewToFront:",id,gButton);}
}'''
legacy = replace_named_function(legacy, 'tick', tick)
legacy = legacy.replace('HFAMap v1.9.36.8 FamilyMenuResolver', 'HFAMap v1.9.37 CleanFamilyResolver')
legacy = legacy.replace('HFAMap v1.9.36.7 AppLocalMenuResolver', 'HFAMap v1.9.37 CleanFamilyResolver')

# ---------------------------------------------------------------------------
# JSON correctness: sliders are sliders; exact identifier lookup preserves the
# first canonical record and exposes all evidence without silent overwrite.
# ---------------------------------------------------------------------------
control_kind = r'''static NSString *HFAJSONControlKind(NSDictionary *feature) {
    NSString *type = [feature[@"type"] isKindOfClass:[NSString class]] ? feature[@"type"] : @"";
    NSString *primitive = [feature[@"executionPrimitive"] isKindOfClass:[NSString class]]
        ? feature[@"executionPrimitive"] : @"";
    if ([type isEqualToString:@"customSwitch"] || [primitive isEqualToString:@"runtimeBoolean"])
        return @"toggle";
    if ([type isEqualToString:@"modslider"] || [type isEqualToString:@"slider"])
        return @"slider";
    if ([type isEqualToString:@"button"] || [type isEqualToString:@"kTypeButton"] ||
        [primitive isEqualToString:@"runtimeAction"] || [primitive isEqualToString:@"blockHandler"])
        return @"button";
    if ([type isEqualToString:@"modtext"] || [type isEqualToString:@"textfield"] ||
        [type isEqualToString:@"textField"] || [primitive isEqualToString:@"numericRuntimeModifier"])
        return @"number";
    return @"unknown";
}'''
exporter = replace_named_function(exporter, 'HFAJSONControlKind', control_kind)

menu_index = r'''static NSDictionary *HFAJSONMenuIndex(NSArray *features) {
    NSMutableDictionary *byIdentifier = [NSMutableDictionary dictionary];
    NSMutableDictionary *byIdentifierAll = [NSMutableDictionary dictionary];
    NSMutableDictionary *byTitle = [NSMutableDictionary dictionary];
    for (NSDictionary *feature in features) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *identifier = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : @"";
        NSString *title = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : @"";
        if (identifier.length) {
            if (!byIdentifier[identifier]) byIdentifier[identifier] = feature;
            NSMutableArray *all = [byIdentifierAll[identifier] isKindOfClass:[NSArray class]]
                ? [byIdentifierAll[identifier] mutableCopy] : [NSMutableArray array];
            [all addObject:feature];
            byIdentifierAll[identifier] = all;
        }
        if (title.length && identifier.length) {
            NSMutableArray *ids = [byTitle[title] isKindOfClass:[NSArray class]]
                ? [byTitle[title] mutableCopy] : [NSMutableArray array];
            if (![ids containsObject:identifier]) [ids addObject:identifier];
            byTitle[title] = ids;
        }
    }
    return @{ @"lookupOrder": @[ @"identifier", @"title" ],
              @"byIdentifier": byIdentifier,
              @"byIdentifierAll": byIdentifierAll,
              @"byTitle": byTitle };
}'''
exporter = replace_named_function(exporter, 'HFAJSONMenuIndex', menu_index)
exporter = exporter.replace('HFAMapUniversal v1.9.36.8 FamilyMenuResolver',
                            'HFAMapUniversal v1.9.37 CleanFamilyResolver')

# ---------------------------------------------------------------------------
# Live UI: Chinese summary by default. Detailed technical evidence stays in the
# Documents log/JSON rather than flooding the panel.
# ---------------------------------------------------------------------------
replacements = {
    '[DISCOVERY] scanning app root + Frameworks ...': '🔎 正在扫描游戏目录中的 dylib…',
    '[DISCOVERY-END] candidates=%u': '✅ 扫描完成：识别到 %u 个候选模块',
    '[RESOLVE] image-local parser starting ...': '🔎 正在按已识别家族解析菜单…',
    '[EXPORT-END] validMappings=%u': '✅ 解析结束：有效映射 %u',
    '  HFAMap AppLocalMenuResolver': '  HFAMap 家族解析器 v1.9.37',
    '[System] HFAMap AppLocalMenuResolver ready.': '[系统] 家族解析器已就绪。',
    '[System] 先扫描菜单模块，再解析并导出。': '[系统] 先扫描模块，再解析并导出。',
}
for old, new in replacements.items():
    cyber = cyber.replace(old, new)

# ---------------------------------------------------------------------------
# Build graph: add the clean resolver, remove obsolete key-callgraph probe.
# ---------------------------------------------------------------------------
files_line = next((line for line in makefile.splitlines() if line.startswith('HFAMapUniversal_FILES = ')), None)
if not files_line: raise SystemExit('Makefile files line missing')
new_files = files_line.replace(' src/HFAMapSecretCallGraphProbe.m', '')
if 'src/HFAMapFamilyRuntimeResolver.m' not in new_files:
    new_files += ' src/HFAMapFamilyRuntimeResolver.m'
makefile = makefile.replace(files_line, new_files, 1)

# ---------------------------------------------------------------------------
# Hard gates for this generation step.
# ---------------------------------------------------------------------------
_, _, execute_text = (*function_span(legacy, 'HFAAppLocalExecuteParser'),)
if 'HFAFamilyResolveCurrentUI()' not in execute_text or 'run_full_scan()' in execute_text:
    raise SystemExit('family dispatcher is not the parser entry point')
if 'tryhook();' in legacy:
    raise SystemExit('global UIControl sendAction hook still auto-installs')
if 'HFAProbeKey2Path' in trace:
    raise SystemExit('obsolete Key2 probe still referenced by patch trace')
if 'src/HFAMapSecretCallGraphProbe.m' in makefile:
    raise SystemExit('obsolete Key2 probe source still linked')
for required in ('HFAAppLocalPrimaryFamily', 'runtime-5m', 'legacy-ap'):
    if required not in app: raise SystemExit(f'missing app-local context: {required}')
for required in ('HFAGenericMenuResetScanState', 'IGSecretString'):
    if required not in generic: raise SystemExit(f'missing generic fix: {required}')
if 'HFAJailpatchResetProfilerState' not in profiler:
    raise SystemExit('profiler reset missing')
if 'HFAPatchTraceResetAnalysis' not in trace or 'signatureWrapper' not in trace:
    raise SystemExit('trace reset/signature state missing')
if 'modslider' not in exporter or 'byIdentifierAll' not in exporter:
    raise SystemExit('JSON correctness fixes missing')

APPLOCAL.write_text(app)
GENERIC.write_text(generic)
TRACE.write_text(trace)
PROFILER.write_text(profiler)
LEGACY.write_text(legacy)
EXPORTER.write_text(exporter)
CYBER.write_text(cyber)
MAKEFILE.write_text(makefile)
print('patched v1.9.37 CleanFamilyResolver: family dispatcher + runtime object bridge + clean production path')
