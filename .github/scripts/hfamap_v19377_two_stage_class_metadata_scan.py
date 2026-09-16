from pathlib import Path

APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
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
family = FAMILY.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()

# Expose exact manually selected path/index to the family resolver. These are
# read-only getters; selection remains owned by AppLocalResolver.
getter_anchor = 'const char *HFAAppLocalPrimaryImage(void) {'
if 'HFAAppLocalPrimaryLoadedIndex(void)' not in app:
    pos = app.find(getter_anchor)
    if pos < 0:
        raise SystemExit('primary getter anchor missing')
    getters = r'''const char *HFAAppLocalPrimaryPath(void) {
    return gHFAAppLocalPrimaryPath;
}

int HFAAppLocalPrimaryLoadedIndex(void) {
    return gHFAAppLocalPrimaryLoadedIndex;
}

'''
    app = app[:pos] + getters + app[pos:]

if '#include <mach-o/dyld.h>' not in family:
    family = family.replace('#include <dlfcn.h>\n', '#include <dlfcn.h>\n#include <mach-o/dyld.h>\n', 1)

extern_anchor = 'extern const char *HFAAppLocalPrimaryFamily(void);\n'
if 'HFAAppLocalPrimaryLoadedIndex' not in family:
    if extern_anchor not in family:
        raise SystemExit('family extern anchor missing')
    family = family.replace(
        extern_anchor,
        extern_anchor + 'extern const char *HFAAppLocalPrimaryPath(void);\nextern int HFAAppLocalPrimaryLoadedIndex(void);\n',
        1,
    )

metadata_helpers = r'''
static BOOL HFAFamilyMetaContainsMarker(NSString *value) {
    if (!value.length) return NO;
    static NSArray<NSString *> *markers = nil;
    if (!markers) markers = [[NSArray alloc] initWithObjects:
        @"APPatchItem", @"IGSecretInt", @"IGSecretData", @"IGSecretString",
        @"APSubpatchManager", @"IGCodePatch", @"customSwitch", @"modslider",
        @"modtext", @"kTypeButton", nil];
    for (NSString *marker in markers)
        if ([value rangeOfString:marker options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    return NO;
}

static void HFAFamilyMetaAddReason(NSMutableArray<NSString *> *reasons, NSString *reason) {
    if (reason.length && ![reasons containsObject:reason]) [reasons addObject:reason];
}

static NSDictionary *HFAFamilyMetadataRecord(Class cls, const char *family) {
    if (!cls) return nil;
    NSString *className = [NSString stringWithUTF8String:class_getName(cls) ?: "?"];
    Class superClass = class_getSuperclass(cls);
    NSString *superName = superClass ? [NSString stringWithUTF8String:class_getName(superClass) ?: "?"] : @"";
    NSMutableArray *methodsOut = [NSMutableArray array];
    NSMutableArray *ivarsOut = [NSMutableArray array];
    NSMutableArray *propertiesOut = [NSMutableArray array];
    NSMutableArray *protocolsOut = [NSMutableArray array];
    NSMutableArray<NSString *> *reasons = [NSMutableArray array];
    NSInteger score = 0;
    BOOL hasIdentifier = NO, hasType = NO, hasCurrentState = NO, hasSetCurrentState = NO;
    BOOL uiSubclass = NO;

    for (Class cursor = superClass; cursor; cursor = class_getSuperclass(cursor)) {
        const char *name = class_getName(cursor);
        if (!name) continue;
        if (strcmp(name, "UIControl") == 0 || strcmp(name, "UIButton") == 0 || strcmp(name, "UISlider") == 0) {
            uiSubclass = YES;
            break;
        }
    }

    if (HFAFamilyMetaContainsMarker(className)) {
        score += 12;
        HFAFamilyMetaAddReason(reasons, [@"class:" stringByAppendingString:className]);
    }
    if (HFAFamilyMetaContainsMarker(superName)) {
        score += 6;
        HFAFamilyMetaAddReason(reasons, [@"super:" stringByAppendingString:superName]);
    }

    unsigned methodCount = 0;
    Method *methods = class_copyMethodList(cls, &methodCount);
    for (unsigned i = 0; methods && i < methodCount; i++) {
        const char *rawName = sel_getName(method_getName(methods[i]));
        const char *rawTypes = method_getTypeEncoding(methods[i]);
        NSString *name = rawName ? [NSString stringWithUTF8String:rawName] : @"?";
        NSString *types = rawTypes ? [NSString stringWithUTF8String:rawTypes] : @"";
        [methodsOut addObject:@{ @"name": name, @"types": types }];
        if ([name isEqualToString:@"identifier"] || [name isEqualToString:@"setIdentifier:"]) {
            hasIdentifier = YES; score += 3; HFAFamilyMetaAddReason(reasons, @"method:identifier");
        } else if ([name isEqualToString:@"type"]) {
            hasType = YES; score += 2; HFAFamilyMetaAddReason(reasons, @"method:type");
        } else if ([name isEqualToString:@"currentState"]) {
            hasCurrentState = YES; score += 4; HFAFamilyMetaAddReason(reasons, @"method:currentState");
        } else if ([name isEqualToString:@"setCurrentState:"]) {
            hasSetCurrentState = YES; score += 4; HFAFamilyMetaAddReason(reasons, @"method:setCurrentState:");
        } else if ([name isEqualToString:@"label"] || [name isEqualToString:@"setLabel:"]) {
            score += 2; HFAFamilyMetaAddReason(reasons, @"method:label");
        } else if ([name rangeOfString:@"customSwitch" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [name rangeOfString:@"modslider" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [name rangeOfString:@"modtext" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            score += 4; HFAFamilyMetaAddReason(reasons, [@"method:" stringByAppendingString:name]);
        }
    }
    free(methods);

    unsigned ivarCount = 0;
    Ivar *ivars = class_copyIvarList(cls, &ivarCount);
    for (unsigned i = 0; ivars && i < ivarCount; i++) {
        const char *rawName = ivar_getName(ivars[i]);
        const char *rawType = ivar_getTypeEncoding(ivars[i]);
        NSString *name = rawName ? [NSString stringWithUTF8String:rawName] : @"?";
        NSString *type = rawType ? [NSString stringWithUTF8String:rawType] : @"";
        [ivarsOut addObject:@{ @"name": name, @"type": type, @"offset": @(ivar_getOffset(ivars[i])) }];
        if (HFAFamilyMetaContainsMarker(name) || HFAFamilyMetaContainsMarker(type)) {
            score += 12;
            HFAFamilyMetaAddReason(reasons, [NSString stringWithFormat:@"ivar:%@:%@", name, type]);
        } else if ([name rangeOfString:@"feature" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [name rangeOfString:@"menu" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [name rangeOfString:@"toggle" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [name rangeOfString:@"slider" options:NSCaseInsensitiveSearch].location != NSNotFound) {
            score += 2;
            HFAFamilyMetaAddReason(reasons, [@"ivar-name:" stringByAppendingString:name]);
        }
    }
    free(ivars);

    unsigned propertyCount = 0;
    objc_property_t *properties = class_copyPropertyList(cls, &propertyCount);
    for (unsigned i = 0; properties && i < propertyCount; i++) {
        const char *rawName = property_getName(properties[i]);
        const char *rawAttrs = property_getAttributes(properties[i]);
        NSString *name = rawName ? [NSString stringWithUTF8String:rawName] : @"?";
        NSString *attrs = rawAttrs ? [NSString stringWithUTF8String:rawAttrs] : @"";
        [propertiesOut addObject:@{ @"name": name, @"attributes": attrs }];
        if (HFAFamilyMetaContainsMarker(name) || HFAFamilyMetaContainsMarker(attrs)) {
            score += 8;
            HFAFamilyMetaAddReason(reasons, [NSString stringWithFormat:@"property:%@", name]);
        }
        if ([name isEqualToString:@"identifier"]) { hasIdentifier = YES; score += 2; }
        else if ([name isEqualToString:@"type"]) { hasType = YES; score += 2; }
        else if ([name isEqualToString:@"currentState"]) { hasCurrentState = YES; score += 3; }
        else if ([name isEqualToString:@"label"]) { score += 2; }
    }
    free(properties);

    unsigned protocolCount = 0;
    Protocol *__unsafe_unretained *protocols = class_copyProtocolList(cls, &protocolCount);
    for (unsigned i = 0; protocols && i < protocolCount; i++) {
        const char *rawName = protocol_getName(protocols[i]);
        NSString *name = rawName ? [NSString stringWithUTF8String:rawName] : @"?";
        [protocolsOut addObject:name];
        if ([name isEqualToString:@"APPatchItem"]) {
            score += 16;
            HFAFamilyMetaAddReason(reasons, @"protocol:APPatchItem");
        } else if (HFAFamilyMetaContainsMarker(name)) {
            score += 10;
            HFAFamilyMetaAddReason(reasons, [@"protocol:" stringByAppendingString:name]);
        }
    }
    free(protocols);

    if (hasIdentifier && hasType && hasCurrentState && hasSetCurrentState) {
        score += 12;
        HFAFamilyMetaAddReason(reasons, @"signature:feature-control");
    }
    if (uiSubclass && (hasIdentifier || hasCurrentState || hasSetCurrentState)) {
        score += 4;
        HFAFamilyMetaAddReason(reasons, @"hierarchy:UIControl-related");
    }
    if (family && strcmp(family, "legacy-ap") == 0 && [protocolsOut containsObject:@"APPatchItem"]) score += 6;
    if (family && strcmp(family, "runtime-5m") == 0 && hasIdentifier && hasCurrentState) score += 4;

    return @{ @"class": className,
              @"superclass": superName,
              @"score": @(score),
              @"reasons": reasons,
              @"methods": methodsOut,
              @"ivars": ivarsOut,
              @"properties": propertiesOut,
              @"protocols": protocolsOut };
}

static NSSet<NSString *> *HFAFamilyStage1MetadataScan(const char *image, const char *family) {
    int loadedIndex = HFAAppLocalPrimaryLoadedIndex();
    const char *imagePath = NULL;
    if (loadedIndex >= 0 && (uint32_t)loadedIndex < _dyld_image_count()) imagePath = _dyld_get_image_name((uint32_t)loadedIndex);
    if (!imagePath || !*imagePath) imagePath = HFAAppLocalPrimaryPath();
    if (!imagePath || !*imagePath) {
        HFAFamilyLog(@"[CLASS-META-END] status=no-image-path scanned=0 matched=0 selected=0");
        return [NSSet set];
    }

    unsigned classCount = 0;
    const char **classNames = objc_copyClassNamesForImage(imagePath, &classCount);
    HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-BEGIN] image=%s path=%s loadedIndex=%d classes=%u mode=metadata-only",
                  image ?: "?", imagePath, loadedIndex, classCount]);

    NSMutableArray<NSDictionary *> *all = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *matched = [NSMutableArray array];
    NSInteger threshold = (family && strcmp(family, "legacy-ap") == 0) ? 6 : 7;
    for (unsigned i = 0; classNames && i < classCount; i++) {
        Class cls = objc_lookUpClass(classNames[i]);
        if (!cls) continue;
        NSDictionary *record = HFAFamilyMetadataRecord(cls, family);
        if (!record) continue;
        [all addObject:record];
        if ([record[@"score"] integerValue] >= threshold) [matched addObject:record];
    }
    free(classNames);

    [matched sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
        if (sa != sb) return sa > sb ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"class"] compare:b[@"class"]];
    }];

    NSUInteger selectedCount = MIN(matched.count, (NSUInteger)20);
    NSMutableArray<NSString *> *selectedNames = [NSMutableArray arrayWithCapacity:selectedCount];
    for (NSUInteger i = 0; i < selectedCount; i++) {
        NSDictionary *record = matched[i];
        [selectedNames addObject:record[@"class"]];
        HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-HIT] rank=%lu class=%@ score=%@ super=%@ methods=%lu ivars=%lu properties=%lu protocols=%lu reasons=%@",
                      (unsigned long)i, record[@"class"], record[@"score"], record[@"superclass"],
                      (unsigned long)[record[@"methods"] count], (unsigned long)[record[@"ivars"] count],
                      (unsigned long)[record[@"properties"] count], (unsigned long)[record[@"protocols"] count],
                      [record[@"reasons"] componentsJoinedByString:@","]]);
    }

    NSDictionary *root = @{ @"schema": @"com.hfa.class-metadata/v1",
                            @"analyzer": @"HFAMapUniversal v1.9.37.7 TwoStageClassMetadataScan",
                            @"image": image ? [NSString stringWithUTF8String:image] : @"?",
                            @"imagePath": [NSString stringWithUTF8String:imagePath] ?: @"?",
                            @"family": family ? [NSString stringWithUTF8String:family] : @"?",
                            @"classCount": @(all.count),
                            @"matchedCount": @(matched.count),
                            @"selectedClasses": selectedNames,
                            @"classes": all };
    NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    if (json.length) {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_ClassMetadata.json"];
        [json writeToFile:path atomically:YES];
    }
    HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-END] status=ok scanned=%lu matched=%lu selected=%lu cap=20",
                  (unsigned long)all.count, (unsigned long)matched.count, (unsigned long)selectedNames.count]);
    return [NSSet setWithArray:selectedNames];
}

'''

struct_anchor = 'typedef struct {\n'
if 'HFAFamilyStage1MetadataScan' not in family:
    pos = family.find(struct_anchor)
    if pos < 0:
        raise SystemExit('family context anchor missing')
    family = family[:pos] + metadata_helpers + family[pos:]

old_struct = r'''typedef struct {
    const char *image;
    const char *family;
    NSMutableSet<NSValue *> *seenTargets;
    unsigned controls;
    unsigned featureControls;
    unsigned actionTargets;
    unsigned actions;
    unsigned igmmArrays;
    unsigned legacyProfiles;
} HFAFamilyContext;'''
new_struct = r'''typedef struct {
    const char *image;
    const char *family;
    NSMutableSet<NSValue *> *seenTargets;
    NSSet<NSString *> *stage1ClassNames;
    unsigned controls;
    unsigned featureControls;
    unsigned actionTargets;
    unsigned actions;
    unsigned igmmArrays;
    unsigned legacyProfiles;
    unsigned stage2MatchedInstances;
    unsigned stage2RejectedInstances;
} HFAFamilyContext;'''
if old_struct not in family:
    raise SystemExit('family context struct shape changed')
family = family.replace(old_struct, new_struct, 1)

stage2_helpers = r'''
static BOOL HFAFamilyStage2ClassMatch(HFAFamilyContext *context, Class cls, NSString **matchedClassOut) {
    if (matchedClassOut) *matchedClassOut = nil;
    if (!context || !cls || !context->stage1ClassNames.count) return NO;
    if (!HFAFamilyClassBelongsToImage(cls, context->image)) return NO;
    for (Class cursor = cls; cursor && HFAFamilyClassBelongsToImage(cursor, context->image); cursor = class_getSuperclass(cursor)) {
        NSString *name = [NSString stringWithUTF8String:class_getName(cursor) ?: "?"];
        if ([context->stage1ClassNames containsObject:name]) {
            if (matchedClassOut) *matchedClassOut = name;
            return YES;
        }
    }
    return NO;
}

static BOOL HFAFamilyStage2ObjectMatch(HFAFamilyContext *context, id object, NSString **matchedClassOut) {
    if (!object) return NO;
    return HFAFamilyStage2ClassMatch(context, object_getClass(object), matchedClassOut);
}

'''
mark_anchor = 'static BOOL HFAFamilyMarkTarget(HFAFamilyContext *context, id target) {'
if 'HFAFamilyStage2ObjectMatch' not in family:
    pos = family.find(mark_anchor)
    if pos < 0:
        raise SystemExit('family mark target anchor missing')
    family = family[:pos] + stage2_helpers + family[pos:]

profile_owner = r'''static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {
    if (!context || !owner) return;
    NSString *matchedClass = nil;
    if (!HFAFamilyStage2ObjectMatch(context, owner, &matchedClass)) {
        context->stage2RejectedInstances++;
        return;
    }
    if (!HFAFamilyMarkTarget(context, owner)) return;
    context->stage2MatchedInstances++;
    HFAFamilyLog([NSString stringWithFormat:@"[STAGE2-MATCH] origin=%s instanceClass=%s metadataClass=%@",
                  origin ?: "?", class_getName(object_getClass(owner)) ?: "?", matchedClass ?: @"?"]);
    if (strcmp(context->family, "runtime-5m") == 0) {
        NSString *ivarName = nil;
        NSArray *features = HFAFamilyFindIGMMFeatureArray(owner, &ivarName);
        if (features.count) {
            HFARegisterIGMMFeatureArray(owner, features);
            context->igmmArrays++;
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-ARRAY] origin=%s class=%s ivar=%@ features=%lu",
                          origin ?: "?", class_getName(object_getClass(owner)) ?: "?",
                          ivarName ?: @"?", (unsigned long)features.count]);
        }
    } else if (strcmp(context->family, "legacy-ap") == 0) {
        HFAJailpatchProfileTarget(owner, origin ?: "family-owner");
        context->legacyProfiles++;
    }
}'''
family = replace_named_function(family, 'HFAFamilyProfileOwner', profile_owner)

observe_actions = r'''static void HFAFamilyObserveActions(HFAFamilyContext *context, UIControl *control) {
    if (!context || !control) return;
    NSString *controlMatch = nil;
    if (!HFAFamilyStage2ObjectMatch(context, control, &controlMatch)) return;
    NSSet *targets = control.allTargets;
    UIControlEvents eventMask = control.allControlEvents;
    if (!eventMask) eventMask = UIControlEventAllEvents;
    for (id target in targets) {
        NSString *targetMatch = nil;
        if (!HFAFamilyStage2ObjectMatch(context, target, &targetMatch)) {
            context->stage2RejectedInstances++;
            continue;
        }
        context->actionTargets++;
        HFAFamilyProfileOwner(context, target, "control-target");
        NSArray<NSString *> *actions = [control actionsForTarget:target forControlEvent:eventMask];
        for (NSString *actionName in actions) {
            if (![actionName isKindOfClass:[NSString class]] || !actionName.length) continue;
            SEL action = NSSelectorFromString(actionName);
            HFAGenericMenuObserveAction(control, target, action);
            context->actions++;
        }
    }
}'''
family = replace_named_function(family, 'HFAFamilyObserveActions', observe_actions)

walk_view = r'''static void HFAFamilyWalkView(HFAFamilyContext *context, UIView *view, unsigned depth) {
    if (!context || !view || depth > 32) return;
    if ([view isKindOfClass:[UIControl class]]) {
        context->controls++;
        NSString *metadataClass = nil;
        if (HFAFamilyStage2ObjectMatch(context, view, &metadataClass)) {
            HFAFamilyProfileOwner(context, view, "ui-control");
            Class cls = object_getClass(view);
            if (HFAFamilyLooksLikeFeatureControl(cls)) {
                context->featureControls++;
                NSString *identifier = HFAFamilyStringGetter(view, "identifier");
                NSString *label = HFAFamilyLabel(view);
                if (identifier.length && label.length)
                    HFARegisterFeatureDefinition(label.UTF8String, identifier.UTF8String);
                HFAGenericMenuObserveObject(view, "family-ui-control");
                HFAFamilyObserveActions(context, (UIControl *)view);
                HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-CONTROL] family=%s class=%s metadataClass=%@ identifier=%@ label=%@",
                              context->family, class_getName(cls) ?: "?", metadataClass ?: @"?",
                              identifier ?: @"?", label ?: @"?"]);
            }
        }
    }
    NSArray<UIView *> *subviews = view.subviews;
    NSUInteger count = MIN(subviews.count, (NSUInteger)512);
    for (NSUInteger i = 0; i < count; i++) HFAFamilyWalkView(context, subviews[i], depth + 1);
}'''
family = replace_named_function(family, 'HFAFamilyWalkView', walk_view)

walk_controller = r'''static void HFAFamilyWalkController(HFAFamilyContext *context, UIViewController *controller, unsigned depth) {
    if (!context || !controller || depth > 16) return;
    NSString *metadataClass = nil;
    if (HFAFamilyStage2ObjectMatch(context, controller, &metadataClass))
        HFAFamilyProfileOwner(context, controller, "view-controller");
    if (controller.isViewLoaded && controller.view)
        HFAFamilyWalkView(context, controller.view, 0);
    NSArray<UIViewController *> *children = controller.childViewControllers;
    NSUInteger count = MIN(children.count, (NSUInteger)64);
    for (NSUInteger i = 0; i < count; i++)
        HFAFamilyWalkController(context, children[i], depth + 1);
    UIViewController *presented = controller.presentedViewController;
    if (presented) HFAFamilyWalkController(context, presented, depth + 1);
}'''
family = replace_named_function(family, 'HFAFamilyWalkController', walk_controller)

resolve = r'''unsigned HFAFamilyResolveCurrentUI(void) {
    @autoreleasepool {
        const char *image = HFAAppLocalPrimaryImage();
        const char *family = HFAAppLocalPrimaryFamily();
        if (!image || !*image || !family || !*family) {
            HFAFamilyLog(@"[FAMILY-RESOLVE] status=no-primary-context");
            HFACyberUIAppendLog(@"❌ 没有可解析的目标菜单模块");
            return 0;
        }
        if (strcmp(family, "runtime-5m") != 0 && strcmp(family, "legacy-ap") != 0) {
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE] status=unsupported family=%s image=%s", family, image]);
            HFACyberUIAppendLog(@"❌ 当前家族没有对应解析器");
            return 0;
        }

        NSSet<NSString *> *stage1 = HFAFamilyStage1MetadataScan(image, family);
        if (!stage1.count) {
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE] status=no-stage1-metadata-match family=%s image=%s", family, image]);
            HFACyberUIAppendLog(@"❌ metadata 扫描没有命中相关 class；为避免盲目运行时探测，已停止");
            return 0;
        }

        HFAPatchTraceResetAnalysis();
        HFAGenericMenuResetScanState();
        HFAJailpatchResetProfilerState();
        HFAFamilyClearCurrentOutputs();

        HFAFamilyContext context = {0};
        context.image = image;
        context.family = family;
        context.seenTargets = [NSMutableSet set];
        context.stage1ClassNames = stage1;

        NSString *displayFamily = strcmp(family, "runtime-5m") == 0 ? @"5M 家族" : @"Legacy-AP";
        HFACyberUIAppendLog([NSString stringWithFormat:@"🧬 metadata 命中 %lu 个 class；开始实例阶段", (unsigned long)stage1.count]);
        HFACyberUIAppendLog([NSString stringWithFormat:@"🔎 正在解析：%@ (%s)", displayFamily, image]);
        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-BEGIN] family=%s image=%s stage1Selected=%lu",
                      family, image, (unsigned long)stage1.count]);

        UIApplication *application = UIApplication.sharedApplication;
        NSArray<UIWindow *> *windows = application.windows ?: @[];
        NSUInteger windowCount = MIN(windows.count, (NSUInteger)32);
        for (NSUInteger i = 0; i < windowCount; i++) {
            UIWindow *window = windows[i];
            if (window.rootViewController)
                HFAFamilyWalkController(&context, window.rootViewController, 0);
            else
                HFAFamilyWalkView(&context, window, 0);
        }

        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-END] family=%s image=%s windows=%lu stage1Selected=%lu stage2Matched=%u stage2Rejected=%u controls=%u featureControls=%u targets=%u actions=%u igmmArrays=%u legacyProfiles=%u",
                      family, image, (unsigned long)windowCount, (unsigned long)stage1.count,
                      context.stage2MatchedInstances, context.stage2RejectedInstances, context.controls,
                      context.featureControls, context.actionTargets, context.actions,
                      context.igmmArrays, context.legacyProfiles]);
        HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 两阶段扫描完成：metadata %lu，实例 %u，菜单控件 %u，动作 %u",
                              (unsigned long)stage1.count, context.stage2MatchedInstances,
                              context.featureControls, context.actions]);
        if (strcmp(family, "runtime-5m") == 0)
            HFACyberUIAppendLog([NSString stringWithFormat:@"📋 5M 菜单定义数组：%u", context.igmmArrays]);
        else
            HFACyberUIAppendLog([NSString stringWithFormat:@"🔑 Legacy-AP 运行对象检查：%u", context.legacyProfiles]);
        return context.featureControls + context.igmmArrays;
    }
}'''
family = replace_named_function(family, 'HFAFamilyResolveCurrentUI', resolve)

for old, new in (
    ('HFAMapUniversal v1.9.37.6 LoadedImageFingerprint', 'HFAMapUniversal v1.9.37.7 TwoStageClassMetadataScan'),
    ('v1.9.37.6 LoadedImageFingerprint', 'v1.9.37.7 TwoStageClassMetadataScan'),
):
    app = app.replace(old, new)
    family = family.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)
    exporter = exporter.replace(old, new)

# Generation invariants. Stage 1 must remain metadata-only against the target
# image. No process-wide class enumeration and no target method invocation.
required = (
    'objc_copyClassNamesForImage', 'class_copyMethodList', 'class_copyIvarList',
    'class_copyPropertyList', 'class_copyProtocolList', '[CLASS-META-BEGIN]',
    '[CLASS-META-HIT]', '[CLASS-META-END]', '[STAGE2-MATCH]',
    'HFAFamilyStage2ObjectMatch', 'HFAMap_ClassMetadata.json',
)
for token in required:
    if token not in family:
        raise SystemExit(f'missing v19377 token: {token}')
for forbidden in ('objc_getClassList', 'objc_copyClassList', '_dyld_register_func_for_add_image'):
    if forbidden in app or forbidden in family:
        raise SystemExit(f'forbidden broad-scan regression: {forbidden}')

s1_start, s1_end = function_span(family, 'HFAFamilyStage1MetadataScan')
stage1_body = family[s1_start:s1_end]
for forbidden in ('objc_msgSend', 'object_getIvar', 'performSelector', 'method_invoke'):
    if forbidden in stage1_body:
        raise SystemExit(f'stage1 executes target behavior: {forbidden}')

APPLOCAL.write_text(app)
FAMILY.write_text(family)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
EXPORTER.write_text(exporter)
print('patched v1.9.37.7: selected-image metadata scan -> matched-class instance scan')
