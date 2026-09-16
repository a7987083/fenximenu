from pathlib import Path

FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
PROFILER = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
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


family = FAMILY.read_text()
profiler = PROFILER.read_text()
app = APPLOCAL.read_text()
cyber = CYBER.read_text()
legacy = LEGACY.read_text()
exporter = EXPORTER.read_text()

# ---------------------------------------------------------------------------
# Image ownership: prefer the manually selected loaded image's exact canonical
# path. Basename is retained only as a last-resort compatibility fallback when
# no exact selected path is available.
# ---------------------------------------------------------------------------
class_belongs = r'''static BOOL HFAFamilyClassBelongsToImage(Class cls, const char *image) {
    if (!cls) return NO;
    const char *classRaw = class_getImageName(cls);
    if (!classRaw || !*classRaw) return NO;
    NSString *classPath = [[NSString stringWithUTF8String:classRaw] stringByStandardizingPath].stringByResolvingSymlinksInPath;
    const char *selectedRaw = NULL;
    int loadedIndex = HFAAppLocalPrimaryLoadedIndex();
    if (loadedIndex >= 0 && (uint32_t)loadedIndex < _dyld_image_count()) selectedRaw = _dyld_get_image_name((uint32_t)loadedIndex);
    if (!selectedRaw || !*selectedRaw) selectedRaw = HFAAppLocalPrimaryPath();
    if (selectedRaw && *selectedRaw) {
        NSString *selectedPath = [[NSString stringWithUTF8String:selectedRaw] stringByStandardizingPath].stringByResolvingSymlinksInPath;
        if (selectedPath.length && classPath.length) return [classPath isEqualToString:selectedPath];
    }
    return image && *image && strcmp(HFAFamilyBase(classRaw), image) == 0;
}'''
family = replace_named_function(family, 'HFAFamilyClassBelongsToImage', class_belongs)

# ---------------------------------------------------------------------------
# Stage 1B: seed scores remain useful evidence, but are no longer the only
# admission gate. Expand within the selected image using metadata-only shape:
# collection holders, delegate/controller-like owners, and concrete type edges
# to seed classes. No target methods or target ivars are read here.
# ---------------------------------------------------------------------------
meta_anchor = 'static NSSet<NSString *> *HFAFamilyStage1MetadataScan(const char *image, const char *family) {'
meta_helpers = r'''
static BOOL HFAFamilyTypeLooksCollection(NSString *type) {
    if (!type.length) return NO;
    static NSArray<NSString *> *names = nil;
    if (!names) names = [[NSArray alloc] initWithObjects:@"NSArray", @"NSMutableArray", @"NSDictionary", @"NSMutableDictionary", @"NSSet", @"NSMutableSet", nil];
    for (NSString *name in names) if ([type rangeOfString:name].location != NSNotFound) return YES;
    return NO;
}

static NSUInteger HFAFamilyCollectionFieldCount(NSDictionary *record) {
    NSUInteger count = 0;
    for (NSDictionary *iv in record[@"ivars"]) if (HFAFamilyTypeLooksCollection(iv[@"type"])) count++;
    for (NSDictionary *prop in record[@"properties"]) if (HFAFamilyTypeLooksCollection(prop[@"attributes"])) count++;
    return count;
}

static NSUInteger HFAFamilyDelegateProtocolCount(NSDictionary *record) {
    NSUInteger count = 0;
    for (NSString *name in record[@"protocols"]) if ([name hasSuffix:@"Delegate"] || [name hasSuffix:@"DataSource"]) count++;
    return count;
}

static BOOL HFAFamilyRecordReferencesAnyClass(NSDictionary *record, NSSet<NSString *> *names, NSString **edgeOut) {
    if (edgeOut) *edgeOut = nil;
    if (!record || !names.count) return NO;
    for (NSDictionary *iv in record[@"ivars"]) {
        NSString *type = iv[@"type"];
        for (NSString *name in names) if ([type rangeOfString:name].location != NSNotFound) {
            if (edgeOut) *edgeOut = [NSString stringWithFormat:@"ivar:%@->%@", iv[@"name"] ?: @"?", name];
            return YES;
        }
    }
    for (NSDictionary *prop in record[@"properties"]) {
        NSString *attrs = prop[@"attributes"];
        for (NSString *name in names) if ([attrs rangeOfString:name].location != NSNotFound) {
            if (edgeOut) *edgeOut = [NSString stringWithFormat:@"property:%@->%@", prop[@"name"] ?: @"?", name];
            return YES;
        }
    }
    return NO;
}

static BOOL HFAFamilyLooksLikeStructuralOwner(NSDictionary *record, NSSet<NSString *> *seedNames, NSString **reasonOut) {
    if (reasonOut) *reasonOut = nil;
    if (!record) return NO;
    NSUInteger collections = HFAFamilyCollectionFieldCount(record);
    NSUInteger delegates = HFAFamilyDelegateProtocolCount(record);
    NSUInteger methods = [record[@"methods"] count];
    NSUInteger ivars = [record[@"ivars"] count];
    NSUInteger properties = [record[@"properties"] count];
    NSString *edge = nil;
    if (HFAFamilyRecordReferencesAnyClass(record, seedNames, &edge)) {
        if (reasonOut) *reasonOut = [@"type-edge:" stringByAppendingString:edge ?: @"?"];
        return YES;
    }
    if (collections && delegates) {
        if (reasonOut) *reasonOut = [NSString stringWithFormat:@"collection+delegate collections=%lu delegates=%lu", (unsigned long)collections, (unsigned long)delegates];
        return YES;
    }
    if (collections >= 2 && (methods >= 24 || ivars >= 8 || properties >= 8)) {
        if (reasonOut) *reasonOut = [NSString stringWithFormat:@"collection-owner collections=%lu methods=%lu ivars=%lu properties=%lu", (unsigned long)collections, (unsigned long)methods, (unsigned long)ivars, (unsigned long)properties];
        return YES;
    }
    return NO;
}

'''
if 'HFAFamilyLooksLikeStructuralOwner' not in family:
    pos = family.find(meta_anchor)
    if pos < 0: raise SystemExit('stage1 anchor missing')
    family = family[:pos] + meta_helpers + family[pos:]

stage1 = r'''static NSSet<NSString *> *HFAFamilyStage1MetadataScan(const char *image, const char *family) {
    int loadedIndex = HFAAppLocalPrimaryLoadedIndex();
    const char *imagePath = NULL;
    if (loadedIndex >= 0 && (uint32_t)loadedIndex < _dyld_image_count()) imagePath = _dyld_get_image_name((uint32_t)loadedIndex);
    if (!imagePath || !*imagePath) imagePath = HFAAppLocalPrimaryPath();
    if (!imagePath || !*imagePath) {
        HFAFamilyLog(@"[CLASS-META-END] status=no-image-path scanned=0 seeds=0 expanded=0 selected=0");
        return [NSSet set];
    }

    unsigned classCount = 0;
    const char **classNames = objc_copyClassNamesForImage(imagePath, &classCount);
    HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-BEGIN] image=%s path=%s loadedIndex=%d classes=%u mode=metadata-only+structural-expansion",
                  image ?: "?", imagePath, loadedIndex, classCount]);

    NSMutableArray<NSDictionary *> *all = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *seeds = [NSMutableArray array];
    NSInteger threshold = (family && strcmp(family, "legacy-ap") == 0) ? 6 : 7;
    for (unsigned i = 0; classNames && i < classCount; i++) {
        Class cls = objc_lookUpClass(classNames[i]);
        if (!cls || !HFAFamilyClassBelongsToImage(cls, image)) continue;
        NSDictionary *record = HFAFamilyMetadataRecord(cls, family);
        if (!record) continue;
        [all addObject:record];
        if ([record[@"score"] integerValue] >= threshold) [seeds addObject:record];
    }
    free(classNames);

    [seeds sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
        if (sa != sb) return sa > sb ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"class"] compare:b[@"class"]];
    }];

    NSMutableSet<NSString *> *selectedNames = [NSMutableSet set];
    NSMutableSet<NSString *> *seedNames = [NSMutableSet set];
    for (NSDictionary *record in seeds) {
        NSString *name = record[@"class"];
        if (!name.length) continue;
        [seedNames addObject:name];
        [selectedNames addObject:name];
        HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-SEED] class=%@ score=%@ super=%@ methods=%lu ivars=%lu properties=%lu protocols=%lu reasons=%@",
                      name, record[@"score"], record[@"superclass"],
                      (unsigned long)[record[@"methods"] count], (unsigned long)[record[@"ivars"] count],
                      (unsigned long)[record[@"properties"] count], (unsigned long)[record[@"protocols"] count],
                      [record[@"reasons"] componentsJoinedByString:@","]]);
    }

    NSUInteger expandedCount = 0;
    BOOL changed = YES;
    unsigned pass = 0;
    while (changed && pass < 3) {
        changed = NO;
        pass++;
        NSSet<NSString *> *current = [selectedNames copy];
        for (NSDictionary *record in all) {
            NSString *name = record[@"class"];
            if (!name.length || [selectedNames containsObject:name]) continue;
            NSString *reason = nil;
            if (!HFAFamilyLooksLikeStructuralOwner(record, current, &reason)) continue;
            [selectedNames addObject:name];
            expandedCount++;
            changed = YES;
            HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-EXPAND] pass=%u class=%@ super=%@ methods=%lu ivars=%lu properties=%lu collections=%lu delegates=%lu reason=%@",
                          pass, name, record[@"superclass"], (unsigned long)[record[@"methods"] count],
                          (unsigned long)[record[@"ivars"] count], (unsigned long)[record[@"properties"] count],
                          (unsigned long)HFAFamilyCollectionFieldCount(record), (unsigned long)HFAFamilyDelegateProtocolCount(record), reason ?: @"?"]);
        }
#if !__has_feature(objc_arc)
        [current release];
#endif
    }

    NSMutableArray<NSString *> *selectedSorted = [[selectedNames allObjects] mutableCopy];
    [selectedSorted sortUsingSelector:@selector(compare:)];
    NSDictionary *root = @{ @"schema": @"com.hfa.class-metadata/v2",
                            @"analyzer": @"HFAMapUniversal v1.9.37.8 StructuralRelationExpansion",
                            @"image": image ? [NSString stringWithUTF8String:image] : @"?",
                            @"imagePath": [NSString stringWithUTF8String:imagePath] ?: @"?",
                            @"family": family ? [NSString stringWithUTF8String:family] : @"?",
                            @"classCount": @(all.count),
                            @"seedCount": @(seedNames.count),
                            @"expandedCount": @(expandedCount),
                            @"selectedCount": @(selectedNames.count),
                            @"selectedClasses": selectedSorted,
                            @"classes": all };
    NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    if (json.length) {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_ClassMetadata.json"];
        [json writeToFile:path atomically:YES];
    }
    HFAFamilyLog([NSString stringWithFormat:@"[CLASS-META-END] status=ok scanned=%lu seeds=%lu expanded=%lu selected=%lu cap=none",
                  (unsigned long)all.count, (unsigned long)seedNames.count, (unsigned long)expandedCount, (unsigned long)selectedNames.count]);
#if !__has_feature(objc_arc)
    [selectedSorted release];
#endif
    return [NSSet setWithSet:selectedNames];
}'''
family = replace_named_function(family, 'HFAFamilyStage1MetadataScan', stage1)

# Context selected set becomes mutable so a real UIControl allTargets relation
# can promote a same-image owner after metadata narrowing.
family = family.replace('    NSSet<NSString *> *stage1ClassNames;\n', '    NSMutableSet<NSString *> *stage1ClassNames;\n', 1)
family = family.replace('        context.stage1ClassNames = stage1;\n', '        context.stage1ClassNames = [[stage1 mutableCopy] autorelease];\n', 1)

# ---------------------------------------------------------------------------
# Stage 2A: direct action-target relation is strong evidence. Promote only
# same-selected-image classes. Before deep profiling a newly promoted owner,
# perform a shallow direct-ivar collection probe: no unknown selector calls and
# no recursive object graph traversal.
# ---------------------------------------------------------------------------
profile_anchor = 'static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {'
stage2_helpers = r'''
static BOOL HFAFamilyFeatureLikeDictionary(id value, BOOL requireType) {
    if (![value isKindOfClass:[NSDictionary class]]) return NO;
    NSDictionary *d = value;
    id label = d[@"label"], identifier = d[@"identifier"], type = d[@"type"];
    if (![label isKindOfClass:[NSString class]] || ![(NSString *)label length]) return NO;
    if (![identifier isKindOfClass:[NSString class]] || ![(NSString *)identifier length]) return NO;
    if (requireType && (![type isKindOfClass:[NSString class]] || ![(NSString *)type length])) return NO;
    return YES;
}

static BOOL HFAFamilyShallowOwnerProbe(HFAFamilyContext *context, id owner, NSString **reasonOut) {
    if (reasonOut) *reasonOut = nil;
    if (!context || !owner) return NO;
    Class cls = object_getClass(owner);
    if (!HFAFamilyClassBelongsToImage(cls, context->image)) return NO;
    for (Class cursor = cls; cursor && cursor != [NSObject class] && HFAFamilyClassBelongsToImage(cursor, context->image); cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned i = 0; ivars && i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type || type[0] != '@') continue;
            id value = nil;
            @try { value = object_getIvar(owner, ivars[i]); } @catch (__unused id exception) { value = nil; }
            NSArray *array = nil;
            if ([value isKindOfClass:[NSArray class]]) array = value;
            else if ([value isKindOfClass:[NSSet class]]) array = [(NSSet *)value allObjects];
            if (!array.count) continue;
            NSUInteger inspect = MIN(array.count, (NSUInteger)256);
            NSUInteger featureLike = 0, typedFeatureLike = 0, sameImageObjects = 0;
            for (NSUInteger j = 0; j < inspect; j++) {
                id item = array[j];
                if (HFAFamilyFeatureLikeDictionary(item, NO)) featureLike++;
                if (HFAFamilyFeatureLikeDictionary(item, YES)) typedFeatureLike++;
                Class itemClass = item ? object_getClass(item) : Nil;
                if (itemClass && HFAFamilyClassBelongsToImage(itemClass, context->image)) sameImageObjects++;
            }
            BOOL featureShape = featureLike >= 2 && (featureLike * 2 >= inspect || featureLike >= 4);
            BOOL recordShape = sameImageObjects >= 2 && (sameImageObjects * 2 >= inspect || sameImageObjects >= 4);
            if (featureShape || recordShape) {
                NSString *ivarName = [NSString stringWithUTF8String:ivar_getName(ivars[i]) ?: "?"];
                NSString *reason = [NSString stringWithFormat:@"ivar=%@ count=%lu inspected=%lu featureLike=%lu typed=%lu sameImageObjects=%lu",
                                    ivarName, (unsigned long)array.count, (unsigned long)inspect,
                                    (unsigned long)featureLike, (unsigned long)typedFeatureLike, (unsigned long)sameImageObjects];
                HFAFamilyLog([NSString stringWithFormat:@"[OWNER-SHALLOW] class=%s %@", class_getName(cls) ?: "?", reason]);
                if (reasonOut) *reasonOut = reason;
                free(ivars);
                return YES;
            }
        }
        free(ivars);
    }
    return NO;
}

static BOOL HFAFamilyPromoteRelationTarget(HFAFamilyContext *context, id target, const char *origin) {
    if (!context || !target) return NO;
    Class cls = object_getClass(target);
    if (!HFAFamilyClassBelongsToImage(cls, context->image)) return NO;
    NSString *name = [NSString stringWithUTF8String:class_getName(cls) ?: "?"];
    if ([context->stage1ClassNames containsObject:name]) return YES;
    NSString *probeReason = nil;
    if (!HFAFamilyShallowOwnerProbe(context, target, &probeReason)) {
        HFAFamilyLog([NSString stringWithFormat:@"[RELATION-REJECT] origin=%s class=%@ reason=no-shallow-owner-shape", origin ?: "?", name]);
        return NO;
    }
    [context->stage1ClassNames addObject:name];
    HFAFamilyLog([NSString stringWithFormat:@"[RELATION-PROMOTE] origin=%s class=%@ reason=%@", origin ?: "?", name, probeReason ?: @"allTargets+same-image"]);
    return YES;
}

'''
if 'HFAFamilyPromoteRelationTarget' not in family:
    pos = family.find(profile_anchor)
    if pos < 0: raise SystemExit('profile owner anchor missing')
    family = family[:pos] + stage2_helpers + family[pos:]

# Restore v1.9.37.2 dual backend behavior inside the v1.9.37.7 Stage2 gate.
if 'extern BOOL HFAJailpatchCanProfileTarget(id target);' not in family:
    family = family.replace('extern void HFAJailpatchProfileTarget(id target, const char *context);\n',
                            'extern void HFAJailpatchProfileTarget(id target, const char *context);\nextern BOOL HFAJailpatchCanProfileTarget(id target);\n', 1)
if 'extern void HFA5MDispatcherObserveFeatureArray' not in family:
    marker = 'extern void HFARegisterIGMMFeatureArray(id menuTarget, id featureArray);\n'
    family = family.replace(marker, marker + 'extern void HFA5MDispatcherObserveFeatureArray(id menuTarget, id featureArray);\n', 1)

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
            HFA5MDispatcherObserveFeatureArray(owner, features);
            HFARegisterIGMMFeatureArray(owner, features);
            context->igmmArrays++;
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-ARRAY] origin=%s class=%s ivar=%@ features=%lu backend=igmm",
                          origin ?: "?", class_getName(object_getClass(owner)) ?: "?", ivarName ?: @"?", (unsigned long)features.count]);
        } else if (HFAJailpatchCanProfileTarget(owner)) {
            HFAJailpatchProfileTarget(owner, "runtime-5m-jailpatch-target");
            context->legacyProfiles++;
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-JAILPATCH] origin=%s class=%s backend=jailpatch",
                          origin ?: "?", class_getName(object_getClass(owner)) ?: "?"]);
        }
    } else if (strcmp(context->family, "legacy-ap") == 0) {
        if (HFAJailpatchCanProfileTarget(owner)) {
            HFAJailpatchProfileTarget(owner, origin ?: "family-owner");
            context->legacyProfiles++;
        }
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
            if (!HFAFamilyPromoteRelationTarget(context, target, "control-allTargets")) {
                context->stage2RejectedInstances++;
                continue;
            }
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

# ---------------------------------------------------------------------------
# Flexible Jailpatch feature-array detection. Old exact-all-items matching
# rejected real mixed arrays (e.g. 12 label/id feature dictionaries plus helper
# items). Treat counts as evidence density, not schema identity.
# ---------------------------------------------------------------------------
find_array = r'''static NSArray *HFAJPFindFeatureArray(id target, NSString **ivarNameOut) {
    if (ivarNameOut) *ivarNameOut = nil;
    NSArray *best = nil;
    NSString *bestName = nil;
    NSUInteger bestFeatureLike = 0;
    NSUInteger bestInspected = 0;
    for (Class cursor = object_getClass(target); cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned i = 0; ivars && i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type || type[0] != '@') continue;
            id value = nil;
            @try { value = object_getIvar(target, ivars[i]); } @catch (__unused id exception) { value = nil; }
            if (![value isKindOfClass:[NSArray class]]) continue;
            NSArray *a = value;
            if (!a.count) continue;
            NSUInteger inspect = MIN(a.count, (NSUInteger)256);
            NSUInteger featureLike = 0;
            for (NSUInteger j = 0; j < inspect; j++) if (HFAJPFeatureDictionary(a[j], NULL, NULL)) featureLike++;
            BOOL shape = featureLike >= 2 && (featureLike * 2 >= inspect || featureLike >= 4);
            if (!shape) continue;
            BOOL better = !best || featureLike > bestFeatureLike || (featureLike == bestFeatureLike && inspect < bestInspected);
            if (better) {
                best = a;
                bestFeatureLike = featureLike;
                bestInspected = inspect;
                const char *name = ivar_getName(ivars[i]);
                bestName = [NSString stringWithUTF8String:name ?: "?"];
            }
        }
        free(ivars);
    }
    if (best) HFAJPLog("[JAILPATCH-ARRAY-CANDIDATE] class=%s ivar=%s count=%u inspected=%u featureLike=%u\n",
                       class_getName(object_getClass(target)) ?: "?", bestName.UTF8String ?: "?",
                       (unsigned)best.count, (unsigned)bestInspected, (unsigned)bestFeatureLike);
    if (ivarNameOut) *ivarNameOut = bestName;
    return best;
}'''
profiler = replace_named_function(profiler, 'HFAJPFindFeatureArray', find_array)

# Visible version only; schemas are intentionally versioned only where the
# class metadata format changed to v2.
for old, new in (
    ('HFAMapUniversal v1.9.37.7 TwoStageClassMetadataScan', 'HFAMapUniversal v1.9.37.8 StructuralRelationExpansion'),
    ('v1.9.37.7 TwoStageClassMetadataScan', 'v1.9.37.8 StructuralRelationExpansion'),
):
    app = app.replace(old, new)
    family = family.replace(old, new)
    cyber = cyber.replace(old, new)
    legacy = legacy.replace(old, new)
    exporter = exporter.replace(old, new)

# Generation invariants.
required_family = (
    '[CLASS-META-SEED]', '[CLASS-META-EXPAND]', 'cap=none',
    'HFAFamilyLooksLikeStructuralOwner', '[OWNER-SHALLOW]', '[RELATION-PROMOTE]',
    'HFA5MDispatcherObserveFeatureArray', 'HFAJailpatchCanProfileTarget',
    'runtime-5m-jailpatch-target', '[FAMILY-5M-JAILPATCH]',
)
for token in required_family:
    if token not in family: raise SystemExit(f'missing v19378 family token: {token}')
if '[JAILPATCH-ARRAY-CANDIDATE]' not in profiler:
    raise SystemExit('flexible jailpatch array probe missing')
for forbidden in ('objc_getClassList', 'objc_copyClassList', '_dyld_register_func_for_add_image'):
    if forbidden in family or forbidden in app:
        raise SystemExit(f'forbidden broad scan/listener regression: {forbidden}')

s1_start, s1_end = function_span(family, 'HFAFamilyStage1MetadataScan')
stage1_body = family[s1_start:s1_end]
for forbidden in ('objc_msgSend', 'object_getIvar', 'performSelector', 'method_invoke'):
    if forbidden in stage1_body:
        raise SystemExit(f'stage1 executes target behavior: {forbidden}')

jp_start, jp_end = function_span(profiler, 'HFAJPFindFeatureArray')
jp_body = profiler[jp_start:jp_end]
if 'valid == a.count' in jp_body or 'valid != a.count' in jp_body:
    raise SystemExit('exact-all-items jailpatch array rule remains')

FAMILY.write_text(family)
PROFILER.write_text(profiler)
APPLOCAL.write_text(app)
CYBER.write_text(cyber)
LEGACY.write_text(legacy)
EXPORTER.write_text(exporter)
print('patched v1.9.37.8: Stage1B structural expansion + allTargets relation promotion + shallow owner probe + restored 5M dual backend')
