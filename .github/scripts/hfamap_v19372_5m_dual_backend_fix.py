from pathlib import Path

DISPATCH = Path('hfamap/src/HFAMap5MDispatcherResolver.m')
FAMILY = Path('hfamap/src/HFAMapFamilyRuntimeResolver.m')
PROFILER = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
APPLOCAL = Path('hfamap/src/HFAMapAppLocalResolver.m')
CYBER = Path('hfamap/src/HFAMapCyberUI.m')
EXPORTER = Path('hfamap/src/HFAMapJSONExport.m')


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)


dispatch = DISPATCH.read_text()
family = FAMILY.read_text()
profiler = PROFILER.read_text()
app = APPLOCAL.read_text()
cyber = CYBER.read_text()
exporter = EXPORTER.read_text()

# ---------------------------------------------------------------------------
# Crash fix: this target is built without -fobjc-arc. The v1.9.37.1 globals
# were assigned autoreleased NSMutableDictionary instances inside the family
# resolver autorelease pool, then read later by the exporter. Own the storage
# explicitly across the resolver -> finalize/export boundary.
# ---------------------------------------------------------------------------
dispatch = once(
    dispatch,
    '    if (!gHFA5MFeatures && create) gHFA5MFeatures = [NSMutableDictionary dictionary];\n',
    '    if (!gHFA5MFeatures && create) gHFA5MFeatures = [[NSMutableDictionary alloc] init];\n',
    'retain feature storage',
)
dispatch = once(
    dispatch,
    '        if (!gHFA5MDispatcherCache) gHFA5MDispatcherCache = [NSMutableDictionary dictionary];\n',
    '        if (!gHFA5MDispatcherCache) gHFA5MDispatcherCache = [[NSMutableDictionary alloc] init];\n',
    'retain dispatcher cache',
)
old_reset = '''void HFA5MDispatcherReset(void) {
    gHFA5MFeatures = [NSMutableDictionary dictionary];
    gHFA5MDispatcherCache = [NSMutableDictionary dictionary];
    HFA5MLog(@"[5M-DISPATCH-RESET]");
}'''
new_reset = '''void HFA5MDispatcherReset(void) {
#if !__has_feature(objc_arc)
    [gHFA5MFeatures release];
    [gHFA5MDispatcherCache release];
#endif
    gHFA5MFeatures = [[NSMutableDictionary alloc] init];
    gHFA5MDispatcherCache = [[NSMutableDictionary alloc] init];
    HFA5MLog(@"[5M-DISPATCH-RESET] storage=owned");
}'''
dispatch = once(dispatch, old_reset, new_reset, 'own dispatcher reset storage')

# ---------------------------------------------------------------------------
# 5M dual backend: real 5M samples exist in two runtime layouts.
# - IGMM-backed: strict array of {label, identifier, type}
# - Jailpatch-backed: action target owns a feature array whose records contain
#   encrypted offset/patch wrappers. Reuse the existing proven profiler/decrypt
#   chain, but only for the already-selected image-local action target.
# ---------------------------------------------------------------------------
profile_anchor = 'void HFAJailpatchProfileTarget(id target, const char *context) {'
probe = r'''BOOL HFAJailpatchCanProfileTarget(id target) {
    if (!target) return NO;
    @autoreleasepool {
        @try {
            NSString *arrayIvar = nil;
            NSArray *features = HFAJPFindFeatureArray(target, &arrayIvar);
            return features.count > 0;
        } @catch (__unused id exception) {
            return NO;
        }
    }
}

'''
if 'BOOL HFAJailpatchCanProfileTarget(id target)' not in profiler:
    profiler = once(profiler, profile_anchor, probe + profile_anchor, 'add bounded jailpatch target probe')

extern_anchor = 'extern void HFAJailpatchProfileTarget(id target, const char *context);\n'
family = once(
    family,
    extern_anchor,
    extern_anchor + 'extern BOOL HFAJailpatchCanProfileTarget(id target);\n',
    'declare bounded jailpatch probe',
)

old_runtime = '''    if (strcmp(context->family, "runtime-5m") == 0) {
        NSString *ivarName = nil;
        NSArray *features = HFAFamilyFindIGMMFeatureArray(owner, &ivarName);
        if (features.count) {
            HFA5MDispatcherObserveFeatureArray(owner, features);
            HFARegisterIGMMFeatureArray(owner, features);
            context->igmmArrays++;
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-ARRAY] origin=%s class=%s ivar=%@ features=%lu",
                          origin ?: "?", class_getName(object_getClass(owner)) ?: "?",
                          ivarName ?: @"?", (unsigned long)features.count]);
        }
    } else if (strcmp(context->family, "legacy-ap") == 0) {'''
new_runtime = '''    if (strcmp(context->family, "runtime-5m") == 0) {
        NSString *ivarName = nil;
        NSArray *features = HFAFamilyFindIGMMFeatureArray(owner, &ivarName);
        if (features.count) {
            HFA5MDispatcherObserveFeatureArray(owner, features);
            HFARegisterIGMMFeatureArray(owner, features);
            context->igmmArrays++;
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-ARRAY] origin=%s class=%s ivar=%@ features=%lu backend=igmm",
                          origin ?: "?", class_getName(object_getClass(owner)) ?: "?",
                          ivarName ?: @"?", (unsigned long)features.count]);
        } else {
            Class ownerClass = object_getClass(owner);
            if (HFAFamilyClassBelongsToImage(ownerClass, context->image) &&
                HFAJailpatchCanProfileTarget(owner)) {
                HFAJailpatchProfileTarget(owner, "runtime-5m-jailpatch-target");
                context->legacyProfiles++;
                HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-5M-JAILPATCH] origin=%s class=%s backend=jailpatch",
                              origin ?: "?", class_getName(ownerClass) ?: "?"]);
            }
        }
    } else if (strcmp(context->family, "legacy-ap") == 0) {'''
family = once(family, old_runtime, new_runtime, 'add 5M jailpatch backend fallback')

# Visible version only; schemas remain stable.
for old, new in (
    ('HFAMapUniversal v1.9.37.1 5MDispatcherResolver', 'HFAMapUniversal v1.9.37.2 5MDualBackendFix'),
    ('v1.9.37.1 5MDispatcherResolver', 'v1.9.37.2 5MDualBackendFix'),
):
    app = app.replace(old, new)
    cyber = cyber.replace(old, new)
    exporter = exporter.replace(old, new)

# Hard generation checks.
if '[NSMutableDictionary dictionary]' in dispatch and ('gHFA5MFeatures = [NSMutableDictionary dictionary]' in dispatch or 'gHFA5MDispatcherCache = [NSMutableDictionary dictionary]' in dispatch):
    raise SystemExit('autoreleased 5M global storage remains')
for required in (
    'gHFA5MFeatures = [[NSMutableDictionary alloc] init]',
    'gHFA5MDispatcherCache = [[NSMutableDictionary alloc] init]',
    'storage=owned',
):
    if required not in dispatch:
        raise SystemExit(f'missing MRC lifetime fix: {required}')
for required in (
    'HFAJailpatchCanProfileTarget',
    'runtime-5m-jailpatch-target',
    'FAMILY-5M-JAILPATCH',
):
    if required not in family and required not in profiler:
        raise SystemExit(f'missing 5M dual-backend integration: {required}')

DISPATCH.write_text(dispatch)
FAMILY.write_text(family)
PROFILER.write_text(profiler)
APPLOCAL.write_text(app)
CYBER.write_text(cyber)
EXPORTER.write_text(exporter)
print('patched v1.9.37.2: owned 5M dispatcher state + IGMM/Jailpatch dual backend')
