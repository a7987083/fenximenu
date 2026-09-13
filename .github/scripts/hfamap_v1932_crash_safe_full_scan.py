from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")
generic_path = Path("hfamap/src/HFAMapGenericMenuResolver.m")
profiler_path = Path("hfamap/src/HFAMapJailpatchRuntimeProfiler.m")
selector_path = Path("hfamap/src/HFAMapJailpatchSelectorResolver.m")

s = patch_path.read_text()
l = legacy_path.read_text()
g = generic_path.read_text()
p = profiler_path.read_text()
r = selector_path.read_text()


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


def replace_exact(text, old, new, expected, label):
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} matches, got {count}")
    return text.replace(old, new)


# v1.9.32 CrashSafeFullScan
# Device evidence from both supplied 5 MB games showed the same failure shape:
# a semantic menu target was already found in window 0, but Auto Detect kept
# traversing unrelated UIKit windows and never reached AUTO-TRAVERSAL-END.
# Historical v1.9.24/v1.9.29 discovery also walked framework superclass ivars.
# ObjC @try/@catch cannot catch EXC_BAD_ACCESS, so the fix is structural:
# - never enumerate UIView/UIWindow/NS*/CA*/CG* superclass ivars from custom objects
# - prefer semantic feature-array discovery over the old deep runtime-graph probe
# - mark a confirmed 5 MB semantic menu target as found and stop scanning other windows
# - preserve the iGMM feature-array registration/export path without deep probing
# - preserve v1.9.31 generic secret-decrypt resolver unchanged

s = replace_once(
    s,
    '[HFALearn v1.9.31 GenericSecretDecryptResolver] loaded',
    '[HFALearn v1.9.32 CrashSafeFullScan] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.31 GenericSecretDecryptResolver] loaded',
    '[HFALearn UI v1.9.32 CrashSafeFullScan] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=selector-resolver+generic-secret-decrypt export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=semantic-feature-array jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    'update dual mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.31 GenericSecretDecryptResolver',
    'HFAMap v1.9.32 CrashSafeFullScan',
    2,
    'update generic resolver markers',
)
g = replace_once(g, '@"1.9.31"', '@"1.9.32"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.31 GenericSecretDecryptResolver";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.32 CrashSafeFullScan";',
    'update profiler version marker',
)
p = replace_once(p, '@"1.9.31"', '@"1.9.32"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.31 GenericSecretDecryptResolver";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.32 CrashSafeFullScan";',
    'update selector version marker',
)
r = replace_once(r, '@"1.9.31"', '@"1.9.32"', 'update selector json version')

l = replace_once(
    l,
    'HFAMap v1.9.31 Generic Secret Resolver',
    'HFAMap v1.9.32 Crash-Safe Scan',
    'update panel title',
)
l = replace_once(
    l,
    'Legacy + Jailpatch selector resolver with generic secret decrypt enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'Crash-safe semantic scan + generic secret decrypt enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'update panel help',
)

# Expose a read-only semantic predicate so Legacy.m can stop scanning after a
# real Jailpatch feature array has been found. This uses the already-existing
# feature-array validator and does not mark/dedupe/profile the target.
profile_anchor = 'void HFAJailpatchProfileTarget(id target, const char *context) {\n'
profile_helper = r'''int HFAJailpatchTargetHasFeatures(id target) {
    if (!target) return 0;
    @autoreleasepool {
        @try {
            NSArray *features = HFAJPFindFeatureArray(target, NULL);
            return features.count > 0 ? 1 : 0;
        } @catch (__unused id exception) {
            return 0;
        }
    }
}

''' + profile_anchor
p = replace_once(p, profile_anchor, profile_helper, 'add semantic target predicate')

# HFAJPFindFeatureArray historically walked into UIView/UIWindow framework
# superclasses. Stop once the cursor leaves the custom class hierarchy.
find_loop = 'for (Class cursor = object_getClass(target); cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {\n        unsigned count = 0;'
find_loop_safe = 'for (Class cursor = object_getClass(target); cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {\n        if (HFAJPIsFrameworkClass(cursor)) break;\n        unsigned count = 0;'
p = replace_once(p, find_loop, find_loop_safe, 'bound feature-array superclass scan')

# Runtime-record profiling should likewise never enumerate private framework
# superclass ivars for a custom UIView-derived object.
profile_loop = 'for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {\n        unsigned count = 0;'
profile_loop_safe = 'for (Class cursor = cls; cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {\n        if (HFAJPIsFrameworkClass(cursor)) break;\n        unsigned count = 0;'
p = replace_once(p, profile_loop, profile_loop_safe, 'bound object profiler superclass scan')

# The legacy v1.9.24 deep graph probe also walked system superclass ivars.
old_igmm_super = '        const char*kcn=class_getName(k);unsigned int count=0;Ivar*ivars=class_copyIvarList(k,&count);if(count>64)count=64;'
new_igmm_super = '        const char*kcn=class_getName(k);if(igmm_skip_custom(kcn))break;unsigned int count=0;Ivar*ivars=class_copyIvarList(k,&count);if(count>64)count=64;'
l = replace_once(l, old_igmm_super, new_igmm_super, 'bound legacy iGMM superclass scan')

# The old deep-probe implementation is kept for historical/diagnostic reference,
# but it must not be reintroduced into Auto Detect. Mark it unused so -Werror
# does not turn its intentional inactivity into a build failure.
l = replace_once(
    l,
    'static void igmm_probe_target(id o){',
    'static void __attribute__((unused)) igmm_probe_target(id o){',
    'mark inactive historical deep probe unused',
)

# Add the semantic predicate declaration next to the profiler bridge.
l = replace_once(
    l,
    'extern void HFAJailpatchProfileTarget(id,const char*);\n',
    'extern void HFAJailpatchProfileTarget(id,const char*);\nextern int HFAJailpatchTargetHasFeatures(id);\n',
    'declare semantic target predicate',
)

# Replace the old "probe every custom target" Full Scan behavior. The modern
# profiler still runs first and captures runtime records. After that, if the
# object has a semantic feature array, preserve the iGMM registration when its
# stricter {label,identifier,type} array is available, mark the menu found, and
# stop traversal. Random custom control/window targets are no longer deep-probed.
old_auto = r'''static void auto_target(id o){
    HFAGenericMenuObserveObject(o,"auto-target");
    HFAJailpatchProfileTarget(o,"auto-target");
    if(!o||o==gTarget||auto_seen(o)||gAutoTargetCount>=256)return;
    @try {
        Class c=M0(Class,o,"class");const char*cn=c?class_getName(c):"?";
        if(customcn(cn))igmm_probe_target(o);
        if(!customcn(cn)||strstr(cn,".")||!resp(o,"_ivarDescription"))return;
'''
new_auto = r'''static void auto_target(id o){
    HFAGenericMenuObserveObject(o,"auto-target");
    HFAJailpatchProfileTarget(o,"auto-target");
    int jailCandidate=HFAJailpatchTargetHasFeatures(o);
    if(!o||o==gTarget||auto_seen(o)||gAutoTargetCount>=256)return;
    @try {
        Class c=M0(Class,o,"class");const char*cn=c?class_getName(c):"?";
        if(customcn(cn)&&jailCandidate){
            unsigned int featureCount=0;const char*featureIvar=0;
            id featureArray=igmm_find_feature_array(o,&featureCount,&featureIvar);
            if(featureArray&&featureCount){
                HFARegisterIGMMFeatureArray(o,featureArray);
                logf("[AUTO-MENU-CANDIDATE] source=igmm-feature-array class=%s ptr=%p ivar=%s features=%u\\n",
                     cn,o,featureIvar?featureIvar:"?",featureCount);
            }else{
                logf("[AUTO-MENU-CANDIDATE] source=jailpatch-feature-array class=%s ptr=%p\\n",cn,o);
            }
            gAutoMenuFound=1;
            return;
        }
        if(!customcn(cn)||strstr(cn,".")||!resp(o,"_ivarDescription"))return;
'''
l = replace_once(l, old_auto, new_auto, 'replace unsafe full-scan target probing')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
