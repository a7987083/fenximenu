#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

extern const char *HFAAppLocalPrimaryImage(void);
extern const char *HFAAppLocalPrimaryFamily(void);
extern void HFAGenericMenuObserveObject(id object, const char *context);
extern void HFAGenericMenuObserveAction(id sender, id target, SEL action);
extern void HFAGenericMenuResetScanState(void);
extern void HFAJailpatchProfileTarget(id target, const char *context);
extern void HFAJailpatchResetProfilerState(void);
extern void HFAPatchTraceResetAnalysis(void);
extern void HFARegisterFeatureDefinition(const char *label, const char *identifier);
extern void HFARegisterIGMMFeatureArray(id menuTarget, id featureArray);
extern void HFACyberUIAppendLog(NSString *text);

static void HFAFamilyLog(NSString *line) {
    if (!line.length) return;
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
    fprintf(f, "%s\n", line.UTF8String ?: "[FAMILY]");
    fflush(f);
    fclose(f);
}

static const char *HFAFamilyBase(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static BOOL HFAFamilyClassBelongsToImage(Class cls, const char *image) {
    if (!cls || !image || !*image) return NO;
    const char *path = class_getImageName(cls);
    return path && strcmp(HFAFamilyBase(path), image) == 0;
}

static BOOL HFAFamilyHasSelector(Class cls, const char *name) {
    return cls && name && class_getInstanceMethod(cls, sel_registerName(name)) != NULL;
}

static BOOL HFAFamilyLooksLikeFeatureControl(Class cls) {
    if (!cls) return NO;
    return HFAFamilyHasSelector(cls, "identifier") &&
           HFAFamilyHasSelector(cls, "type") &&
           HFAFamilyHasSelector(cls, "currentState") &&
           HFAFamilyHasSelector(cls, "setCurrentState:");
}

static NSString *HFAFamilyStringGetter(id object, const char *selectorName) {
    if (!object || !selectorName) return nil;
    SEL sel = sel_registerName(selectorName);
    Method method = class_getInstanceMethod(object_getClass(object), sel);
    if (!method) return nil;
    char *ret = method_copyReturnType(method);
    BOOL objectReturn = ret && ret[0] == '@';
    if (ret) free(ret);
    if (!objectReturn) return nil;
    @try {
        id value = ((id (*)(id, SEL))objc_msgSend)(object, sel);
        return [value isKindOfClass:[NSString class]] ? value : nil;
    } @catch (__unused id exception) {
        return nil;
    }
}

static NSString *HFAFamilyLabel(id object) {
    static const char *selectors[] = {
        "label", "text", "currentTitle", "title", "accessibilityLabel"
    };
    for (unsigned i = 0; i < sizeof(selectors) / sizeof(selectors[0]); i++) {
        NSString *value = HFAFamilyStringGetter(object, selectors[i]);
        if (value.length) return value;
    }
    @try {
        if ([object respondsToSelector:@selector(titleLabel)]) {
            id titleLabel = ((id (*)(id, SEL))objc_msgSend)(object, @selector(titleLabel));
            NSString *value = HFAFamilyStringGetter(titleLabel, "text");
            if (value.length) return value;
        }
    } @catch (__unused id exception) {}
    return nil;
}

static BOOL HFAFamilyIGMMFeatureDictionary(id value) {
    if (![value isKindOfClass:[NSDictionary class]]) return NO;
    NSDictionary *dictionary = value;
    id label = dictionary[@"label"];
    id identifier = dictionary[@"identifier"];
    id type = dictionary[@"type"];
    return [label isKindOfClass:[NSString class]] && [(NSString *)label length] &&
           [identifier isKindOfClass:[NSString class]] && [(NSString *)identifier length] &&
           [type isKindOfClass:[NSString class]] && [(NSString *)type length];
}

static NSArray *HFAFamilyFindIGMMFeatureArray(id owner, NSString **ivarNameOut) {
    if (ivarNameOut) *ivarNameOut = nil;
    if (!owner) return nil;
    NSArray *best = nil;
    NSString *bestName = nil;
    for (Class cursor = object_getClass(owner); cursor && cursor != [NSObject class]; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        if (count > 96) count = 96;
        for (unsigned i = 0; ivars && i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type || type[0] != '@') continue;
            id value = nil;
            @try { value = object_getIvar(owner, ivars[i]); }
            @catch (__unused id exception) { value = nil; }
            if (![value isKindOfClass:[NSArray class]]) continue;
            NSArray *array = value;
            if (!array.count || array.count > 64) continue;
            NSUInteger valid = 0;
            for (id item in array) if (HFAFamilyIGMMFeatureDictionary(item)) valid++;
            if (valid != array.count) continue;
            if (!best || array.count > best.count) {
                best = array;
                bestName = [NSString stringWithUTF8String:ivar_getName(ivars[i]) ?: "?"];
            }
        }
        free(ivars);
    }
    if (ivarNameOut) *ivarNameOut = bestName;
    return best;
}

static void HFAFamilyClearCurrentOutputs(void) {
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSString *prefix = [NSString stringWithFormat:@"%@_%@_%@", safeID, shortVersion, buildVersion];
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSArray *suffixes = @[ @".hfapatch.json", @".hfamap.igmm.json", @".hfamap.analysis.json" ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *suffix in suffixes) {
        NSString *path = [docs stringByAppendingPathComponent:[prefix stringByAppendingString:suffix]];
        if ([fm fileExistsAtPath:path]) [fm removeItemAtPath:path error:nil];
    }
}

typedef struct {
    const char *image;
    const char *family;
    NSMutableSet<NSValue *> *seenTargets;
    unsigned controls;
    unsigned featureControls;
    unsigned actionTargets;
    unsigned actions;
    unsigned igmmArrays;
    unsigned legacyProfiles;
} HFAFamilyContext;

static BOOL HFAFamilyMarkTarget(HFAFamilyContext *context, id target) {
    if (!context || !target) return NO;
    NSValue *key = [NSValue valueWithPointer:(__bridge const void *)target];
    if ([context->seenTargets containsObject:key]) return NO;
    [context->seenTargets addObject:key];
    return YES;
}

static void HFAFamilyProfileOwner(HFAFamilyContext *context, id owner, const char *origin) {
    if (!context || !owner || !HFAFamilyMarkTarget(context, owner)) return;
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
}

static void HFAFamilyObserveActions(HFAFamilyContext *context, UIControl *control) {
    if (!context || !control) return;
    NSSet *targets = control.allTargets;
    UIControlEvents eventMask = control.allControlEvents;
    if (!eventMask) eventMask = UIControlEventAllEvents;
    for (id target in targets) {
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
}

static void HFAFamilyWalkView(HFAFamilyContext *context, UIView *view, unsigned depth) {
    if (!context || !view || depth > 32) return;
    if ([view isKindOfClass:[UIControl class]]) {
        context->controls++;
        Class cls = object_getClass(view);
        if (HFAFamilyClassBelongsToImage(cls, context->image) && HFAFamilyLooksLikeFeatureControl(cls)) {
            context->featureControls++;
            NSString *identifier = HFAFamilyStringGetter(view, "identifier");
            NSString *label = HFAFamilyLabel(view);
            if (identifier.length && label.length)
                HFARegisterFeatureDefinition(label.UTF8String, identifier.UTF8String);
            HFAGenericMenuObserveObject(view, "family-ui-control");
            HFAFamilyObserveActions(context, (UIControl *)view);
            HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-CONTROL] family=%s class=%s identifier=%@ label=%@",
                          context->family, class_getName(cls) ?: "?",
                          identifier ?: @"?", label ?: @"?"]);
        }
    }
    NSArray<UIView *> *subviews = view.subviews;
    NSUInteger count = MIN(subviews.count, (NSUInteger)512);
    for (NSUInteger i = 0; i < count; i++) HFAFamilyWalkView(context, subviews[i], depth + 1);
}

static void HFAFamilyWalkController(HFAFamilyContext *context, UIViewController *controller, unsigned depth) {
    if (!context || !controller || depth > 16) return;
    HFAFamilyProfileOwner(context, controller, "view-controller");
    if (controller.isViewLoaded && controller.view)
        HFAFamilyWalkView(context, controller.view, 0);
    NSArray<UIViewController *> *children = controller.childViewControllers;
    NSUInteger count = MIN(children.count, (NSUInteger)64);
    for (NSUInteger i = 0; i < count; i++)
        HFAFamilyWalkController(context, children[i], depth + 1);
    UIViewController *presented = controller.presentedViewController;
    if (presented) HFAFamilyWalkController(context, presented, depth + 1);
}

unsigned HFAFamilyResolveCurrentUI(void) {
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

        HFAPatchTraceResetAnalysis();
        HFAGenericMenuResetScanState();
        HFAJailpatchResetProfilerState();
        HFAFamilyClearCurrentOutputs();

        HFAFamilyContext context = {0};
        context.image = image;
        context.family = family;
        context.seenTargets = [NSMutableSet set];

        NSString *displayFamily = strcmp(family, "runtime-5m") == 0 ? @"5M 家族" : @"13M 家族";
        HFACyberUIAppendLog([NSString stringWithFormat:@"🔎 正在解析：%@ (%s)", displayFamily, image]);
        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-BEGIN] family=%s image=%s", family, image]);

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

        HFAFamilyLog([NSString stringWithFormat:@"[FAMILY-RESOLVE-END] family=%s image=%s windows=%lu controls=%u featureControls=%u targets=%u actions=%u igmmArrays=%u legacyProfiles=%u",
                      family, image, (unsigned long)windowCount, context.controls,
                      context.featureControls, context.actionTargets, context.actions,
                      context.igmmArrays, context.legacyProfiles]);
        HFACyberUIAppendLog([NSString stringWithFormat:@"✅ 扫描完成：菜单控件 %u，动作 %u",
                              context.featureControls, context.actions]);
        if (strcmp(family, "runtime-5m") == 0)
            HFACyberUIAppendLog([NSString stringWithFormat:@"📋 5M 菜单定义数组：%u", context.igmmArrays]);
        else
            HFACyberUIAppendLog([NSString stringWithFormat:@"🔑 13M 运行对象检查：%u", context.legacyProfiles]);
        return context.featureControls + context.igmmArrays;
    }
}
