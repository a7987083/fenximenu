#import "HFAMapLoadedMenuFeatureEnumerator.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

static const NSUInteger kHFAEnumMaxViews = 1536;
static const NSUInteger kHFAEnumMaxControls = 384;
static const NSUInteger kHFAEnumMaxObjectFields = 96;
static const NSUInteger kHFAEnumMaxMethodsPerClass = 64;
static const NSUInteger kHFAEnumMaxClassDepth = 8;
static const NSUInteger kHFAEnumMaxGraphNodes = 768;
static const NSUInteger kHFAEnumMaxGraphDepth = 6;
static const NSUInteger kHFAEnumMaxContainerItems = 64;

static NSString *HFAEnumImageForClass(Class cls) {
    const char *path = cls ? class_getImageName(cls) : NULL;
    return path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
}
static NSString *HFAEnumImageForObject(id object) {
    return object ? HFAEnumImageForClass(object_getClass(object)) : @"";
}
static NSString *HFAEnumToken(id object) {
    return object ? [NSString stringWithFormat:@"%p", object] : @"";
}
static NSString *HFAEnumNormalized(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return @"";
    NSMutableString *out = [NSMutableString string];
    NSString *lower = value.lowercaseString;
    for (NSUInteger i = 0; i < lower.length; ++i) {
        unichar c = [lower characterAtIndex:i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) [out appendFormat:@"%C", c];
    }
    return out;
}
static NSString *HFAEnumRoleForName(NSString *name) {
    NSString *l = name.lowercaseString;
    if ([l containsString:@"offset"] || [l containsString:@"address"] || [l containsString:@"rva"]) return @"address";
    if ([l containsString:@"patch"] || [l containsString:@"replace"] || [l containsString:@"original"] || [l containsString:@"bytes"] || [l containsString:@"data"]) return @"patch-data";
    if ([l containsString:@"manager"] || [l containsString:@"subpatch"]) return @"manager";
    if ([l containsString:@"callback"] || [l containsString:@"action"] || [l containsString:@"handler"] || [l containsString:@"block"]) return @"callback";
    if ([l containsString:@"identifier"] || [l containsString:@"title"] || [l containsString:@"label"] || [l containsString:@"name"] || [l containsString:@"feature"]) return @"feature-key";
    if ([l containsString:@"path"] || [l containsString:@"image"] || [l containsString:@"module"] || [l containsString:@"macho"] || [l containsString:@"target"]) return @"target-image";
    if ([l containsString:@"value"] || [l containsString:@"multiplier"] || [l containsString:@"amount"] || [l containsString:@"scale"]) return @"runtime-value";
    return @"field";
}
static BOOL HFAEnumIsContainer(id object) {
    return [object isKindOfClass:NSArray.class] || [object isKindOfClass:NSDictionary.class] || [object isKindOfClass:NSSet.class];
}
static NSArray *HFAEnumContainerChildren(id object) {
    NSMutableArray *out = [NSMutableArray array];
    if ([object isKindOfClass:NSArray.class]) {
        NSArray *a = object;
        for (NSUInteger i = 0; i < MIN(a.count, kHFAEnumMaxContainerItems); ++i) if (a[i]) [out addObject:a[i]];
    } else if ([object isKindOfClass:NSDictionary.class]) {
        NSUInteger n = 0;
        for (id key in (NSDictionary *)object) {
            if (n++ >= kHFAEnumMaxContainerItems) break;
            id value = [(NSDictionary *)object objectForKey:key];
            if (key) [out addObject:key];
            if (value) [out addObject:value];
        }
    } else if ([object isKindOfClass:NSSet.class]) {
        NSUInteger n = 0;
        for (id value in (NSSet *)object) {
            if (n++ >= kHFAEnumMaxContainerItems) break;
            if (value) [out addObject:value];
        }
    }
    return out;
}
static NSString *HFAEnumLabelForControl(UIControl *control) {
    if ([control isKindOfClass:UIButton.class]) {
        NSString *title = [(UIButton *)control titleForState:UIControlStateNormal];
        if (title.length) return title;
    }
    if (control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope = control;
    for (NSUInteger depth = 0; scope && depth < 4; ++depth, scope = scope.superview) {
        NSMutableArray *queue = [NSMutableArray arrayWithObject:scope];
        for (NSUInteger i = 0; i < queue.count && i < 48; ++i) {
            UIView *view = queue[i];
            if ([view isKindOfClass:UILabel.class] && [(UILabel *)view text].length) return [(UILabel *)view text];
            for (UIView *child in view.subviews) if (queue.count < 48) [queue addObject:child];
        }
    }
    return @"";
}

static NSDictionary *HFAEnumAddressContext(const void *pointer) {
    if (!pointer) return @{};
    Dl_info info = {};
    if (!dladdr(pointer, &info) || !info.dli_fbase || !info.dli_fname) return @{};
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    return @{ @"runtimeVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)pointer],
              @"image": path.lastPathComponent ?: @"", @"path": path ?: @"",
              @"offsetFromLoadBase": [NSString stringWithFormat:@"0x%llX", (unsigned long long)((uintptr_t)pointer - (uintptr_t)info.dli_fbase)],
              @"semantics": @"runtime-va-minus-loaded-image-base" };
}

static BOOL HFAEnumBlockLike(id object) {
    if (!object) return NO;
    for (Class cls = object_getClass(object); cls; cls = class_getSuperclass(cls)) {
        NSString *name = NSStringFromClass(cls) ?: @"";
        if ([name rangeOfString:@"Block" options:NSCaseInsensitiveSearch].location != NSNotFound) return YES;
    }
    return NO;
}
static NSDictionary *HFAEnumBlockEvidence(id blockObject) {
    if (!HFAEnumBlockLike(blockObject)) return nil;
    struct Layout { uintptr_t isa; uint32_t flags; uint32_t reserved; uintptr_t invoke; uintptr_t descriptor; } layout = {};
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)(uintptr_t)(__bridge const void *)blockObject,
                                         sizeof(layout), (vm_address_t)&layout, &copied);
    if (kr != KERN_SUCCESS || copied != sizeof(layout) || !layout.invoke) return nil;
    return @{ @"token": HFAEnumToken(blockObject), @"class": NSStringFromClass(object_getClass(blockObject)) ?: @"",
              @"flags": [NSString stringWithFormat:@"0x%08X", layout.flags],
              @"invoke": HFAEnumAddressContext((const void *)layout.invoke),
              @"descriptorPointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)layout.descriptor],
              @"invokedByAnalyzer": @NO, @"analysisOnly": @YES };
}

static NSArray *HFAEnumMethodFingerprint(Class runtimeClass, NSString *menuImage) {
    NSMutableArray *classes = [NSMutableArray array];
    NSUInteger depth = 0;
    for (Class cls = runtimeClass; cls && depth < kHFAEnumMaxClassDepth; cls = class_getSuperclass(cls), ++depth) {
        NSString *image = HFAEnumImageForClass(cls);
        if (![image isEqualToString:menuImage]) continue;
        NSMutableArray *methods = [NSMutableArray array];
        unsigned count = 0;
        Method *list = class_copyMethodList(cls, &count);
        for (unsigned i = 0; list && i < count && methods.count < kHFAEnumMaxMethodsPerClass; ++i) {
            Method m = list[i];
            SEL sel = method_getName(m);
            IMP imp = method_getImplementation(m);
            const char *types = method_getTypeEncoding(m);
            [methods addObject:@{ @"selector": sel ? NSStringFromSelector(sel) : @"",
                                  @"typeEncoding": types ? [NSString stringWithUTF8String:types] : @"",
                                  @"implementation": HFAEnumAddressContext((const void *)imp) }];
        }
        if (list) free(list);
        [classes addObject:@{ @"class": NSStringFromClass(cls) ?: @"", @"image": image ?: @"", @"methods": methods }];
    }
    return classes;
}

static NSArray *HFAEnumObjectEvidence(id object, NSString *menuImage, NSMutableArray *children,
                                      NSMutableArray *strings, NSMutableArray *blocks) {
    if (!object) return @[];
    NSMutableArray *fields = [NSMutableArray array];
    NSUInteger fieldCount = 0;
    NSUInteger depth = 0;
    for (Class cls = object_getClass(object); cls && depth < kHFAEnumMaxClassDepth && fieldCount < kHFAEnumMaxObjectFields;
         cls = class_getSuperclass(cls), ++depth) {
        if (![HFAEnumImageForClass(cls) isEqualToString:menuImage]) continue;
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cls, &count);
        for (unsigned i = 0; ivars && i < count && fieldCount < kHFAEnumMaxObjectFields; ++i) {
            Ivar iv = ivars[i];
            const char *type = ivar_getTypeEncoding(iv);
            if (!type || type[0] != '@') continue;
            id value = object_getIvar(object, iv);
            NSString *name = ivar_getName(iv) ? [NSString stringWithUTF8String:ivar_getName(iv)] : @"";
            NSString *role = HFAEnumRoleForName(name);
            NSMutableDictionary *field = [@{ @"name": name ?: @"", @"role": role,
                                               @"ownerClass": NSStringFromClass(cls) ?: @"",
                                               @"offset": [NSString stringWithFormat:@"0x%tx", ivar_getOffset(iv)],
                                               @"valueToken": value ? HFAEnumToken(value) : @"",
                                               @"valueClass": value ? NSStringFromClass(object_getClass(value)) ?: @"" : @"",
                                               @"valueImage": value ? HFAEnumImageForObject(value) : @"" } mutableCopy];
            if ([value isKindOfClass:NSString.class]) { field[@"string"] = value; if (![strings containsObject:value]) [strings addObject:value]; }
            if (value) {
                [children addObject:value];
                NSDictionary *block = HFAEnumBlockEvidence(value);
                if (block) { field[@"blockEvidence"] = block; [blocks addObject:block]; }
            }
            [fields addObject:field]; [field release]; ++fieldCount;
        }
        if (ivars) free(ivars);
    }
    return fields;
}

static NSArray *HFAEnumActions(UIControl *control, NSString *menuImage, NSMutableArray *targetObjects) {
    NSMutableArray *out = [NSMutableArray array];
    NSArray *events = @[
        @{ @"name": @"touch-down", @"mask": @(UIControlEventTouchDown) },
        @{ @"name": @"touch-up-inside", @"mask": @(UIControlEventTouchUpInside) },
        @{ @"name": @"value-changed", @"mask": @(UIControlEventValueChanged) },
        @{ @"name": @"editing-changed", @"mask": @(UIControlEventEditingChanged) },
        @{ @"name": @"primary-action", @"mask": @(UIControlEventPrimaryActionTriggered) }
    ];
    for (id target in control.allTargets) {
        if (![HFAEnumImageForObject(target) isEqualToString:menuImage]) continue;
        [targetObjects addObject:target];
        for (NSDictionary *event in events) {
            UIControlEvents mask = (UIControlEvents)[event[@"mask"] unsignedLongLongValue];
            NSArray *actions = [control actionsForTarget:target forControlEvent:mask] ?: @[];
            for (NSString *action in actions) {
                SEL sel = action.length ? NSSelectorFromString(action) : NULL;
                Method method = sel ? class_getInstanceMethod(object_getClass(target), sel) : NULL;
                IMP imp = method ? method_getImplementation(method) : NULL;
                [out addObject:@{ @"targetToken": HFAEnumToken(target),
                                  @"targetClass": NSStringFromClass(object_getClass(target)) ?: @"",
                                  @"event": event[@"name"], @"selector": action ?: @"",
                                  @"implementation": HFAEnumAddressContext((const void *)imp),
                                  @"typeEncoding": method_getTypeEncoding(method) ? [NSString stringWithUTF8String:method_getTypeEncoding(method)] : @"" }];
            }
        }
    }
    return out;
}

static BOOL HFAEnumStatefulControl(UIControl *control, NSArray *actions) {
    if ([control isKindOfClass:UISwitch.class] || [control isKindOfClass:UISlider.class]) return YES;
    for (NSDictionary *action in actions)
        if ([action[@"event"] isEqualToString:@"value-changed"] || [action[@"event"] isEqualToString:@"editing-changed"]) return YES;
    if (![control isKindOfClass:UIButton.class] && control.allControlEvents != 0) return YES;
    return NO;
}

static NSDictionary *HFAEnumOnMain(NSString *path, NSDictionary *rootGraph, NSDictionary *directed, NSError **error) {
    NSString *menuImage = path.lastPathComponent ?: @"";
    if (!menuImage.length) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.loaded-menu-feature-enumerator" code:1 userInfo:@{NSLocalizedDescriptionKey:@"missing-menu-image"}];
        return nil;
    }
    NSMutableArray *viewQueue = [NSMutableArray array];
    for (UIWindow *window in UIApplication.sharedApplication.windows) if (window) [viewQueue addObject:window];
    NSHashTable *seenViews = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *controls = [NSMutableArray array];
    NSMutableArray *featureCandidates = [NSMutableArray array];
    NSMutableDictionary *dedup = [NSMutableDictionary dictionary];
    NSMutableArray *graphSeeds = [NSMutableArray array];
    NSHashTable *seedSeen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];

    for (NSUInteger index = 0; index < viewQueue.count && index < kHFAEnumMaxViews; ++index) {
        UIView *view = viewQueue[index];
        if ([seenViews containsObject:view]) continue;
        [seenViews addObject:view];
        for (UIView *child in view.subviews) if (viewQueue.count < kHFAEnumMaxViews) [viewQueue addObject:child];
        if (![view isKindOfClass:UIControl.class] || controls.count >= kHFAEnumMaxControls) continue;
        UIControl *control = (UIControl *)view;
        BOOL controlOwned = [HFAEnumImageForObject(control) isEqualToString:menuImage];
        NSMutableArray *targets = [NSMutableArray array];
        NSArray *actions = HFAEnumActions(control, menuImage, targets);
        if (!controlOwned && targets.count == 0) continue;
        NSString *label = HFAEnumLabelForControl(control);
        NSMutableArray *children = [NSMutableArray array];
        NSMutableArray *strings = [NSMutableArray array];
        NSMutableArray *blocks = [NSMutableArray array];
        NSArray *fields = controlOwned ? HFAEnumObjectEvidence(control, menuImage, children, strings, blocks) : @[];
        NSMutableArray *nearby = [NSMutableArray array];
        UIView *scope = control.superview;
        for (NSUInteger d = 0; scope && d < 3; ++d, scope = scope.superview) {
            if ([HFAEnumImageForObject(scope) isEqualToString:menuImage]) {
                NSMutableArray *sc = [NSMutableArray array], *ss = [NSMutableArray array], *sb = [NSMutableArray array];
                NSArray *sf = HFAEnumObjectEvidence(scope, menuImage, sc, ss, sb);
                [nearby addObject:@{ @"token": HFAEnumToken(scope), @"class": NSStringFromClass(object_getClass(scope)) ?: @"",
                                     @"strings": ss, @"fields": sf, @"blocks": sb }];
                [children addObjectsFromArray:sc]; [strings addObjectsFromArray:ss]; [blocks addObjectsFromArray:sb];
            }
        }
        for (id target in targets) {
            NSMutableArray *tc = [NSMutableArray array], *ts = [NSMutableArray array], *tb = [NSMutableArray array];
            HFAEnumObjectEvidence(target, menuImage, tc, ts, tb);
            [children addObjectsFromArray:tc]; [strings addObjectsFromArray:ts]; [blocks addObjectsFromArray:tb];
        }
        BOOL stateful = HFAEnumStatefulControl(control, actions);
        NSMutableDictionary *entry = [@{ @"label": label ?: @"", @"normalizedLabel": HFAEnumNormalized(label),
                                          @"controlToken": HFAEnumToken(control), @"controlClass": NSStringFromClass(object_getClass(control)) ?: @"",
                                          @"controlImage": HFAEnumImageForObject(control), @"menuOwnedControl": @(controlOwned),
                                          @"statefulFeatureCandidate": @(stateful), @"allControlEvents": [NSString stringWithFormat:@"0x%llX", (unsigned long long)control.allControlEvents],
                                          @"actions": actions, @"objectStrings": strings, @"objectFields": fields,
                                          @"nearbyMenuObjects": nearby, @"blockEvidence": blocks,
                                          @"classFingerprint": HFAEnumMethodFingerprint(object_getClass(control), menuImage),
                                          @"analysisOnly": @YES, @"canonicalEligible": @NO } mutableCopy];
        [controls addObject:entry];
        NSString *key = entry[@"normalizedLabel"];
        if (stateful && key.length) {
            NSMutableDictionary *existing = dedup[key];
            if (!existing) {
                existing = [@{ @"title": label, @"normalizedTitle": key, @"controls": [NSMutableArray array],
                                @"identifiers": [NSMutableArray array], @"mechanismEvidence": [NSMutableSet set],
                                @"analysisOnly": @YES, @"canonicalEligible": @NO } mutableCopy];
                dedup[key] = existing; [featureCandidates addObject:existing]; [existing release];
            }
            [(NSMutableArray *)existing[@"controls"] addObject:@{ @"token": entry[@"controlToken"], @"class": entry[@"controlClass"], @"actions": actions }];
            for (NSString *s in strings) {
                NSString *n = HFAEnumNormalized(s);
                if (n.length && ![n isEqualToString:key] && ![(NSMutableArray *)existing[@"identifiers"] containsObject:s]) [(NSMutableArray *)existing[@"identifiers"] addObject:s];
            }
            NSMutableSet *mechanisms = existing[@"mechanismEvidence"];
            if (actions.count) [mechanisms addObject:@"target-action"];
            if (blocks.count) [mechanisms addObject:@"block-callback"];
            for (NSDictionary *f in fields) {
                NSString *r = f[@"role"];
                if ([r isEqualToString:@"address"] || [r isEqualToString:@"patch-data"] || [r isEqualToString:@"manager"]) [mechanisms addObject:@"patch-or-manager-object"];
                if ([r isEqualToString:@"runtime-value"]) [mechanisms addObject:@"runtime-value"];
            }
        }
        if (![seedSeen containsObject:control]) { [seedSeen addObject:control]; [graphSeeds addObject:control]; }
        for (id target in targets) if (![seedSeen containsObject:target]) { [seedSeen addObject:target]; [graphSeeds addObject:target]; }
        [entry release];
    }

    NSMutableArray *queue = [NSMutableArray array];
    for (id seed in graphSeeds) [queue addObject:@{ @"object": seed, @"depth": @0, @"parent": @"" }];
    NSHashTable *seenObjects = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *graphNodes = [NSMutableArray array];
    NSMutableArray *managerCandidates = [NSMutableArray array];
    NSMutableArray *patchObjectCandidates = [NSMutableArray array];
    NSMutableArray *allBlocks = [NSMutableArray array];
    for (NSUInteger index = 0; index < queue.count && graphNodes.count < kHFAEnumMaxGraphNodes; ++index) {
        NSDictionary *q = queue[index]; id object = q[@"object"]; NSUInteger depth = [q[@"depth"] unsignedIntegerValue];
        if (!object || [seenObjects containsObject:object]) continue;
        [seenObjects addObject:object];
        NSString *image = HFAEnumImageForObject(object);
        BOOL owned = [image isEqualToString:menuImage]; BOOL container = HFAEnumIsContainer(object);
        if (!owned && !container) continue;
        NSMutableArray *children = [NSMutableArray array], *strings = [NSMutableArray array], *blocks = [NSMutableArray array];
        NSArray *fields = owned ? HFAEnumObjectEvidence(object, menuImage, children, strings, blocks) : @[];
        if (container) [children addObjectsFromArray:HFAEnumContainerChildren(object)];
        NSMutableSet *roles = [NSMutableSet set];
        for (NSDictionary *f in fields) if (![f[@"role"] isEqualToString:@"field"]) [roles addObject:f[@"role"]];
        BOOL manager = [roles containsObject:@"manager"];
        BOOL patchLike = ([roles containsObject:@"address"] && ([roles containsObject:@"patch-data"] || [roles containsObject:@"target-image"])) ||
                         ([roles containsObject:@"patch-data"] && [roles containsObject:@"manager"]);
        NSMutableDictionary *node = [@{ @"token": HFAEnumToken(object), @"class": NSStringFromClass(object_getClass(object)) ?: @"",
                                         @"image": image ?: @"", @"depth": @(depth), @"parentToken": q[@"parent"] ?: @"",
                                         @"strings": strings, @"fields": fields, @"roles": [[roles allObjects] sortedArrayUsingSelector:@selector(compare:)],
                                         @"blockEvidence": blocks } mutableCopy];
        if (owned) node[@"classFingerprint"] = HFAEnumMethodFingerprint(object_getClass(object), menuImage);
        [graphNodes addObject:node];
        NSDictionary *summary = @{ @"token": node[@"token"], @"class": node[@"class"], @"roles": node[@"roles"], @"strings": strings, @"fields": fields };
        if (manager) [managerCandidates addObject:summary];
        if (patchLike) [patchObjectCandidates addObject:summary];
        [allBlocks addObjectsFromArray:blocks];
        [node release];
        if (depth >= kHFAEnumMaxGraphDepth) continue;
        for (id child in children) {
            if (!child || [seenObjects containsObject:child] || queue.count >= kHFAEnumMaxGraphNodes * 2) continue;
            NSString *childImage = HFAEnumImageForObject(child);
            if ([childImage isEqualToString:menuImage] || HFAEnumIsContainer(child))
                [queue addObject:@{ @"object": child, @"depth": @(depth + 1), @"parent": HFAEnumToken(object) }];
        }
    }

    for (NSMutableDictionary *feature in featureCandidates) {
        NSMutableSet *m = feature[@"mechanismEvidence"];
        feature[@"mechanismEvidence"] = [[m allObjects] sortedArrayUsingSelector:@selector(compare:)];
        if ([feature[@"mechanismEvidence"] containsObject:@"patch-or-manager-object"]) feature[@"mechanismClass"] = @"patch-or-manager";
        else if ([feature[@"mechanismEvidence"] containsObject:@"block-callback"]) feature[@"mechanismClass"] = @"block-or-callback";
        else if ([feature[@"mechanismEvidence"] containsObject:@"runtime-value"]) feature[@"mechanismClass"] = @"runtime-value";
        else if ([feature[@"mechanismEvidence"] containsObject:@"target-action"]) feature[@"mechanismClass"] = @"target-action-unresolved";
        else feature[@"mechanismClass"] = @"ui-feature-only";
    }

    NSDictionary *result = @{
        @"schema": @"com.hfa.loaded-menu-feature-inventory/v1",
        @"buildVersion": @"2.5.13-dev",
        @"componentVersion": @"2.5.13-dev-reference-feature-enumerator",
        @"policy": @"REFERENCE-INSPIRED-READ-ONLY-UI-PATCH-BLOCK-MULTIPATH",
        @"menuImage": menuImage, @"menuPath": path ?: @"",
        @"summary": @{ @"viewCount": @(seenViews.count), @"controlCount": @(controls.count),
                        @"statefulFeatureCandidateCount": @(featureCandidates.count),
                        @"managerCandidateCount": @(managerCandidates.count),
                        @"patchObjectCandidateCount": @(patchObjectCandidates.count),
                        @"blockEvidenceCount": @(allBlocks.count) },
        @"featureCandidates": featureCandidates, @"controls": controls,
        @"managerCandidates": managerCandidates, @"patchObjectCandidates": patchObjectCandidates,
        @"blockEvidence": allBlocks, @"objectGraph": @{ @"nodeCount": @(graphNodes.count), @"nodes": graphNodes,
                                                          @"maxDepth": @(kHFAEnumMaxGraphDepth), @"truncated": @(graphNodes.count >= kHFAEnumMaxGraphNodes) },
        @"upstream": @{ @"runtimeRootNodeCount": rootGraph[@"graph"][@"nodeCount"] ?: @0,
                         @"directedFeatureCount": @([directed[@"featureResolutions"] count]),
                         @"directedDescriptorCandidateCount": directed[@"graph"][@"descriptorCandidateCount"] ?: @0 },
        @"referenceIntegration": @{ @"viewTreeInventory": @YES, @"targetActionInventory": @YES,
                                     @"objcSuperclassMethodFingerprint": @YES, @"blockInvokeInventory": @YES,
                                     @"managerPatchObjectShapeInventory": @YES,
                                     @"unknownSelectorInvocationRequired": @NO },
        @"safety": @{ @"unknownSelectorInvoked": @NO, @"blockInvoked": @NO, @"patchMethodInvoked": @NO,
                       @"impReplaced": @NO, @"inlineHookInstalled": @NO, @"memoryWritten": @NO,
                       @"objectGraphReadOnly": @YES }
    };
    HFADiagnosticsLog(@"loaded-menu-feature-enumerator", @"complete", @{
        @"menuImage": menuImage, @"controlCount": @(controls.count), @"featureCandidateCount": @(featureCandidates.count),
        @"managerCandidateCount": @(managerCandidates.count), @"patchObjectCandidateCount": @(patchObjectCandidates.count),
        @"blockEvidenceCount": @(allBlocks.count) });
    return result;
}

NSDictionary *HFAMapEnumerateLoadedMenuFeatures(NSString *loadedMenuPath, NSDictionary *rootGraph,
                                                NSDictionary *directed, NSError **error) {
    if (NSThread.isMainThread) return HFAEnumOnMain(loadedMenuPath, rootGraph ?: @{}, directed ?: @{}, error);
    __block NSDictionary *result = nil; __block NSError *inner = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{ result = [HFAEnumOnMain(loadedMenuPath, rootGraph ?: @{}, directed ?: @{}, &inner) retain]; });
    if (error && inner) *error = inner;
    return [result autorelease];
}

BOOL HFAMapPersistLoadedMenuFeatureInventory(NSDictionary *result, NSError **error) {
    if (!result) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"LoadedMenuFeatureInventory.json")];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}
