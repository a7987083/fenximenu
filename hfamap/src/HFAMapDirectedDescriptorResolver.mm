#import "HFAMapDirectedDescriptorResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <stdint.h>
#include <string.h>

static const NSUInteger kHFADirectedMaxViews = 1024;
static const NSUInteger kHFADirectedMaxControls = 256;
static const NSUInteger kHFADirectedMaxSeeds = 384;
static const NSUInteger kHFADirectedMaxNodes = 1024;
static const NSUInteger kHFADirectedMaxDepth = 8;
static const NSUInteger kHFADirectedMaxFields = 8192;
static const NSUInteger kHFADirectedMaxContainerItems = 96;
static const NSUInteger kHFADirectedMaxFeatureKeys = 32;

static NSString *HFAImageForClassDD(Class cls) {
    const char *p = cls ? class_getImageName(cls) : NULL;
    return p ? [NSString stringWithUTF8String:p].lastPathComponent : @"";
}
static NSString *HFAImageForObjectDD(id object) {
    return object ? HFAImageForClassDD(object_getClass(object)) : @"";
}
static NSString *HFATokenDD(id object) {
    return object ? [NSString stringWithFormat:@"%p", object] : @"";
}
static NSString *HFANormalizedKeyDD(NSString *s) {
    if (![s isKindOfClass:NSString.class] || !s.length) return @"";
    NSMutableString *m = [NSMutableString string];
    NSString *l = s.lowercaseString;
    for (NSUInteger i = 0; i < l.length; ++i) {
        unichar c = [l characterAtIndex:i];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) [m appendFormat:@"%C", c];
    }
    return m;
}
static NSString *HFARoleDD(NSString *name) {
    NSString *l = name.lowercaseString;
    if ([l containsString:@"offset"] || [l containsString:@"rva"] || [l containsString:@"address"]) return @"address-field";
    if ([l containsString:@"patch"] || [l containsString:@"bytes"] || [l containsString:@"data"] || [l containsString:@"original"] || [l containsString:@"replace"]) return @"patch-field";
    if ([l containsString:@"image"] || [l containsString:@"library"] || [l containsString:@"module"] || [l containsString:@"macho"] || [l containsString:@"path"] || [l containsString:@"target"]) return @"target-image-field";
    if ([l containsString:@"feature"] || [l containsString:@"title"] || [l containsString:@"label"] || [l containsString:@"identifier"] || [l containsString:@"name"]) return @"feature-field";
    if ([l containsString:@"signature"]) return @"signature-field";
    if ([l containsString:@"manager"] || [l containsString:@"subpatch"]) return @"manager-field";
    return @"field";
}
static NSString *HFABackingIvarDD(objc_property_t p) {
    const char *attrs = property_getAttributes(p);
    if (!attrs) return nil;
    for (NSString *piece in [[NSString stringWithUTF8String:attrs] componentsSeparatedByString:@","])
        if ([piece hasPrefix:@"V"] && piece.length > 1) return [piece substringFromIndex:1];
    return nil;
}
static NSString *HFALabelDD(UIControl *control) {
    if ([control isKindOfClass:UIButton.class]) {
        NSString *title = [(UIButton *)control titleForState:UIControlStateNormal];
        if (title.length) return title;
    }
    if (control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope = control;
    for (NSUInteger depth = 0; scope && depth < 3; ++depth, scope = scope.superview) {
        NSMutableArray *q = [NSMutableArray arrayWithObject:scope];
        for (NSUInteger i = 0; i < q.count && i < 32; ++i) {
            UIView *v = q[i];
            if ([v isKindOfClass:UILabel.class] && [(UILabel *)v text].length) return [(UILabel *)v text];
            for (UIView *child in v.subviews) if (q.count < 32) [q addObject:child];
        }
    }
    return @"";
}
static BOOL HFAContainerDD(id object) {
    return [object isKindOfClass:NSArray.class] || [object isKindOfClass:NSDictionary.class] || [object isKindOfClass:NSSet.class];
}
static NSArray *HFAContainerChildrenDD(id object) {
    NSMutableArray *a = [NSMutableArray array];
    if ([object isKindOfClass:NSArray.class]) {
        NSArray *v = object;
        for (NSUInteger i = 0; i < MIN(v.count, kHFADirectedMaxContainerItems); ++i) if (v[i]) [a addObject:v[i]];
    } else if ([object isKindOfClass:NSDictionary.class]) {
        NSDictionary *d = object;
        NSUInteger n = 0;
        for (id key in d) {
            if (n++ >= kHFADirectedMaxContainerItems) break;
            id value = d[key];
            if (key) [a addObject:key];
            if (value) [a addObject:value];
        }
    } else if ([object isKindOfClass:NSSet.class]) {
        NSUInteger n = 0;
        for (id value in (NSSet *)object) {
            if (n++ >= kHFADirectedMaxContainerItems) break;
            if (value) [a addObject:value];
        }
    }
    return a;
}

static void HFAAddKeyDD(NSMutableArray *keys, NSString *value, NSString *source, NSString *ownerToken) {
    if (![value isKindOfClass:NSString.class] || !value.length || keys.count >= kHFADirectedMaxFeatureKeys) return;
    NSString *normalized = HFANormalizedKeyDD(value);
    if (!normalized.length) return;
    for (NSDictionary *existing in keys)
        if ([existing[@"normalized"] isEqualToString:normalized]) return;
    [keys addObject:@{ @"value": value, @"normalized": normalized, @"source": source ?: @"", @"ownerToken": ownerToken ?: @"" }];
}

static NSArray *HFAObjectFieldsDD(id object, NSString *menuImage, NSMutableArray *children,
                                  NSMutableArray *strings, NSUInteger *fieldBudget) {
    NSMutableArray *fields = [NSMutableArray array];
    NSMutableSet *seenOffsets = [NSMutableSet set];
    NSUInteger classDepth = 0;
    for (Class cls = object_getClass(object); cls && classDepth < 10 && *fieldBudget;
         cls = class_getSuperclass(cls), ++classDepth) {
        if (![HFAImageForClassDD(cls) isEqualToString:menuImage]) continue;
        unsigned ic = 0;
        Ivar *ivars = class_copyIvarList(cls, &ic);
        for (unsigned i = 0; ivars && i < ic && *fieldBudget; ++i) {
            Ivar iv = ivars[i];
            const char *type = ivar_getTypeEncoding(iv);
            if (!type || type[0] != '@') continue;
            ptrdiff_t off = ivar_getOffset(iv);
            NSString *offsetKey = [NSString stringWithFormat:@"%@:%td", NSStringFromClass(cls), off];
            if ([seenOffsets containsObject:offsetKey]) continue;
            [seenOffsets addObject:offsetKey];
            --(*fieldBudget);
            NSString *name = ivar_getName(iv) ? [NSString stringWithUTF8String:ivar_getName(iv)] : @"";
            id value = object_getIvar(object, iv);
            NSMutableDictionary *f = [@{
                @"source": @"ivar", @"name": name ?: @"", @"role": HFARoleDD(name ?: @""),
                @"ownerClass": NSStringFromClass(cls) ?: @"", @"offset": @(off),
                @"offsetHex": off >= 0 ? [NSString stringWithFormat:@"0x%tx", off] : @"",
                @"valueClass": value ? NSStringFromClass(object_getClass(value)) ?: @"" : @"",
                @"valueImage": value ? HFAImageForObjectDD(value) : @"", @"valueToken": value ? HFATokenDD(value) : @""
            } mutableCopy];
            if ([value isKindOfClass:NSString.class]) { f[@"string"] = value; [strings addObject:value]; }
            else if ([value isKindOfClass:NSNumber.class]) f[@"number"] = value;
            if (value) [children addObject:value];
            [fields addObject:f]; [f release];
        }
        if (ivars) free(ivars);

        unsigned pc = 0;
        objc_property_t *props = class_copyPropertyList(cls, &pc);
        for (unsigned i = 0; props && i < pc && *fieldBudget; ++i) {
            const char *pnC = property_getName(props[i]);
            NSString *pn = pnC ? [NSString stringWithUTF8String:pnC] : @"";
            NSString *back = HFABackingIvarDD(props[i]);
            if (!back.length) continue;
            Ivar iv = class_getInstanceVariable(cls, back.UTF8String);
            if (!iv) continue;
            const char *type = ivar_getTypeEncoding(iv);
            if (!type || type[0] != '@') continue;
            --(*fieldBudget);
            id value = object_getIvar(object, iv);
            NSMutableDictionary *f = [@{
                @"source": @"property-backing-ivar", @"name": pn ?: @"", @"backingIvar": back,
                @"role": HFARoleDD(pn ?: @""), @"ownerClass": NSStringFromClass(cls) ?: @"",
                @"offset": @(ivar_getOffset(iv)),
                @"valueClass": value ? NSStringFromClass(object_getClass(value)) ?: @"" : @"",
                @"valueImage": value ? HFAImageForObjectDD(value) : @"", @"valueToken": value ? HFATokenDD(value) : @""
            } mutableCopy];
            if ([value isKindOfClass:NSString.class]) { f[@"string"] = value; [strings addObject:value]; }
            else if ([value isKindOfClass:NSNumber.class]) f[@"number"] = value;
            if (value) [children addObject:value];
            [fields addObject:f]; [f release];
        }
        if (props) free(props);
    }
    return fields;
}

static NSDictionary *HFADescriptorShapeDD(NSArray *fields) {
    NSMutableSet *roles = [NSMutableSet set];
    NSMutableArray *roleObjects = [NSMutableArray array];
    for (NSDictionary *f in fields) {
        NSString *role = f[@"role"];
        if (role.length && ![role isEqualToString:@"field"]) [roles addObject:role];
        if (![role isEqualToString:@"field"] && [f[@"valueToken"] length])
            [roleObjects addObject:@{ @"role": role, @"field": f[@"name"] ?: @"", @"valueToken": f[@"valueToken"],
                                      @"valueClass": f[@"valueClass"] ?: @"", @"valueImage": f[@"valueImage"] ?: @"" }];
    }
    BOOL feature = [roles containsObject:@"feature-field"];
    BOOL address = [roles containsObject:@"address-field"];
    BOOL patch = [roles containsObject:@"patch-field"];
    BOOL target = [roles containsObject:@"target-image-field"];
    BOOL signature = [roles containsObject:@"signature-field"];
    BOOL manager = [roles containsObject:@"manager-field"];
    BOOL candidate = (address && target) || (address && patch) || (feature && address) ||
                     (target && patch) || ((address || patch) && (signature || manager));
    if (!candidate) return nil;
    return @{
        @"classification": (address && patch) ? @"patch-descriptor-candidate" : @"descriptor-candidate",
        @"roles": [[roles allObjects] sortedArrayUsingSelector:@selector(compare:)],
        @"roleObjects": roleObjects,
        @"verified": @NO, @"canonicalEligible": @NO,
        @"reason": @"runtime-object-shape-only"
    };
}

static BOOL HFAMatchNormalizedDD(NSString *a, NSString *b) {
    if (!a.length || !b.length) return NO;
    if ([a isEqualToString:b]) return YES;
    if (a.length >= 3 && b.length >= 3 && ([a hasPrefix:b] || [b hasPrefix:a])) return YES;
    return NO;
}

static NSDictionary *HFAResolveOnMainDD(NSString *path, NSDictionary *rootGraph, NSError **error) {
    NSString *menuImage = path.lastPathComponent ?: @"";
    if (!menuImage.length) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.directed-descriptor" code:1
                                             userInfo:@{NSLocalizedDescriptionKey:@"missing-menu-image"}];
        return nil;
    }

    NSMutableArray *viewQueue = [NSMutableArray array];
    for (UIWindow *w in UIApplication.sharedApplication.windows) if (w) [viewQueue addObject:w];
    NSHashTable *seenViews = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSHashTable *seedSeen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *seedObjects = [NSMutableArray array];
    NSMutableArray *features = [NSMutableArray array];
    NSUInteger controls = 0;

    for (NSUInteger index = 0; index < viewQueue.count && index < kHFADirectedMaxViews; ++index) {
        UIView *view = viewQueue[index];
        if ([seenViews containsObject:view]) continue;
        [seenViews addObject:view];
        for (UIView *child in view.subviews) if (viewQueue.count < kHFADirectedMaxViews) [viewQueue addObject:child];
        if ([HFAImageForObjectDD(view) isEqualToString:menuImage] && seedObjects.count < kHFADirectedMaxSeeds && ![seedSeen containsObject:view]) {
            [seedSeen addObject:view]; [seedObjects addObject:view];
        }
        if (![view isKindOfClass:UIControl.class] || controls >= kHFADirectedMaxControls) continue;
        ++controls;
        UIControl *control = (UIControl *)view;
        NSMutableArray *targets = [NSMutableArray array];
        for (id target in control.allTargets) {
            if (![HFAImageForObjectDD(target) isEqualToString:menuImage]) continue;
            [targets addObject:@{ @"targetToken": HFATokenDD(target), @"targetClass": NSStringFromClass(object_getClass(target)) ?: @"" }];
            if (seedObjects.count < kHFADirectedMaxSeeds && ![seedSeen containsObject:target]) { [seedSeen addObject:target]; [seedObjects addObject:target]; }
        }
        if (!targets.count) continue;
        if (seedObjects.count < kHFADirectedMaxSeeds && ![seedSeen containsObject:control]) { [seedSeen addObject:control]; [seedObjects addObject:control]; }
        UIView *superview = control.superview;
        for (NSUInteger d = 0; superview && d < 4 && seedObjects.count < kHFADirectedMaxSeeds; ++d, superview = superview.superview)
            if ([HFAImageForObjectDD(superview) isEqualToString:menuImage] && ![seedSeen containsObject:superview]) { [seedSeen addObject:superview]; [seedObjects addObject:superview]; }
        [features addObject:@{ @"label": HFALabelDD(control), @"controlToken": HFATokenDD(control),
                               @"controlClass": NSStringFromClass(object_getClass(control)) ?: @"",
                               @"targets": targets }];
    }

    NSMutableArray *queue = [NSMutableArray array];
    for (id seed in seedObjects) [queue addObject:@{ @"object": seed, @"depth": @0, @"parent": @"" }];
    NSHashTable *seen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *nodes = [NSMutableArray array];
    NSMutableArray *descriptors = [NSMutableArray array];
    NSMutableDictionary *nodeByToken = [NSMutableDictionary dictionary];
    NSUInteger fieldBudget = kHFADirectedMaxFields;

    for (NSUInteger index = 0; index < queue.count && nodes.count < kHFADirectedMaxNodes; ++index) {
        NSDictionary *entry = queue[index];
        id object = entry[@"object"];
        NSUInteger depth = [entry[@"depth"] unsignedIntegerValue];
        if (!object || [seen containsObject:object]) continue;
        [seen addObject:object];
        NSString *image = HFAImageForObjectDD(object);
        BOOL menuOwned = [image isEqualToString:menuImage];
        BOOL container = HFAContainerDD(object);
        if (!menuOwned && !container) continue;

        NSMutableArray *children = [NSMutableArray array];
        NSMutableArray *strings = [NSMutableArray array];
        NSArray *fields = menuOwned ? HFAObjectFieldsDD(object, menuImage, children, strings, &fieldBudget) : @[];
        if (container) [children addObjectsFromArray:HFAContainerChildrenDD(object)];
        NSString *token = HFATokenDD(object);
        NSMutableDictionary *node = [@{
            @"token": token, @"class": NSStringFromClass(object_getClass(object)) ?: @"",
            @"classImage": image ?: @"", @"depth": @(depth), @"parentToken": entry[@"parent"] ?: @"",
            @"menuOwned": @(menuOwned), @"foundationContainer": @(container), @"fields": fields,
            @"stringValues": strings
        } mutableCopy];
        NSDictionary *shape = menuOwned ? HFADescriptorShapeDD(fields) : nil;
        if (shape) {
            node[@"descriptorShape"] = shape;
            NSMutableArray *ids = [NSMutableArray array];
            for (NSDictionary *f in fields) {
                if ([f[@"role"] isEqualToString:@"feature-field"] && [f[@"string"] length])
                    [ids addObject:f[@"string"]];
            }
            NSDictionary *d = @{ @"token": token, @"class": node[@"class"], @"roles": shape[@"roles"],
                                   @"identifierStrings": ids, @"fields": fields, @"verified": @NO,
                                   @"canonicalEligible": @NO };
            [descriptors addObject:d];
        }
        [nodes addObject:node]; nodeByToken[token] = node; [node release];

        if (depth >= kHFADirectedMaxDepth) continue;
        for (id child in children) {
            if (!child || [seen containsObject:child] || queue.count >= kHFADirectedMaxNodes * 2) continue;
            NSString *ci = HFAImageForObjectDD(child);
            if ([ci isEqualToString:menuImage] || HFAContainerDD(child))
                [queue addObject:@{ @"object": child, @"depth": @(depth + 1), @"parent": token }];
        }
    }

    NSMutableArray *featureResolutions = [NSMutableArray array];
    for (NSDictionary *feature in features) {
        NSMutableArray *keys = [NSMutableArray array];
        HFAAddKeyDD(keys, feature[@"label"], @"ui-label", feature[@"controlToken"]);
        NSDictionary *controlNode = nodeByToken[feature[@"controlToken"]];
        for (NSString *s in controlNode[@"stringValues"] ?: @[]) HFAAddKeyDD(keys, s, @"control-object-string", feature[@"controlToken"]);
        for (NSDictionary *target in feature[@"targets"] ?: @[]) {
            NSDictionary *targetNode = nodeByToken[target[@"targetToken"]];
            for (NSString *s in targetNode[@"stringValues"] ?: @[]) HFAAddKeyDD(keys, s, @"target-object-string", target[@"targetToken"]);
        }
        NSMutableArray *matches = [NSMutableArray array];
        for (NSDictionary *descriptor in descriptors) {
            NSMutableArray *why = [NSMutableArray array];
            for (NSString *candidate in descriptor[@"identifierStrings"] ?: @[]) {
                NSString *cn = HFANormalizedKeyDD(candidate);
                for (NSDictionary *key in keys) {
                    if (HFAMatchNormalizedDD(cn, key[@"normalized"]))
                        [why addObject:@{ @"descriptorValue": candidate, @"featureValue": key[@"value"],
                                          @"featureSource": key[@"source"], @"match": [cn isEqualToString:key[@"normalized"]] ? @"exact-normalized" : @"prefix-normalized" }];
                }
            }
            if (why.count) [matches addObject:@{ @"descriptorToken": descriptor[@"token"], @"descriptorClass": descriptor[@"class"],
                                                  @"roles": descriptor[@"roles"], @"matches": why, @"verified": @NO,
                                                  @"canonicalEligible": @NO }];
        }
        [featureResolutions addObject:@{
            @"label": feature[@"label"] ?: @"", @"controlToken": feature[@"controlToken"] ?: @"",
            @"controlClass": feature[@"controlClass"] ?: @"", @"targets": feature[@"targets"] ?: @[],
            @"featureKeys": keys, @"descriptorMatches": matches, @"descriptorMatchCount": @(matches.count),
            @"status": matches.count ? @"runtime-descriptor-correlated" : @"runtime-entry-only"
        }];
    }

    NSDictionary *result = @{
        @"schema": @"com.hfa.directed-descriptor/v1",
        @"buildVersion": @"2.5.10-dev",
        @"componentVersion": @"2.5.10-dev-directed-descriptor-resolution",
        @"policy": @"UNIVERSAL-DIRECTED-READ-ONLY-NO-SAMPLE-SPECIAL-CASES",
        @"menuImage": menuImage, @"menuPath": path ?: @"",
        @"ui": @{ @"viewCount": @(seenViews.count), @"controlCount": @(controls), @"featureCount": @(features.count) },
        @"featureResolutions": featureResolutions,
        @"graph": @{ @"seedCount": @(seedObjects.count), @"nodeCount": @(nodes.count), @"nodes": nodes,
                      @"descriptorCandidateCount": @(descriptors.count), @"descriptorCandidates": descriptors,
                      @"fieldBudgetRemaining": @(fieldBudget),
                      @"truncated": @(nodes.count >= kHFADirectedMaxNodes || fieldBudget == 0) },
        @"upstreamRuntimeRootGraphSummary": @{ @"rootCount": rootGraph[@"graph"][@"rootCount"] ?: @0,
                                                @"nodeCount": rootGraph[@"graph"][@"nodeCount"] ?: @0,
                                                @"descriptorCandidateCount": rootGraph[@"graph"][@"descriptorCandidateCount"] ?: @0 },
        @"safety": @{ @"unknownSelectorInvoked": @NO, @"impReplaced": @NO, @"inlineHookInstalled": @NO,
                       @"memoryWritten": @NO, @"gameStateWritten": @NO, @"objectGraphReadOnly": @YES }
    };
    HFADiagnosticsLog(@"directed-descriptor", @"complete", @{
        @"menuImage": menuImage, @"featureCount": @(features.count), @"seedCount": @(seedObjects.count),
        @"nodeCount": @(nodes.count), @"descriptorCandidateCount": @(descriptors.count)
    });
    return result;
}

NSDictionary *HFAMapResolveDirectedDescriptors(NSString *loadedMenuPath, NSDictionary *rootGraph, NSError **error) {
    if (NSThread.isMainThread) return HFAResolveOnMainDD(loadedMenuPath, rootGraph ?: @{}, error);
    __block NSDictionary *result = nil; __block NSError *inner = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{ result = [HFAResolveOnMainDD(loadedMenuPath, rootGraph ?: @{}, &inner) retain]; });
    if (error && inner) *error = inner;
    return [result autorelease];
}

BOOL HFAMapPersistDirectedDescriptors(NSDictionary *result, NSError **error) {
    if (!result) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"DirectedDescriptors.json")];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}
