#import "HFAMapRuntimeProbe.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"
#import "HFAIL2CPPRuntimeProbe.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <math.h>
#include <string.h>

static const NSUInteger kHFAProbeMaxViews = 768;
static const NSUInteger kHFAProbeMaxControls = 128;
static const NSUInteger kHFAProbeMaxEvents = 32;
static const NSUInteger kHFAProbeMaxCallbacks = 256;
static const NSUInteger kHFAProbeMaxStateClasses = 8;
static const NSUInteger kHFAProbeMaxStateIvars = 32;
static const UIControlEvents kHFAProbeEvents = UIControlEventTouchUpInside |
                                                  UIControlEventValueChanged;

static BOOL gHFAProbeArmed;
static NSUInteger gHFAProbeGeneration;
static NSTimeInterval gHFAProbeStarted;
static NSString *gHFAProbeMenuImage;
static NSDictionary *gHFAProbeCandidate;
static NSMutableArray<UIControl *> *gHFAProbeControls;
static NSMutableArray<NSDictionary *> *gHFAProbeRecords;
static NSMutableDictionary<NSString *, NSNumber *> *gHFAProbeSliderRecordIndexes;
static NSMutableDictionary<NSString *, NSDictionary *> *gHFAProbeControlBaselines;
static NSUInteger gHFAProbeCallbackCount;
static void (^gHFAProbeCompletion)(NSDictionary *summary);

static NSString *HFAProbeImageForClass(Class cls) {
    if (!cls) return @"";
    const char *path = class_getImageName(cls);
    return path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
}

static BOOL HFAProbeStateLikeIvarName(NSString *name) {
    NSString *lower = name.lowercaseString;
    static NSArray<NSString *> *tokens;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        tokens = [[NSArray alloc] initWithObjects:@"state", @"selected", @"enabled", @"active",
                  @"checked", @"toggle", @"switch", @"value", @"progress", @"percent", nil];
    });
    if ([lower isEqualToString:@"on"] || [lower isEqualToString:@"_on"] ||
        [lower isEqualToString:@"ison"] || [lower isEqualToString:@"_ison"])
        return YES;
    for (NSString *token in tokens)
        if ([lower containsString:token]) return YES;
    return NO;
}

static const char *HFAProbeSkipTypeQualifiers(const char *encoding) {
    if (!encoding) return NULL;
    while (*encoding && strchr("rnNoORV", *encoding)) ++encoding;
    return encoding;
}

static NSNumber *HFAProbeReadScalarIvar(id object, Ivar ivar, NSString **kindOut) {
    const char *encoding = HFAProbeSkipTypeQualifiers(ivar_getTypeEncoding(ivar));
    if (!object || !ivar || !encoding || !*encoding) return nil;
    size_t width = 0;
    switch (*encoding) {
        case 'B': case 'c': case 'C': width = 1; break;
        case 's': case 'S': width = 2; break;
        case 'i': case 'I': case 'f': width = 4; break;
        case 'l': case 'L': width = sizeof(long); break;
        case 'q': case 'Q': case 'd': width = 8; break;
        default: return nil;
    }
    ptrdiff_t offset = ivar_getOffset(ivar);
    size_t objectSize = class_getInstanceSize(object_getClass(object));
    if (offset < 0 || width > 8 || (size_t)offset > objectSize || width > objectSize - (size_t)offset)
        return nil;
    uint8_t bytes[8] = {};
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
        (vm_address_t)((uintptr_t)(__bridge const void *)object + (uintptr_t)offset),
        (vm_size_t)width, (vm_address_t)bytes, &copied);
    if (kr != KERN_SUCCESS || copied != width) return nil;
    switch (*encoding) {
        case 'B': { bool value = false; memcpy(&value, bytes, 1); if (kindOut) *kindOut = @"bool"; return @(value); }
        case 'c': { int8_t value = 0; memcpy(&value, bytes, 1); if (kindOut) *kindOut = @"int8"; return @(value); }
        case 'C': { uint8_t value = 0; memcpy(&value, bytes, 1); if (kindOut) *kindOut = @"uint8"; return @(value); }
        case 's': { int16_t value = 0; memcpy(&value, bytes, 2); if (kindOut) *kindOut = @"int16"; return @(value); }
        case 'S': { uint16_t value = 0; memcpy(&value, bytes, 2); if (kindOut) *kindOut = @"uint16"; return @(value); }
        case 'i': { int32_t value = 0; memcpy(&value, bytes, 4); if (kindOut) *kindOut = @"int32"; return @(value); }
        case 'I': { uint32_t value = 0; memcpy(&value, bytes, 4); if (kindOut) *kindOut = @"uint32"; return @(value); }
        case 'l': { long value = 0; memcpy(&value, bytes, width); if (kindOut) *kindOut = @"long"; return @(value); }
        case 'L': { unsigned long value = 0; memcpy(&value, bytes, width); if (kindOut) *kindOut = @"ulong"; return @(value); }
        case 'q': { int64_t value = 0; memcpy(&value, bytes, 8); if (kindOut) *kindOut = @"int64"; return @(value); }
        case 'Q': { uint64_t value = 0; memcpy(&value, bytes, 8); if (kindOut) *kindOut = @"uint64"; return @(value); }
        case 'f': { float value = 0; memcpy(&value, bytes, 4); if (!isfinite(value)) return nil; if (kindOut) *kindOut = @"float"; return @(value); }
        case 'd': { double value = 0; memcpy(&value, bytes, 8); if (!isfinite(value)) return nil; if (kindOut) *kindOut = @"double"; return @(value); }
    }
    return nil;
}

static NSDictionary *HFAProbeStateSnapshot(UIControl *control) {
    NSMutableDictionary *publicState = [@{
        @"selected": @(control.selected), @"enabled": @(control.enabled),
        @"highlighted": @(control.highlighted)
    } mutableCopy];
    if ([control isKindOfClass:UISwitch.class]) publicState[@"switchOn"] = @([(UISwitch *)control isOn]);
    if ([control isKindOfClass:UISlider.class]) publicState[@"sliderValue"] = @([(UISlider *)control value]);
    NSMutableArray *ivars = [NSMutableArray array];
    NSMutableDictionary *valueMap = [NSMutableDictionary dictionary];
    for (NSString *key in publicState)
        valueMap[[@"public." stringByAppendingString:key]] = publicState[key];
    Class runtimeClass = object_getClass(control);
    NSUInteger inspectedClasses = 0;
    for (Class cls = runtimeClass; cls && inspectedClasses < kHFAProbeMaxStateClasses &&
         ivars.count < kHFAProbeMaxStateIvars; cls = class_getSuperclass(cls), ++inspectedClasses) {
        NSString *ownerImage = HFAProbeImageForClass(cls);
        if (![ownerImage isEqualToString:gHFAProbeMenuImage]) continue;
        unsigned count = 0;
        Ivar *list = class_copyIvarList(cls, &count);
        for (unsigned index = 0; list && index < count && ivars.count < kHFAProbeMaxStateIvars; ++index) {
            Ivar ivar = list[index];
            const char *rawName = ivar_getName(ivar);
            NSString *name = rawName ? [NSString stringWithUTF8String:rawName] : @"";
            if (!name.length || !HFAProbeStateLikeIvarName(name)) continue;
            NSString *kind = nil;
            NSNumber *value = HFAProbeReadScalarIvar(control, ivar, &kind);
            if (!value) continue;
            NSString *className = NSStringFromClass(cls) ?: @"?";
            NSString *key = [NSString stringWithFormat:@"%@.%@", className, name];
            valueMap[key] = value;
            [ivars addObject:@{ @"key": key, @"ownerClass": className,
                                @"ownerImage": ownerImage ?: @"?", @"name": name,
                                @"offset": [NSString stringWithFormat:@"0x%tx", ivar_getOffset(ivar)],
                                @"typeEncoding": [NSString stringWithUTF8String:ivar_getTypeEncoding(ivar) ?: "?"],
                                @"scalarKind": kind ?: @"unknown", @"value": value }];
        }
        if (list) free(list);
    }
    NSDictionary *snapshot = @{ @"publicState": publicState, @"primitiveIvars": ivars,
                                 @"valueMap": valueMap, @"unknownAccessorInvoked": @NO,
                                 @"objectIvarDereferenced": @NO, @"analysisOnly": @YES };
    [publicState release];
    return snapshot;
}

static NSArray *HFAProbeStateChanges(NSDictionary *before, NSDictionary *after) {
    NSDictionary *left = before[@"valueMap"] ?: @{};
    NSDictionary *right = after[@"valueMap"] ?: @{};
    NSMutableArray *changes = [NSMutableArray array];
    NSMutableSet *keys = [NSMutableSet setWithArray:left.allKeys];
    [keys addObjectsFromArray:right.allKeys];
    for (NSString *key in [[keys allObjects] sortedArrayUsingSelector:@selector(compare:)]) {
        id oldValue = left[key] ?: [NSNull null];
        id newValue = right[key] ?: [NSNull null];
        if (![oldValue isEqual:newValue])
            [changes addObject:@{ @"key": key, @"before": oldValue, @"after": newValue }];
    }
    return changes;
}

static NSString *HFAProbeLabel(UIControl *control) {
    if ([control isKindOfClass:UIButton.class]) {
        NSString *title = [(UIButton *)control titleForState:UIControlStateNormal];
        if (title.length) return title;
    }
    if (control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope = control;
    for (NSUInteger depth = 0; scope && depth < 3; ++depth, scope = scope.superview) {
        NSMutableArray<UIView *> *queue = [NSMutableArray arrayWithObject:scope];
        for (NSUInteger index = 0; index < queue.count && index < 32; ++index) {
            UIView *view = queue[index];
            if ([view isKindOfClass:UILabel.class] && [(UILabel *)view text].length)
                return [(UILabel *)view text];
            for (UIView *child in view.subviews)
                if (queue.count < 32) [queue addObject:child];
        }
    }
    return @"";
}

static NSString *HFAProbeImageForObject(id object) {
    if (!object) return @"";
    const char *path = class_getImageName(object_getClass(object));
    return path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
}

static NSDictionary *HFAProbeActionRecord(id target, NSString *action) {
    NSMutableDictionary *record = [@{
        @"targetClass": NSStringFromClass(object_getClass(target)) ?: @"?",
        @"targetImage": HFAProbeImageForObject(target),
        @"targetToken": [NSString stringWithFormat:@"%p", target],
        @"action": action ?: @"?",
        @"semanticStage": @"action-entry",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"selectorInvokedByProbe": @NO,
        @"impReplaced": @NO
    } mutableCopy];
    SEL selector = action.length ? NSSelectorFromString(action) : NULL;
    Method method = selector ? class_getInstanceMethod(object_getClass(target), selector) : NULL;
    IMP implementation = method ? method_getImplementation(method) : NULL;
    if (implementation) {
        Dl_info info = {};
        record[@"implementationPointer"] = [NSString stringWithFormat:@"0x%llX",
                                               (unsigned long long)(uintptr_t)implementation];
        if (dladdr((const void *)implementation, &info) && info.dli_fbase && info.dli_fname) {
            NSString *path = [NSString stringWithUTF8String:info.dli_fname];
            record[@"implementationImage"] = path.lastPathComponent ?: @"?";
            record[@"implementationPath"] = path ?: @"?";
            record[@"implementationInSelectedMenu"] =
                @([path.lastPathComponent isEqualToString:gHFAProbeMenuImage]);
            record[@"implementationOffsetFromLoadBase"] =
                [NSString stringWithFormat:@"0x%llX",
                 (unsigned long long)((uintptr_t)implementation - (uintptr_t)info.dli_fbase)];
            record[@"addressSemantics"] = @"runtime-implementation-minus-load-base";
        }
        const char *types = method_getTypeEncoding(method);
        if (types) record[@"typeEncoding"] = [NSString stringWithUTF8String:types];
    }
    return [record autorelease];
}

static NSArray<NSDictionary *> *HFAProbeActionsForControl(UIControl *control) {
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSMutableDictionary *> *byKey = [NSMutableDictionary dictionary];
    for (id target in control.allTargets) {
        if (![HFAProbeImageForObject(target) isEqualToString:gHFAProbeMenuImage]) continue;
        NSArray<NSDictionary *> *eventSets = @[
            @{ @"name": @"touch-up-inside", @"actions":
                   [control actionsForTarget:target forControlEvent:UIControlEventTouchUpInside] ?: @[] },
            @{ @"name": @"value-changed", @"actions":
                   [control actionsForTarget:target forControlEvent:UIControlEventValueChanged] ?: @[] }
        ];
        for (NSDictionary *eventSet in eventSets) {
            for (NSString *action in eventSet[@"actions"]) {
                NSString *key = [NSString stringWithFormat:@"%p:%@", target, action];
                NSMutableDictionary *record = byKey[key];
                if (!record) {
                    record = [[HFAProbeActionRecord(target, action) mutableCopy] autorelease];
                    record[@"registeredControlEvents"] = [NSMutableArray array];
                    byKey[key] = record;
                    [records addObject:record];
                }
                NSMutableArray *events = record[@"registeredControlEvents"];
                if (![events containsObject:eventSet[@"name"]]) [events addObject:eventSet[@"name"]];
            }
        }
    }
    return records;
}

static NSString *HFAProbeInteractionKind(UIControl *control, NSArray<NSDictionary *> *actions) {
    if ([control isKindOfClass:UISlider.class]) return @"slider-value-changed";
    if ([control isKindOfClass:UISwitch.class]) return @"switch-value-changed";
    BOOL touch = NO, value = NO;
    for (NSDictionary *action in actions) {
        NSArray *events = action[@"registeredControlEvents"];
        touch |= [events containsObject:@"touch-up-inside"];
        value |= [events containsObject:@"value-changed"];
    }
    if (touch && !value) return @"touch-up-inside";
    if (value && !touch) return @"value-changed";
    if ([control isKindOfClass:UIButton.class]) return @"button-activation";
    return @"ambiguous-control-activation";
}

static NSArray<UIControl *> *HFAProbeEligibleControls(NSString *menuImage) {
    NSMutableArray<UIView *> *queue = [NSMutableArray array];
    for (UIWindow *window in UIApplication.sharedApplication.windows)
        if (window) [queue addObject:window];
    NSHashTable *seenViews = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray<UIControl *> *controls = [NSMutableArray array];
    for (NSUInteger index = 0; index < queue.count && index < kHFAProbeMaxViews; ++index) {
        UIView *view = queue[index];
        if ([seenViews containsObject:view]) continue;
        [seenViews addObject:view];
        for (UIView *child in view.subviews)
            if (queue.count < kHFAProbeMaxViews) [queue addObject:child];
        if (![view isKindOfClass:UIControl.class] || controls.count >= kHFAProbeMaxControls) continue;
        UIControl *control = (UIControl *)view;
        BOOL eligible = NO;
        for (id target in control.allTargets) {
            if ([HFAProbeImageForObject(target) isEqualToString:menuImage]) {
                eligible = YES;
                break;
            }
        }
        if (eligible) [controls addObject:control];
    }
    return controls;
}

static BOOL HFAProbeControlHasSidecarAction(UIControl *control, id target) {
    NSString *selector = NSStringFromSelector(@selector(observeControl:));
    NSArray *touch = [control actionsForTarget:target
                               forControlEvent:UIControlEventTouchUpInside] ?: @[];
    NSArray *value = [control actionsForTarget:target
                               forControlEvent:UIControlEventValueChanged] ?: @[];
    return [touch containsObject:selector] || [value containsObject:selector];
}

static void HFAProbeWriteSummary(NSDictionary *summary) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:summary
                                                   options:NSJSONWritingPrettyPrinted error:nil];
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"RuntimeProbe.json")];
    [data writeToFile:path options:NSDataWritingAtomic error:nil];
}

@interface HFAMapRuntimeProbeTarget : NSObject
+ (instancetype)shared;
- (void)observeControl:(UIControl *)control;
@end

@implementation HFAMapRuntimeProbeTarget
+ (instancetype)shared {
    static HFAMapRuntimeProbeTarget *target;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ target = [[HFAMapRuntimeProbeTarget alloc] init]; });
    return target;
}
- (void)observeControl:(UIControl *)control {
    if (!NSThread.isMainThread) return;
    if (!gHFAProbeArmed || !control || gHFAProbeCallbackCount >= kHFAProbeMaxCallbacks) return;
    ++gHFAProbeCallbackCount;
    NSArray<NSDictionary *> *actions = HFAProbeActionsForControl(control);
    NSString *controlToken = [NSString stringWithFormat:@"%p", control];
    HFAIL2CPPRuntimeProbeMarkInteraction(HFAProbeLabel(control), controlToken);
    NSString *interactionKind = HFAProbeInteractionKind(control, actions);
    NSDictionary *armState = gHFAProbeControlBaselines[controlToken] ?: @{};
    NSDictionary *immediateState = HFAProbeStateSnapshot(control);
    NSTimeInterval now = NSDate.date.timeIntervalSince1970;
    NSMutableDictionary *record = [@{
        @"time": @(now),
        @"elapsedMs": @((now - gHFAProbeStarted) * 1000.0),
        @"label": HFAProbeLabel(control),
        @"controlClass": NSStringFromClass(object_getClass(control)) ?: @"?",
        @"controlToken": controlToken,
        @"interactionKind": interactionKind,
        @"actions": actions,
        @"stateAtArm": armState,
        @"stateImmediate": immediateState,
        @"stateChangesAtCallback": HFAProbeStateChanges(armState, immediateState),
        @"selected": @([control respondsToSelector:@selector(isSelected)] ? control.selected : NO),
        @"enabled": @(control.enabled),
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"originalActionContinues": @YES,
        @"memoryWritten": @NO,
        @"hookInstalled": @NO
    } mutableCopy];
    if ([control isKindOfClass:UISwitch.class]) record[@"switchOn"] = @([(UISwitch *)control isOn]);
    if ([control isKindOfClass:UISlider.class]) {
        float value = [(UISlider *)control value];
        record[@"sliderValue"] = @(value);
        NSNumber *existingIndex = gHFAProbeSliderRecordIndexes[controlToken];
        if (existingIndex && existingIndex.unsignedIntegerValue < gHFAProbeRecords.count) {
            NSMutableDictionary *existing = (NSMutableDictionary *)gHFAProbeRecords[existingIndex.unsignedIntegerValue];
            NSUInteger samples = [existing[@"sliderSampleCount"] unsignedIntegerValue] + 1U;
            existing[@"sliderSampleCount"] = @(samples);
            existing[@"sliderValue"] = @(value);
            existing[@"sliderLastValue"] = @(value);
            existing[@"sliderMinValue"] = @(MIN([existing[@"sliderMinValue"] floatValue], value));
            existing[@"sliderMaxValue"] = @(MAX([existing[@"sliderMaxValue"] floatValue], value));
            existing[@"label"] = record[@"label"];
            existing[@"lastTime"] = @(now);
            existing[@"elapsedMs"] = record[@"elapsedMs"];
            existing[@"stateImmediate"] = immediateState;
            existing[@"stateChangesAtCallback"] = HFAProbeStateChanges(armState, immediateState);
            record[@"coalescedIntoSliderSummary"] = @YES;
            record[@"sliderSampleCount"] = @(samples);
            HFADiagnosticsLog(@"runtime-probe-event", @"observed", record);
            NSUInteger generation = gHFAProbeGeneration;
            dispatch_async(dispatch_get_main_queue(), ^{
                if (!gHFAProbeArmed || generation != gHFAProbeGeneration) return;
                NSDictionary *settled = HFAProbeStateSnapshot(control);
                existing[@"stateSettled"] = settled;
                existing[@"stateChangesAfterEvent"] = HFAProbeStateChanges(armState, settled);
            });
            [record release];
            if (gHFAProbeCallbackCount >= kHFAProbeMaxCallbacks)
                dispatch_async(dispatch_get_main_queue(), ^{ HFAMapStopRuntimeProbe(@"callback-limit"); });
            return;
        }
        record[@"sliderFirstValue"] = @(value);
        record[@"sliderLastValue"] = @(value);
        record[@"sliderMinValue"] = @(value);
        record[@"sliderMaxValue"] = @(value);
        record[@"sliderSampleCount"] = @1;
        gHFAProbeSliderRecordIndexes[controlToken] = @(gHFAProbeRecords.count);
    }
    if (gHFAProbeRecords.count < kHFAProbeMaxEvents) [gHFAProbeRecords addObject:record];
    HFADiagnosticsLog(@"runtime-probe-event", @"observed", record);
    NSUInteger generation = gHFAProbeGeneration;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gHFAProbeArmed || generation != gHFAProbeGeneration) return;
        NSDictionary *settled = HFAProbeStateSnapshot(control);
        record[@"stateSettled"] = settled;
        record[@"stateChangesAfterEvent"] = HFAProbeStateChanges(armState, settled);
        HFADiagnosticsLog(@"runtime-probe-state", @"settled", @{
            @"controlToken": controlToken,
            @"label": record[@"label"] ?: @"",
            @"changes": record[@"stateChangesAfterEvent"] ?: @[]
        });
    });
    [record release];
    if (gHFAProbeRecords.count >= kHFAProbeMaxEvents ||
        gHFAProbeCallbackCount >= kHFAProbeMaxCallbacks) {
        NSString *reason = gHFAProbeCallbackCount >= kHFAProbeMaxCallbacks ?
            @"callback-limit" : @"event-limit";
        dispatch_async(dispatch_get_main_queue(), ^{ HFAMapStopRuntimeProbe(reason); });
    }
}
@end

BOOL HFAMapRuntimeProbeIsArmed(void) {
    return gHFAProbeArmed;
}

void HFAMapStopRuntimeProbe(NSString *reason) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{ HFAMapStopRuntimeProbe(reason); });
        return;
    }
    if (!gHFAProbeArmed) return;
    gHFAProbeArmed = NO;
    ++gHFAProbeGeneration;
    HFAMapRuntimeProbeTarget *target = [HFAMapRuntimeProbeTarget shared];
    for (UIControl *control in gHFAProbeControls)
        [control removeTarget:target action:@selector(observeControl:) forControlEvents:kHFAProbeEvents];
    NSUInteger targetRestoreFailureCount = 0;
    for (UIControl *control in gHFAProbeControls)
        if (HFAProbeControlHasSidecarAction(control, target)) ++targetRestoreFailureCount;
    NSDictionary *il2cppRuntimeProbe = HFAIL2CPPRuntimeProbeStop(reason ?: @"stopped");
    NSDictionary *summary = @{
        @"schema": @"com.hfa.runtime-probe/v2",
        @"version": @"2.3.8-dev-dual-runtime-probe",
        @"status": @"complete",
        @"reason": reason ?: @"stopped",
        @"menuImage": gHFAProbeMenuImage ?: @"?",
        @"candidateIdentity": gHFAProbeCandidate ?: @{},
        @"durationMs": @((NSDate.date.timeIntervalSince1970 - gHFAProbeStarted) * 1000.0),
        @"observedControlCount": @(gHFAProbeControls.count),
        @"eventCount": @(gHFAProbeRecords.count),
        @"callbackCount": @(gHFAProbeCallbackCount),
        @"sliderEventsCoalesced": @YES,
        @"customControlPrimitiveStateObserved": @YES,
        @"stateSnapshotMode": @"selected-menu-class-primitive-ivars-plus-public-state",
        @"records": gHFAProbeRecords ?: @[],
        @"il2cppRuntimeProbe": il2cppRuntimeProbe ?: @{},
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"targetListModifiedTemporarily": @YES,
        @"targetListRestored": @(targetRestoreFailureCount == 0),
        @"targetRestoreFailureCount": @(targetRestoreFailureCount),
        @"unknownSelectorInvoked": @NO,
        @"impReplaced": @NO,
        @"hookInstalled": il2cppRuntimeProbe[@"hookInstalled"] ?: @NO,
        @"memoryWritten": il2cppRuntimeProbe[@"memoryWritten"] ?: @NO,
        @"gameStateWritten": @NO
    };
    HFAProbeWriteSummary(summary);
    HFADiagnosticsLog(@"runtime-probe", @"stopped", summary);
    void (^completion)(NSDictionary *) = gHFAProbeCompletion;
    gHFAProbeCompletion = nil;
    [gHFAProbeControls release]; gHFAProbeControls = nil;
    [gHFAProbeRecords release]; gHFAProbeRecords = nil;
    [gHFAProbeSliderRecordIndexes release]; gHFAProbeSliderRecordIndexes = nil;
    [gHFAProbeControlBaselines release]; gHFAProbeControlBaselines = nil;
    [gHFAProbeMenuImage release]; gHFAProbeMenuImage = nil;
    [gHFAProbeCandidate release]; gHFAProbeCandidate = nil;
    if (completion) completion(summary);
    [completion release];
}

void HFAMapArmRuntimeProbeForCandidate(NSDictionary *candidate, NSTimeInterval duration,
                                      void (^completion)(NSDictionary *summary)) {
    if (!NSThread.isMainThread) {
        dispatch_async(dispatch_get_main_queue(), ^{
            HFAMapArmRuntimeProbeForCandidate(candidate, duration, completion);
        });
        return;
    }
    if (gHFAProbeArmed) {
        if (completion) completion(@{ @"status": @"busy", @"analysisOnly": @YES });
        return;
    }
    NSString *menuImage = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : nil;
    if (!menuImage.length) {
        if (completion) completion(@{ @"status": @"no-selected-menu-image",
                                      @"analysisOnly": @YES });
        return;
    }
    duration = MAX(2.0, MIN(duration, 15.0));
    NSArray<UIControl *> *eligible = HFAProbeEligibleControls(menuImage);
    if (!eligible.count) {
        if (completion) completion(@{ @"status": @"no-eligible-controls",
                                      @"menuImage": menuImage, @"analysisOnly": @YES });
        return;
    }
    gHFAProbeMenuImage = [menuImage copy];
    gHFAProbeCandidate = [[NSDictionary alloc] initWithObjectsAndKeys:
        menuImage, @"menuImage",
        candidate[@"menuUUID"] ?: @"unknown", @"menuUUID",
        candidate[@"hostBundleID"] ?: @"unknown", @"hostBundleID",
        candidate[@"hostVersion"] ?: @"unknown", @"hostVersion",
        candidate[@"hostBuild"] ?: @"unknown", @"hostBuild", nil];
    gHFAProbeControls = [eligible mutableCopy];
    gHFAProbeRecords = [[NSMutableArray alloc] init];
    gHFAProbeSliderRecordIndexes = [[NSMutableDictionary alloc] init];
    gHFAProbeControlBaselines = [[NSMutableDictionary alloc] init];
    for (UIControl *control in eligible) {
        NSString *token = [NSString stringWithFormat:@"%p", control];
        gHFAProbeControlBaselines[token] = HFAProbeStateSnapshot(control);
    }
    gHFAProbeCallbackCount = 0;
    gHFAProbeCompletion = [completion copy];
    gHFAProbeStarted = NSDate.date.timeIntervalSince1970;
    NSDictionary *il2cppArm = HFAIL2CPPRuntimeProbeArm(gHFAProbeCandidate, duration);
    gHFAProbeArmed = YES;
    NSUInteger generation = ++gHFAProbeGeneration;
    HFAMapRuntimeProbeTarget *target = [HFAMapRuntimeProbeTarget shared];
    for (UIControl *control in gHFAProbeControls)
        [control addTarget:target action:@selector(observeControl:) forControlEvents:kHFAProbeEvents];
    NSDictionary *armed = @{
        @"version": @"2.3.8-dev-dual-runtime-probe",
        @"menuImage": menuImage,
        @"candidateIdentity": gHFAProbeCandidate,
        @"durationSeconds": @(duration),
        @"observedControlCount": @(gHFAProbeControls.count),
        @"eventLimit": @(kHFAProbeMaxEvents),
        @"callbackLimit": @(kHFAProbeMaxCallbacks),
        @"sliderEventsCoalesced": @YES,
        @"customControlPrimitiveStateObserved": @YES,
        @"stateSnapshotMode": @"selected-menu-class-primitive-ivars-plus-public-state",
        @"mode": @"reversible-ui-control-sidecar-target",
        @"il2cppRuntimeProbe": il2cppArm ?: @{},
        @"unknownSelectorInvoked": @NO,
        @"impReplaced": @NO,
        @"hookInstalled": il2cppArm[@"hookInstalled"] ?: @NO,
        @"memoryWritten": il2cppArm[@"instrumentationCodeModifiedTemporarily"] ?: @NO,
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO
    };
    HFADiagnosticsLog(@"runtime-probe", @"armed", armed);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(duration * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (gHFAProbeArmed && generation == gHFAProbeGeneration)
            HFAMapStopRuntimeProbe(@"deadline");
    });
}
