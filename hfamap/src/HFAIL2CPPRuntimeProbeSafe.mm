#import "HFAIL2CPPRuntimeProbe.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapStrippedActionAnalyzer.h"
#import "HFAMapFeatureContextAnalyzer.h"

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

// v2.5.7 crash-safe backend.
// Deliberately does NOT resolve/use DobbyHook/DobbyDestroy and never patches
// IL2CPP exports. Correlation is derived only from the exact user-activated
// UIControl -> target/action -> implementation chain plus bounded static/context
// analysis of that implementation.

static const NSUInteger kHFASafeMaxInteractions = 64;
static const NSUInteger kHFASafeMaxFeatureAnalyses = 64;
static const NSUInteger kHFASafeMaxActionsPerInteraction = 16;

static pthread_mutex_t gHFASafeLock = PTHREAD_MUTEX_INITIALIZER;
static BOOL gHFASafeSessionActive = NO;
static NSTimeInterval gHFASafeStarted = 0;
static NSTimeInterval gHFASafeDuration = 0;
static NSDictionary *gHFASafeCandidate = nil;
static NSMutableArray *gHFASafeInteractions = nil;
static NSMutableArray *gHFASafeFeatureAnalyses = nil;

static NSTimeInterval HFASafeNow(void) {
    return NSDate.date.timeIntervalSince1970;
}

static NSString *HFASafePointerToken(const void *pointer) {
    return [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)pointer];
}

static NSString *HFASafeImageForObject(id object) {
    if (!object) return @"";
    const char *path = class_getImageName(object_getClass(object));
    if (!path) return @"";
    NSString *value = [NSString stringWithUTF8String:path];
    return value.lastPathComponent ?: @"";
}

static NSArray *HFASafeFeatureDirectedAnalyses(NSString *label, NSString *controlToken) {
    if (!NSThread.isMainThread || !controlToken.length) return @[];

    const char *rawToken = controlToken.UTF8String;
    char *end = NULL;
    uintptr_t pointer = (uintptr_t)strtoull(rawToken, &end, 0);
    if (!pointer || end == rawToken || (end && *end)) return @[];

    UIControl *control = (__bridge UIControl *)(void *)pointer;
    if (!control || ![control isKindOfClass:UIControl.class]) return @[];

    NSString *menuImage = [gHFASafeCandidate[@"menuImage"] isKindOfClass:NSString.class]
        ? gHFASafeCandidate[@"menuImage"] : @"";
    if (!menuImage.length) return @[];

    NSMutableArray *records = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];

    for (id target in control.allTargets) {
        if (records.count >= kHFASafeMaxActionsPerInteraction) break;
        if (![HFASafeImageForObject(target) isEqualToString:menuImage]) continue;

        NSArray *eventSets = @[
            @{ @"event": @"touch-up-inside",
               @"actions": [control actionsForTarget:target forControlEvent:UIControlEventTouchUpInside] ?: @[] },
            @{ @"event": @"value-changed",
               @"actions": [control actionsForTarget:target forControlEvent:UIControlEventValueChanged] ?: @[] }
        ];

        for (NSDictionary *eventSet in eventSets) {
            for (NSString *action in eventSet[@"actions"]) {
                if (records.count >= kHFASafeMaxActionsPerInteraction) break;
                NSString *key = [NSString stringWithFormat:@"%p:%@", target, action ?: @""];
                if ([seen containsObject:key]) continue;
                [seen addObject:key];

                SEL selector = action.length ? NSSelectorFromString(action) : NULL;
                Method method = selector ? class_getInstanceMethod(object_getClass(target), selector) : NULL;
                IMP implementation = method ? method_getImplementation(method) : NULL;
                if (!implementation) continue;

                Dl_info info = {};
                if (!dladdr((const void *)implementation, &info) || !info.dli_fname || !info.dli_fbase) continue;
                NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
                if (![path.lastPathComponent isEqualToString:menuImage]) continue;

                NSDictionary *downstream = HFAMapAnalyzeStrippedActionIMP((const void *)implementation, path);
                NSDictionary *context = HFAMapAnalyzeFeatureCallbackContext((const void *)implementation,
                                                                             path,
                                                                             target,
                                                                             selector,
                                                                             control);
                NSUInteger downstreamLinks = [downstream[@"il2cppCorrelationCount"] unsignedIntegerValue];
                NSUInteger contextLinks = [context[@"il2cppCorrelationCount"] unsignedIntegerValue];
                NSUInteger correlations = downstreamLinks + contextLinks;

                [records addObject:@{
                    @"schema": @"com.hfa.feature-directed-runtime-method/v2",
                    @"version": @"2.5.7-dev-crash-safe-runtime-probe",
                    @"label": label ?: @"",
                    @"controlToken": controlToken,
                    @"registeredEvent": eventSet[@"event"] ?: @"unknown",
                    @"targetClass": NSStringFromClass(object_getClass(target)) ?: @"?",
                    @"action": action ?: @"?",
                    @"implementationPointer": HFASafePointerToken((const void *)implementation),
                    @"implementationImage": path.lastPathComponent ?: @"?",
                    @"implementationPath": path,
                    @"implementationOffsetFromLoadBase": [NSString stringWithFormat:@"0x%llX",
                        (unsigned long long)((uintptr_t)implementation - (uintptr_t)info.dli_fbase)],
                    @"downstreamAnalysis": downstream ?: @{},
                    @"contextSeededAnalysis": context ?: @{},
                    @"contextSeededCorrelationCount": @(contextLinks),
                    @"il2cppCorrelationCount": @(correlations),
                    @"selectionPolicy": @"exact-user-activated-control-target-action",
                    @"runtimeHookPolicy": @"no-inline-hook-no-il2cpp-export-hook",
                    @"analysisOnly": @YES,
                    @"canonicalEligible": @NO,
                    @"selectorInvokedByProbe": @NO,
                    @"impReplaced": @NO,
                    @"hookInstalled": @NO,
                    @"memoryWritten": @NO,
                    @"gameStateWritten": @NO
                }];
            }
        }
    }
    return records;
}

BOOL HFAIL2CPPRuntimeProbeIsArmed(void) {
    pthread_mutex_lock(&gHFASafeLock);
    BOOL active = gHFASafeSessionActive;
    pthread_mutex_unlock(&gHFASafeLock);
    return active;
}

NSDictionary *HFAIL2CPPRuntimeProbeArm(NSDictionary *candidate, NSTimeInterval duration) {
    pthread_mutex_lock(&gHFASafeLock);
    if (gHFASafeSessionActive) {
        pthread_mutex_unlock(&gHFASafeLock);
        return @{ @"status": @"busy", @"analysisOnly": @YES,
                  @"hookInstalled": @NO, @"memoryWritten": @NO };
    }

    gHFASafeSessionActive = YES;
    gHFASafeStarted = HFASafeNow();
    gHFASafeDuration = duration;
    gHFASafeCandidate = [candidate copy];
    gHFASafeInteractions = [[NSMutableArray alloc] init];
    gHFASafeFeatureAnalyses = [[NSMutableArray alloc] init];

    NSDictionary *result = @{
        @"schema": @"com.hfa.il2cpp-runtime-probe/v2",
        @"version": @"2.5.7-dev-crash-safe-runtime-probe",
        @"status": @"armed-read-only",
        @"backend": @"feature-directed-read-only",
        @"durationSeconds": @(duration),
        @"featureDirectedAnalysisEnabled": @YES,
        @"featureDirectedAnalysisRequiresHook": @NO,
        @"featureContextSeededAnalysisEnabled": @YES,
        @"installedSymbols": @[],
        @"il2cppExportsHooked": @[],
        @"runtimeInvokeHooked": @NO,
        @"originalCallsContinue": @YES,
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"hookInstalled": @NO,
        @"instrumentationCodeModifiedTemporarily": @NO,
        @"memoryWritten": @NO,
        @"gameStateWritten": @NO,
        @"policy": @"fail-closed-no-dobby-no-il2cpp-export-hook"
    };
    pthread_mutex_unlock(&gHFASafeLock);

    HFADiagnosticsLog(@"il2cpp-runtime-probe", @"armed-read-only", result);
    return result;
}

void HFAIL2CPPRuntimeProbeMarkInteraction(NSString *label, NSString *controlToken) {
    pthread_mutex_lock(&gHFASafeLock);
    BOOL active = gHFASafeSessionActive;
    pthread_mutex_unlock(&gHFASafeLock);
    if (!active) return;

    NSArray *directed = HFASafeFeatureDirectedAnalyses(label, controlToken);
    NSUInteger correlations = 0;
    NSUInteger contextResolved = 0;
    for (NSDictionary *item in directed) {
        correlations += [item[@"il2cppCorrelationCount"] unsignedIntegerValue];
        NSDictionary *context = item[@"contextSeededAnalysis"];
        contextResolved += [context[@"resolvedConditionalCount"] unsignedIntegerValue];
    }

    NSDictionary *interaction = @{
        @"time": @(HFASafeNow()),
        @"label": label ?: @"",
        @"controlToken": controlToken ?: @"",
        @"featureDirectedAnalyses": directed ?: @[],
        @"featureDirectedActionCount": @(directed.count),
        @"featureDirectedCorrelationCount": @(correlations),
        @"contextResolvedConditionalCount": @(contextResolved),
        @"analysisPolicy": @"exact-control-target-action-no-hook",
        @"hookInstalled": @NO,
        @"memoryWritten": @NO
    };

    pthread_mutex_lock(&gHFASafeLock);
    if (gHFASafeSessionActive && gHFASafeInteractions.count < kHFASafeMaxInteractions)
        [gHFASafeInteractions addObject:interaction];
    if (gHFASafeSessionActive && directed.count && gHFASafeFeatureAnalyses.count < kHFASafeMaxFeatureAnalyses) {
        for (NSDictionary *item in directed) {
            if (gHFASafeFeatureAnalyses.count >= kHFASafeMaxFeatureAnalyses) break;
            [gHFASafeFeatureAnalyses addObject:item];
        }
    }
    pthread_mutex_unlock(&gHFASafeLock);

    if (directed.count) {
        HFADiagnosticsLog(@"feature-directed-runtime-method",
                          correlations ? @"correlated" : @"analyzed",
                          @{ @"label": label ?: @"",
                             @"controlToken": controlToken ?: @"",
                             @"actionCount": @(directed.count),
                             @"correlationCount": @(correlations),
                             @"contextResolvedConditionalCount": @(contextResolved),
                             @"records": directed,
                             @"hookInstalled": @NO,
                             @"memoryWritten": @NO });
    }
}

NSDictionary *HFAIL2CPPRuntimeProbeStop(NSString *reason) {
    pthread_mutex_lock(&gHFASafeLock);
    if (!gHFASafeSessionActive) {
        pthread_mutex_unlock(&gHFASafeLock);
        return @{ @"schema": @"com.hfa.il2cpp-runtime-probe/v2",
                  @"version": @"2.5.7-dev-crash-safe-runtime-probe",
                  @"status": @"not-armed",
                  @"reason": reason ?: @"stopped",
                  @"hookInstalled": @NO,
                  @"memoryWritten": @NO,
                  @"gameStateWritten": @NO,
                  @"analysisOnly": @YES };
    }

    gHFASafeSessionActive = NO;
    NSArray *interactions = [gHFASafeInteractions copy];
    NSArray *featureAnalyses = [gHFASafeFeatureAnalyses copy];
    NSDictionary *candidate = [gHFASafeCandidate copy];
    NSTimeInterval started = gHFASafeStarted;
    NSTimeInterval requested = gHFASafeDuration;

    [gHFASafeInteractions release]; gHFASafeInteractions = nil;
    [gHFASafeFeatureAnalyses release]; gHFASafeFeatureAnalyses = nil;
    [gHFASafeCandidate release]; gHFASafeCandidate = nil;
    gHFASafeStarted = 0;
    gHFASafeDuration = 0;
    pthread_mutex_unlock(&gHFASafeLock);

    NSUInteger featureCorrelations = 0;
    NSUInteger contextResolved = 0;
    for (NSDictionary *item in featureAnalyses) {
        featureCorrelations += [item[@"il2cppCorrelationCount"] unsignedIntegerValue];
        contextResolved += [item[@"contextSeededAnalysis"][@"resolvedConditionalCount"] unsignedIntegerValue];
    }

    NSString *classification = featureCorrelations
        ? @"feature-directed-method-correlation-observed"
        : (contextResolved ? @"feature-context-branch-correlation-observed"
                           : @"no-method-chain-read-only");

    NSDictionary *summary = @{
        @"schema": @"com.hfa.il2cpp-runtime-probe/v2",
        @"version": @"2.5.7-dev-crash-safe-runtime-probe",
        @"status": @"complete",
        @"reason": reason ?: @"stopped",
        @"candidateIdentity": candidate ?: @{},
        @"durationMs": @((HFASafeNow() - started) * 1000.0),
        @"requestedDurationSeconds": @(requested),
        @"eventCount": @0,
        @"resolvedMethodCount": @0,
        @"observedInvocationCount": @0,
        @"interactions": interactions ?: @[],
        @"events": @[],
        @"featureDirectedAnalyses": featureAnalyses ?: @[],
        @"featureDirectedAnalysisCount": @(featureAnalyses.count),
        @"featureDirectedCorrelationCount": @(featureCorrelations),
        @"contextResolvedConditionalCount": @(contextResolved),
        @"featureDirectedAnalysisRequiresHook": @NO,
        @"classification": classification,
        @"originalCallsContinued": @YES,
        @"hookInstalled": @NO,
        @"instrumentationCodeModifiedTemporarily": @NO,
        @"hookRestoreFailureCount": @0,
        @"hooksRestored": @YES,
        @"runtimeInvokeHooked": @NO,
        @"memoryWritten": @NO,
        @"gameStateWritten": @NO,
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"policy": @"feature-directed-read-only-correlation-no-dobby-no-il2cpp-export-hook"
    };

    [interactions release];
    [featureAnalyses release];
    [candidate release];

    HFADiagnosticsLog(@"il2cpp-runtime-probe", @"complete", summary);
    return summary;
}
