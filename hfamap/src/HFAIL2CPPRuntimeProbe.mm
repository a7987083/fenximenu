#import "HFAIL2CPPRuntimeProbe.h"
#import "HFAIL2CPPResolver.h"
#import "HFAMapDiagnostics.h"
#import "dobby.h"

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <string.h>

// Observation-only IL2CPP resolver probe. It never suppresses or changes the
// original call. v2.3.9 embeds a pinned Dobby backend and combines exported
// IL2CPP API observation with bounded ABI-safe method-entry instrumentation.

typedef void *(*HFAClassFromNameFn)(const void *image, const char *namespaze,
                                    const char *name);
typedef const void *(*HFAClassGetMethodFn)(void *klass, const char *name,
                                           int argumentCount);
typedef void *(*HFARuntimeInvokeFn)(const void *method, void *object,
                                    void **arguments, void **exception);
typedef const char *(*HFAImageGetNameFn)(const void *image);

static const NSUInteger kHFAIL2CPPMaxEvents = 512;
static const NSUInteger kHFAIL2CPPMaxMappings = 256;
static const NSUInteger kHFAIL2CPPMaxDirectInstruments = 96;
static const NSTimeInterval kHFAIL2CPPCorrelationWindow = 1.5;

static pthread_mutex_t gHFAIL2CPPLock = PTHREAD_MUTEX_INITIALIZER;
static volatile BOOL gHFAIL2CPPArmed;
static NSTimeInterval gHFAIL2CPPStarted;
static NSTimeInterval gHFAIL2CPPDuration;
static NSDictionary *gHFAIL2CPPCandidate;
static NSMutableArray *gHFAIL2CPPEvents;
static NSMutableArray *gHFAIL2CPPInteractions;
static NSMutableDictionary *gHFAIL2CPPClasses;
static NSMutableDictionary *gHFAIL2CPPMethods;
static NSMutableArray *gHFAIL2CPPInstalledTargets;
static NSMutableArray *gHFAIL2CPPInstalledSymbols;
static NSMutableDictionary *gHFAIL2CPPDirectMethods;
static NSDictionary *gHFAIL2CPPResolverEvidence;
static NSString *gHFAIL2CPPStopStatus;

static HFAImageGetNameFn gHFAIL2CPPImageGetName;
static HFAClassFromNameFn gHFAIL2CPPClassFromNameOriginal;
static HFAClassGetMethodFn gHFAIL2CPPClassGetMethodOriginal;
static HFARuntimeInvokeFn gHFAIL2CPPRuntimeInvokeOriginal;

static void *gHFAIL2CPPClassFromNameTarget;
static void *gHFAIL2CPPClassGetMethodTarget;
static void *gHFAIL2CPPRuntimeInvokeTarget;

static NSTimeInterval HFANow(void) {
    return NSDate.date.timeIntervalSince1970;
}

static NSString *HFAPointerToken(const void *pointer) {
    return [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)pointer];
}

static NSString *HFASafeCString(const char *pointer, NSUInteger limit) {
    if (!pointer || !limit) return @"";
    NSMutableData *data = [NSMutableData dataWithCapacity:MIN(limit, 256U)];
    for (NSUInteger index = 0; index < limit; ++index) {
        uint8_t byte = 0;
        vm_size_t copied = 0;
        kern_return_t result = vm_read_overwrite(mach_task_self(),
            (vm_address_t)((uintptr_t)pointer + index), 1,
            (vm_address_t)&byte, &copied);
        if (result != KERN_SUCCESS || copied != 1 || byte == 0) break;
        [data appendBytes:&byte length:1];
    }
    NSString *value = [[[NSString alloc] initWithData:data
                                             encoding:NSUTF8StringEncoding] autorelease];
    return value ?: @"";
}

static NSDictionary *HFASymbolLocation(const void *pointer) {
    if (!pointer) return @{};
    Dl_info info = {};
    if (!dladdr(pointer, &info) || !info.dli_fbase || !info.dli_fname) return @{};
    NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
    return @{
        @"image": path.lastPathComponent ?: @"?",
        @"path": path,
        @"offsetFromLoadBase": [NSString stringWithFormat:@"0x%llX",
            (unsigned long long)((uintptr_t)pointer - (uintptr_t)info.dli_fbase)],
        @"addressSemantics": @"runtime-address-minus-load-base"
    };
}

static NSValue *HFAKey(const void *pointer) {
    return [NSValue valueWithPointer:pointer];
}

static NSDictionary *HFACurrentInteractionLocked(NSTimeInterval now) {
    NSDictionary *last = gHFAIL2CPPInteractions.lastObject;
    if (!last) return nil;
    NSTimeInterval delta = fabs(now - [last[@"time"] doubleValue]);
    return delta <= kHFAIL2CPPCorrelationWindow ? last : nil;
}

static void HFAAppendEvent(NSDictionary *payload) {
    if (!payload || !gHFAIL2CPPArmed) return;
    pthread_mutex_lock(&gHFAIL2CPPLock);
    if (gHFAIL2CPPArmed && gHFAIL2CPPEvents.count < kHFAIL2CPPMaxEvents) {
        NSTimeInterval now = HFANow();
        NSMutableDictionary *event = [payload mutableCopy];
        event[@"time"] = @(now);
        event[@"elapsedMs"] = @((now - gHFAIL2CPPStarted) * 1000.0);
        event[@"thread"] = NSThread.isMainThread ? @"main" : @"background";
        event[@"analysisOnly"] = @YES;
        event[@"canonicalEligible"] = @NO;
        NSDictionary *interaction = HFACurrentInteractionLocked(now);
        if (interaction) event[@"nearInteraction"] = interaction;
        [gHFAIL2CPPEvents addObject:event];
        [event release];
    }
    pthread_mutex_unlock(&gHFAIL2CPPLock);
}

static void HFADirectMethodInstrument(void *address, DobbyRegisterContext *context) {
    if (!gHFAIL2CPPArmed || !address || !context) return;
    NSDictionary *mapping = nil;
    pthread_mutex_lock(&gHFAIL2CPPLock);
    mapping = [gHFAIL2CPPDirectMethods[HFAKey(address)] copy];
    pthread_mutex_unlock(&gHFAIL2CPPLock);
    if (!mapping) return;
    @autoreleasepool {
        NSMutableDictionary *event = [NSMutableDictionary dictionaryWithDictionary:mapping];
        event[@"stage"] = @"direct-method-entry";
        event[@"methodPointerToken"] = HFAPointerToken(address);
        event[@"invocationObserved"] = @YES;
        event[@"resolutionStatus"] = @"resolved-method-entry-observed";
        event[@"registers"] = @{
            @"x0": HFAPointerToken((void *)(uintptr_t)context->general.regs.x0),
            @"x1": HFAPointerToken((void *)(uintptr_t)context->general.regs.x1),
            @"x2": HFAPointerToken((void *)(uintptr_t)context->general.regs.x2),
            @"x3": HFAPointerToken((void *)(uintptr_t)context->general.regs.x3),
            @"x4": HFAPointerToken((void *)(uintptr_t)context->general.regs.x4),
            @"x5": HFAPointerToken((void *)(uintptr_t)context->general.regs.x5),
            @"x6": HFAPointerToken((void *)(uintptr_t)context->general.regs.x6),
            @"x7": HFAPointerToken((void *)(uintptr_t)context->general.regs.x7),
            @"lr": HFAPointerToken((void *)(uintptr_t)context->lr),
            @"sp": HFAPointerToken((void *)(uintptr_t)context->sp)
        };
        HFAAppendEvent(event);
    }
    [mapping release];
}

static void *HFAClassFromNameReplacement(const void *image, const char *namespaze,
                                         const char *name) {
    HFAClassFromNameFn original = gHFAIL2CPPClassFromNameOriginal;
    void *klass = original ? original(image, namespaze, name) : NULL;
    if (!gHFAIL2CPPArmed) return klass;
    @autoreleasepool {
        NSString *namespaceValue = HFASafeCString(namespaze, 256);
        NSString *classValue = HFASafeCString(name, 256);
        NSString *assembly = @"";
        if (gHFAIL2CPPImageGetName && image)
            assembly = HFASafeCString(gHFAIL2CPPImageGetName(image), 256);
        NSDictionary *mapping = @{
            @"assembly": assembly ?: @"", @"namespace": namespaceValue ?: @"",
            @"class": classValue ?: @"", @"imageToken": HFAPointerToken(image),
            @"classToken": HFAPointerToken(klass)
        };
        if (klass) {
            pthread_mutex_lock(&gHFAIL2CPPLock);
            if (gHFAIL2CPPClasses.count < kHFAIL2CPPMaxMappings)
                gHFAIL2CPPClasses[HFAKey(klass)] = mapping;
            pthread_mutex_unlock(&gHFAIL2CPPLock);
        }
        NSMutableDictionary *event = [mapping mutableCopy];
        event[@"stage"] = @"class-from-name";
        event[@"resolutionStatus"] = klass ? @"resolved" : @"not-found";
        HFAAppendEvent(event);
        [event release];
    }
    return klass;
}

static const void *HFAClassGetMethodReplacement(void *klass, const char *name,
                                                 int argumentCount) {
    HFAClassGetMethodFn original = gHFAIL2CPPClassGetMethodOriginal;
    const void *method = original ? original(klass, name, argumentCount) : NULL;
    if (!gHFAIL2CPPArmed) return method;
    @autoreleasepool {
        NSString *methodName = HFASafeCString(name, 256);
        NSDictionary *classMapping = nil;
        pthread_mutex_lock(&gHFAIL2CPPLock);
        classMapping = [[gHFAIL2CPPClasses[HFAKey(klass)] retain] autorelease];
        pthread_mutex_unlock(&gHFAIL2CPPLock);
        NSMutableDictionary *mapping = [NSMutableDictionary dictionaryWithDictionary:
                                         classMapping ?: @{}];
        mapping[@"method"] = methodName ?: @"";
        mapping[@"parameterCount"] = @(argumentCount);
        mapping[@"classToken"] = HFAPointerToken(klass);
        mapping[@"methodInfoToken"] = HFAPointerToken(method);
        mapping[@"signatureValidated"] = @NO;
        mapping[@"invocationObserved"] = @NO;
        if (method) {
            pthread_mutex_lock(&gHFAIL2CPPLock);
            if (gHFAIL2CPPMethods.count < kHFAIL2CPPMaxMappings)
                gHFAIL2CPPMethods[HFAKey(method)] = mapping;
            pthread_mutex_unlock(&gHFAIL2CPPLock);
        }
        NSMutableDictionary *event = [mapping mutableCopy];
        event[@"stage"] = @"class-get-method-from-name";
        event[@"resolutionStatus"] = method ? @"resolved" : @"not-found";
        HFAAppendEvent(event);
        [event release];
    }
    return method;
}

static void *HFARuntimeInvokeReplacement(const void *method, void *object,
                                         void **arguments, void **exception) {
    NSDictionary *mapping = nil;
    if (gHFAIL2CPPArmed) {
        pthread_mutex_lock(&gHFAIL2CPPLock);
        mapping = [gHFAIL2CPPMethods[HFAKey(method)] copy];
        pthread_mutex_unlock(&gHFAIL2CPPLock);
    }
    HFARuntimeInvokeFn original = gHFAIL2CPPRuntimeInvokeOriginal;
    void *result = original ? original(method, object, arguments, exception) : NULL;
    if (gHFAIL2CPPArmed) {
        @autoreleasepool {
            NSMutableDictionary *event = [NSMutableDictionary dictionaryWithDictionary:
                                           mapping ?: @{}];
            event[@"stage"] = @"runtime-invoke";
            event[@"methodInfoToken"] = HFAPointerToken(method);
            event[@"objectToken"] = HFAPointerToken(object);
            event[@"argumentsToken"] = HFAPointerToken(arguments);
            event[@"resultToken"] = HFAPointerToken(result);
            event[@"exceptionToken"] = HFAPointerToken(exception ? *exception : NULL);
            event[@"invocationObserved"] = @YES;
            event[@"resolutionStatus"] = mapping ? @"resolved-method-invoked" : @"unmapped-method-invoked";
            HFAAppendEvent(event);
        }
    }
    [mapping release];
    return result;
}

static BOOL HFAInstallHook(void *target, void *replacement, void **original,
                           NSString *symbol) {
    if (!target || !replacement || !original) return NO;
    int result = DobbyHook(target, replacement, original);
    if (result != 0 || !*original) return NO;
    [gHFAIL2CPPInstalledTargets addObject:HFAKey(target)];
    [gHFAIL2CPPInstalledSymbols addObject:symbol ?: @"?"];
    return YES;
}

static BOOL HFAInstallDirectInstrument(NSDictionary *candidate) {
    uintptr_t pointer = (uintptr_t)[candidate[@"methodPointer"] unsignedLongLongValue];
    if (!pointer || gHFAIL2CPPDirectMethods.count >= kHFAIL2CPPMaxDirectInstruments) return NO;
    NSValue *key = HFAKey((void *)pointer);
    if (gHFAIL2CPPDirectMethods[key]) return YES;
    if (DobbyInstrument((void *)pointer, &HFADirectMethodInstrument) != 0) return NO;
    gHFAIL2CPPDirectMethods[key] = candidate ?: @{};
    [gHFAIL2CPPInstalledTargets addObject:key];
    [gHFAIL2CPPInstalledSymbols addObject:[@"method:" stringByAppendingString:
        candidate[@"canonical"] ?: HFAPointerToken((void *)pointer)]];
    NSNumber *methodInfo = candidate[@"methodInfo"];
    if (methodInfo.unsignedLongLongValue && gHFAIL2CPPMethods.count < kHFAIL2CPPMaxMappings)
        gHFAIL2CPPMethods[HFAKey((void *)(uintptr_t)methodInfo.unsignedLongLongValue)] = candidate;
    return YES;
}

static void HFARemoveHooksLocked(void) {
    for (NSValue *value in [gHFAIL2CPPInstalledTargets reverseObjectEnumerator])
        DobbyDestroy(value.pointerValue);
    [gHFAIL2CPPInstalledTargets removeAllObjects];
    [gHFAIL2CPPInstalledSymbols removeAllObjects];
    gHFAIL2CPPClassFromNameOriginal = NULL;
    gHFAIL2CPPClassGetMethodOriginal = NULL;
    gHFAIL2CPPRuntimeInvokeOriginal = NULL;
}

BOOL HFAIL2CPPRuntimeProbeIsArmed(void) {
    return gHFAIL2CPPArmed;
}

NSDictionary *HFAIL2CPPRuntimeProbeArm(NSDictionary *candidate, NSTimeInterval duration) {
    pthread_mutex_lock(&gHFAIL2CPPLock);
    if (gHFAIL2CPPArmed) {
        pthread_mutex_unlock(&gHFAIL2CPPLock);
        return @{ @"status": @"busy", @"analysisOnly": @YES };
    }
    gHFAIL2CPPImageGetName = (HFAImageGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_name");
    gHFAIL2CPPClassFromNameTarget = dlsym(RTLD_DEFAULT, "il2cpp_class_from_name");
    gHFAIL2CPPClassGetMethodTarget = dlsym(RTLD_DEFAULT, "il2cpp_class_get_method_from_name");
    gHFAIL2CPPRuntimeInvokeTarget = dlsym(RTLD_DEFAULT, "il2cpp_runtime_invoke");

    gHFAIL2CPPEvents = [[NSMutableArray alloc] init];
    gHFAIL2CPPInteractions = [[NSMutableArray alloc] init];
    gHFAIL2CPPClasses = [[NSMutableDictionary alloc] init];
    gHFAIL2CPPMethods = [[NSMutableDictionary alloc] init];
    gHFAIL2CPPInstalledTargets = [[NSMutableArray alloc] init];
    gHFAIL2CPPInstalledSymbols = [[NSMutableArray alloc] init];
    gHFAIL2CPPDirectMethods = [[NSMutableDictionary alloc] init];
    gHFAIL2CPPCandidate = [candidate copy];
    gHFAIL2CPPStarted = HFANow();
    gHFAIL2CPPDuration = duration;
    gHFAIL2CPPStopStatus = nil;

    NSTimeInterval resolverDeadline = HFANow() + MIN(1.5, MAX(0.25, duration * 0.25));
    gHFAIL2CPPResolverEvidence = [HFAIL2CPPResolveInstrumentCandidates(
        candidate ?: @{}, resolverDeadline, kHFAIL2CPPMaxDirectInstruments) copy];
    NSUInteger directInstalled = 0;
    for (NSDictionary *methodCandidate in gHFAIL2CPPResolverEvidence[@"candidates"] ?: @[])
        if (HFAInstallDirectInstrument(methodCandidate)) ++directInstalled;

    NSUInteger apiHooksInstalled = 0;
    if (gHFAIL2CPPClassFromNameTarget && HFAInstallHook(gHFAIL2CPPClassFromNameTarget,
        (void *)&HFAClassFromNameReplacement,
        (void **)&gHFAIL2CPPClassFromNameOriginal, @"il2cpp_class_from_name")) ++apiHooksInstalled;
    if (gHFAIL2CPPClassGetMethodTarget && HFAInstallHook(gHFAIL2CPPClassGetMethodTarget,
        (void *)&HFAClassGetMethodReplacement,
        (void **)&gHFAIL2CPPClassGetMethodOriginal, @"il2cpp_class_get_method_from_name")) ++apiHooksInstalled;
    if (gHFAIL2CPPRuntimeInvokeTarget && HFAInstallHook(gHFAIL2CPPRuntimeInvokeTarget,
        (void *)&HFARuntimeInvokeReplacement,
        (void **)&gHFAIL2CPPRuntimeInvokeOriginal, @"il2cpp_runtime_invoke")) ++apiHooksInstalled;
    if (directInstalled || apiHooksInstalled) {
        gHFAIL2CPPArmed = YES;
        gHFAIL2CPPStopStatus = [@"armed" copy];
    } else {
        HFARemoveHooksLocked();
        gHFAIL2CPPStopStatus = [@"no-installable-il2cpp-observation-point" copy];
    }

    const char *dobbyVersionRaw = DobbyGetVersion();
    NSString *dobbyVersion = dobbyVersionRaw
        ? ([NSString stringWithUTF8String:dobbyVersionRaw] ?: @"unknown")
        : @"unknown";
    NSDictionary *result = @{
        @"schema": @"com.hfa.il2cpp-runtime-probe/v2",
        @"status": gHFAIL2CPPStopStatus ?: @"unknown",
        @"backend": @"embedded-dobby-instrument-reversible",
        @"dobbyVersion": dobbyVersion,
        @"durationSeconds": @(duration),
        @"directInstrumentCount": @(directInstalled),
        @"apiHookCount": @(apiHooksInstalled),
        @"installedSymbols": [NSArray arrayWithArray:gHFAIL2CPPInstalledSymbols],
        @"resolver": gHFAIL2CPPResolverEvidence ?: @{},
        @"exports": @{
            @"il2cpp_image_get_name": @(gHFAIL2CPPImageGetName != NULL),
            @"il2cpp_class_from_name": @(gHFAIL2CPPClassFromNameTarget != NULL),
            @"il2cpp_class_get_method_from_name": @(gHFAIL2CPPClassGetMethodTarget != NULL),
            @"il2cpp_runtime_invoke": @(gHFAIL2CPPRuntimeInvokeTarget != NULL)
        },
        @"classFromNameLocation": HFASymbolLocation(gHFAIL2CPPClassFromNameTarget),
        @"classGetMethodLocation": HFASymbolLocation(gHFAIL2CPPClassGetMethodTarget),
        @"runtimeInvokeLocation": HFASymbolLocation(gHFAIL2CPPRuntimeInvokeTarget),
        @"originalCallsContinue": @YES, @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"hookInstalled": @(gHFAIL2CPPInstalledTargets.count > 0),
        @"instrumentationCodeModifiedTemporarily": @(gHFAIL2CPPInstalledTargets.count > 0),
        @"gameStateWritten": @NO
    };
    pthread_mutex_unlock(&gHFAIL2CPPLock);
    HFADiagnosticsLog(@"il2cpp-runtime-probe", result[@"status"], result);
    return result;
}

void HFAIL2CPPRuntimeProbeMarkInteraction(NSString *label, NSString *controlToken) {
    if (!gHFAIL2CPPArmed) return;
    pthread_mutex_lock(&gHFAIL2CPPLock);
    if (gHFAIL2CPPArmed && gHFAIL2CPPInteractions.count < 64) {
        [gHFAIL2CPPInteractions addObject:@{
            @"time": @(HFANow()), @"label": label ?: @"",
            @"controlToken": controlToken ?: @""
        }];
    }
    pthread_mutex_unlock(&gHFAIL2CPPLock);
}

static NSArray *HFAEnrichedEventsLocked(void) {
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:gHFAIL2CPPEvents.count];
    for (NSDictionary *raw in gHFAIL2CPPEvents) {
        if (raw[@"nearInteraction"] || !gHFAIL2CPPInteractions.count) {
            [result addObject:raw];
            continue;
        }
        NSTimeInterval eventTime = [raw[@"time"] doubleValue];
        NSDictionary *nearest = nil;
        NSTimeInterval nearestDelta = DBL_MAX;
        for (NSDictionary *interaction in gHFAIL2CPPInteractions) {
            NSTimeInterval delta = fabs(eventTime - [interaction[@"time"] doubleValue]);
            if (delta < nearestDelta) { nearest = interaction; nearestDelta = delta; }
        }
        if (nearest && nearestDelta <= kHFAIL2CPPCorrelationWindow) {
            NSMutableDictionary *event = [raw mutableCopy];
            event[@"nearInteraction"] = nearest;
            event[@"interactionDeltaMs"] = @(nearestDelta * 1000.0);
            [result addObject:event];
            [event release];
        } else {
            [result addObject:raw];
        }
    }
    return result;
}

NSDictionary *HFAIL2CPPRuntimeProbeStop(NSString *reason) {
    pthread_mutex_lock(&gHFAIL2CPPLock);
    NSString *startStatus = [[gHFAIL2CPPStopStatus copy] autorelease] ?: @"not-armed";
    gHFAIL2CPPArmed = NO;
    NSArray *targetsToRestore = [gHFAIL2CPPInstalledTargets copy];
    [gHFAIL2CPPInstalledTargets removeAllObjects];
    pthread_mutex_unlock(&gHFAIL2CPPLock);
    NSUInteger restoreFailures = 0;
    for (NSValue *value in [targetsToRestore reverseObjectEnumerator])
        if (DobbyDestroy(value.pointerValue) != 0) ++restoreFailures;
    [targetsToRestore release];
    pthread_mutex_lock(&gHFAIL2CPPLock);
    gHFAIL2CPPClassFromNameOriginal = NULL;
    gHFAIL2CPPClassGetMethodOriginal = NULL;
    gHFAIL2CPPRuntimeInvokeOriginal = NULL;
    NSArray *events = HFAEnrichedEventsLocked();
    NSUInteger resolvedMethods = gHFAIL2CPPMethods.count;
    NSUInteger invokedMethods = 0, directEntries = 0, runtimeInvokes = 0;
    for (NSDictionary *event in events)
        if ([event[@"stage"] isEqualToString:@"runtime-invoke"] &&
            [event[@"resolutionStatus"] isEqualToString:@"resolved-method-invoked"]) {
            ++invokedMethods; ++runtimeInvokes;
        } else if ([event[@"stage"] isEqualToString:@"direct-method-entry"] &&
                   [event[@"resolutionStatus"] isEqualToString:@"resolved-method-entry-observed"]) {
            ++invokedMethods; ++directEntries;
        }
    NSDictionary *summary = @{
        @"schema": @"com.hfa.il2cpp-runtime-probe/v2",
        @"status": [startStatus isEqualToString:@"armed"] ? @"complete" : startStatus,
        @"reason": reason ?: @"stopped",
        @"candidateIdentity": gHFAIL2CPPCandidate ?: @{},
        @"durationMs": @((HFANow() - gHFAIL2CPPStarted) * 1000.0),
        @"requestedDurationSeconds": @(gHFAIL2CPPDuration),
        @"eventCount": @(events.count), @"resolvedMethodCount": @(resolvedMethods),
        @"observedInvocationCount": @(invokedMethods),
        @"directMethodEntryCount": @(directEntries), @"runtimeInvokeCount": @(runtimeInvokes),
        @"resolver": gHFAIL2CPPResolverEvidence ?: @{},
        @"interactions": gHFAIL2CPPInteractions ?: @[], @"events": events,
        @"classification": ![startStatus isEqualToString:@"armed"] ? startStatus :
            (invokedMethods ? @"runtime-method-call-observed" :
            (resolvedMethods ? @"method-resolved-invocation-not-observed" : @"no-method-chain")),
        @"originalCallsContinued": @YES,
        @"hookInstalled": @([startStatus isEqualToString:@"armed"]),
        @"instrumentationCodeModifiedTemporarily": @([startStatus isEqualToString:@"armed"]),
        @"hookRestoreFailureCount": @(restoreFailures),
        @"hooksRestored": @(restoreFailures == 0),
        @"gameStateWritten": @NO,
        @"analysisOnly": @YES, @"canonicalEligible": @NO,
        @"memoryWritten": @([startStatus isEqualToString:@"armed"])
    };
    [gHFAIL2CPPEvents release]; gHFAIL2CPPEvents = nil;
    [gHFAIL2CPPInteractions release]; gHFAIL2CPPInteractions = nil;
    [gHFAIL2CPPClasses release]; gHFAIL2CPPClasses = nil;
    [gHFAIL2CPPMethods release]; gHFAIL2CPPMethods = nil;
    [gHFAIL2CPPInstalledTargets release]; gHFAIL2CPPInstalledTargets = nil;
    [gHFAIL2CPPInstalledSymbols release]; gHFAIL2CPPInstalledSymbols = nil;
    [gHFAIL2CPPDirectMethods release]; gHFAIL2CPPDirectMethods = nil;
    [gHFAIL2CPPResolverEvidence release]; gHFAIL2CPPResolverEvidence = nil;
    [gHFAIL2CPPCandidate release]; gHFAIL2CPPCandidate = nil;
    [gHFAIL2CPPStopStatus release]; gHFAIL2CPPStopStatus = nil;
    pthread_mutex_unlock(&gHFAIL2CPPLock);
    HFADiagnosticsLog(@"il2cpp-runtime-probe", summary[@"status"], summary);
    return summary;
}
