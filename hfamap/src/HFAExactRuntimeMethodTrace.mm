#import "HFAExactRuntimeMethodTrace.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>

typedef void *(*HFARuntimeInvokeFn)(const void *, void *, void **, void **);
typedef int (*HFADobbyHookFn)(void *, void *, void **);
typedef int (*HFADobbyDestroyFn)(void *);
typedef const char *(*HFAMethodGetNameFn)(const void *);
typedef void *(*HFAMethodGetClassFn)(const void *);
typedef const char *(*HFAClassGetNameFn)(void *);
typedef const char *(*HFAClassGetNamespaceFn)(void *);
typedef const void *(*HFAClassGetImageFn)(void *);
typedef const char *(*HFAImageGetNameFn)(const void *);
typedef uint32_t (*HFAMethodGetParamCountFn)(const void *);

static const NSUInteger kHFAMaxTraceEvents = 512;
static const NSUInteger kHFAMaxTraceInteractions = 64;
static const NSTimeInterval kHFAPostInteractionWindow = 0.50;

static pthread_mutex_t gHFATraceLock = PTHREAD_MUTEX_INITIALIZER;
static BOOL gHFATraceArmed = NO;
static NSTimeInterval gHFATraceStarted = 0;
static NSTimeInterval gHFATraceDuration = 0;
static NSMutableArray *gHFATraceEvents = nil;
static NSMutableArray *gHFATraceInteractions = nil;

static HFARuntimeInvokeFn gHFARuntimeInvokeOriginal = NULL;
static void *gHFARuntimeInvokeTarget = NULL;
static HFADobbyHookFn gHFADobbyHook = NULL;
static HFADobbyDestroyFn gHFADobbyDestroy = NULL;
static HFAMethodGetNameFn gHFAMethodGetName = NULL;
static HFAMethodGetClassFn gHFAMethodGetClass = NULL;
static HFAClassGetNameFn gHFAClassGetName = NULL;
static HFAClassGetNamespaceFn gHFAClassGetNamespace = NULL;
static HFAClassGetImageFn gHFAClassGetImage = NULL;
static HFAImageGetNameFn gHFAImageGetName = NULL;
static HFAMethodGetParamCountFn gHFAMethodGetParamCount = NULL;

static NSTimeInterval HFATraceNow(void) { return NSDate.date.timeIntervalSince1970; }
static NSString *HFATracePointer(const void *p) {
    return [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)p];
}
static NSString *HFATraceCString(const char *s) {
    return (s && *s) ? ([NSString stringWithUTF8String:s] ?: @"") : @"";
}
static NSString *HFATraceMainExecutable(void) {
    NSString *name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    if (![name isKindOfClass:NSString.class] || !name.length)
        name = NSBundle.mainBundle.executablePath.lastPathComponent;
    return name.length ? name : @"MainExecutable";
}

static NSDictionary *HFATraceMethod(const void *method) {
    if (!method || !gHFAMethodGetName || !gHFAMethodGetClass) return @{};
    void *klass = gHFAMethodGetClass(method);
    if (!klass) return @{};
    const void *image = gHFAClassGetImage ? gHFAClassGetImage(klass) : NULL;
    NSString *methodName = HFATraceCString(gHFAMethodGetName(method));
    NSString *className = gHFAClassGetName ? HFATraceCString(gHFAClassGetName(klass)) : @"";
    NSString *nameSpace = gHFAClassGetNamespace ? HFATraceCString(gHFAClassGetNamespace(klass)) : @"";
    NSString *assembly = (gHFAImageGetName && image) ? HFATraceCString(gHFAImageGetName(image)) : @"";
    return @{
        @"methodInfoToken": HFATracePointer(method),
        @"assembly": assembly ?: @"",
        @"namespace": nameSpace ?: @"",
        @"class": className ?: @"",
        @"method": methodName ?: @"",
        @"parameterCount": gHFAMethodGetParamCount ? @(gHFAMethodGetParamCount(method)) : @(-1),
        @"resolutionStatus": @"runtime-verified-methodinfo"
    };
}

static NSDictionary *HFATracePrecedingInteractionLocked(NSTimeInterval eventTime) {
    for (NSDictionary *interaction in [gHFATraceInteractions reverseObjectEnumerator]) {
        NSTimeInterval interactionTime = [interaction[@"time"] doubleValue];
        if (interactionTime > eventTime) continue;
        NSTimeInterval delta = eventTime - interactionTime;
        if (delta <= kHFAPostInteractionWindow) {
            NSMutableDictionary *copy = [[interaction mutableCopy] autorelease];
            copy[@"afterInteractionMs"] = @(delta * 1000.0);
            return copy;
        }
        break;
    }
    return nil;
}

static void *HFATraceRuntimeInvoke(const void *method, void *object, void **arguments, void **exception) {
    NSTimeInterval now = HFATraceNow();
    NSDictionary *metadata = gHFATraceArmed ? HFATraceMethod(method) : nil;
    HFARuntimeInvokeFn original = gHFARuntimeInvokeOriginal;
    void *result = original ? original(method, object, arguments, exception) : NULL;

    if (gHFATraceArmed) {
        pthread_mutex_lock(&gHFATraceLock);
        if (gHFATraceArmed && gHFATraceEvents.count < kHFAMaxTraceEvents) {
            NSDictionary *interaction = HFATracePrecedingInteractionLocked(now);
            if (interaction) {
                NSMutableDictionary *event = [NSMutableDictionary dictionaryWithDictionary:metadata ?: @{}];
                event[@"time"] = @(now);
                event[@"elapsedMs"] = @((now - gHFATraceStarted) * 1000.0);
                event[@"interaction"] = interaction;
                event[@"correlationRule"] = @"eventTime>=interactionTime&&delta<=500ms";
                event[@"futureInteractionAssociation"] = @NO;
                event[@"objectToken"] = HFATracePointer(object);
                event[@"argumentsToken"] = HFATracePointer(arguments);
                event[@"resultToken"] = HFATracePointer(result);
                event[@"exceptionToken"] = HFATracePointer(exception ? *exception : NULL);
                [gHFATraceEvents addObject:event];
            }
        }
        pthread_mutex_unlock(&gHFATraceLock);
    }
    return result;
}

BOOL HFAExactRuntimeMethodTraceIsArmed(void) {
    pthread_mutex_lock(&gHFATraceLock);
    BOOL armed = gHFATraceArmed;
    pthread_mutex_unlock(&gHFATraceLock);
    return armed;
}

NSDictionary *HFAExactRuntimeMethodTraceArm(NSTimeInterval duration) {
    pthread_mutex_lock(&gHFATraceLock);
    if (gHFATraceArmed) {
        pthread_mutex_unlock(&gHFATraceLock);
        return @{@"status": @"busy"};
    }

    gHFADobbyHook = (HFADobbyHookFn)dlsym(RTLD_DEFAULT, "DobbyHook");
    gHFADobbyDestroy = (HFADobbyDestroyFn)dlsym(RTLD_DEFAULT, "DobbyDestroy");
    gHFARuntimeInvokeTarget = dlsym(RTLD_DEFAULT, "il2cpp_runtime_invoke");
    gHFAMethodGetName = (HFAMethodGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_name");
    gHFAMethodGetClass = (HFAMethodGetClassFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_class");
    gHFAClassGetName = (HFAClassGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_name");
    gHFAClassGetNamespace = (HFAClassGetNamespaceFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_namespace");
    gHFAClassGetImage = (HFAClassGetImageFn)dlsym(RTLD_DEFAULT, "il2cpp_class_get_image");
    gHFAImageGetName = (HFAImageGetNameFn)dlsym(RTLD_DEFAULT, "il2cpp_image_get_name");
    gHFAMethodGetParamCount = (HFAMethodGetParamCountFn)dlsym(RTLD_DEFAULT, "il2cpp_method_get_param_count");

    BOOL ready = gHFADobbyHook && gHFADobbyDestroy && gHFARuntimeInvokeTarget &&
                 gHFAMethodGetName && gHFAMethodGetClass && gHFAClassGetName;
    if (!ready) {
        pthread_mutex_unlock(&gHFATraceLock);
        return @{
            @"status": @"unavailable",
            @"reason": @"required-dobby-or-il2cpp-exports-missing",
            @"mainExecutable": HFATraceMainExecutable(),
            @"hookInstalled": @NO,
            @"gameStateWritten": @NO
        };
    }

    gHFATraceEvents = [[NSMutableArray alloc] init];
    gHFATraceInteractions = [[NSMutableArray alloc] init];
    gHFATraceStarted = HFATraceNow();
    gHFATraceDuration = duration > 0 ? duration : 8.0;
    int hookResult = gHFADobbyHook(gHFARuntimeInvokeTarget, (void *)&HFATraceRuntimeInvoke,
                                   (void **)&gHFARuntimeInvokeOriginal);
    if (hookResult != 0 || !gHFARuntimeInvokeOriginal) {
        [gHFATraceEvents release]; gHFATraceEvents = nil;
        [gHFATraceInteractions release]; gHFATraceInteractions = nil;
        pthread_mutex_unlock(&gHFATraceLock);
        return @{
            @"status": @"hook-install-failed",
            @"mainExecutable": HFATraceMainExecutable(),
            @"hookInstalled": @NO,
            @"gameStateWritten": @NO
        };
    }
    gHFATraceArmed = YES;
    pthread_mutex_unlock(&gHFATraceLock);

    NSDictionary *result = @{
        @"schema": @"com.hfa.exact-runtime-method-trace/v1",
        @"version": @"2.5.23-dev-exact-runtime-method-trace",
        @"status": @"armed",
        @"durationSeconds": @(gHFATraceDuration),
        @"mainExecutable": HFATraceMainExecutable(),
        @"targetImageAliasPolicy": @"real-CFBundleExecutable-never-@main",
        @"correlationWindowMs": @500,
        @"futureInteractionAssociation": @NO,
        @"hookInstalled": @YES,
        @"instrumentationCodeModifiedTemporarily": @YES,
        @"gameStateWritten": @NO,
        @"analysisOnly": @YES
    };
    HFADiagnosticsLog(@"exact-runtime-method-trace", @"armed", result);
    return result;
}

void HFAExactRuntimeMethodTraceMarkInteraction(NSString *label, NSString *controlToken) {
    pthread_mutex_lock(&gHFATraceLock);
    if (gHFATraceArmed && gHFATraceInteractions.count < kHFAMaxTraceInteractions) {
        [gHFATraceInteractions addObject:@{
            @"time": @(HFATraceNow()),
            @"label": label ?: @"",
            @"controlToken": controlToken ?: @""
        }];
    }
    pthread_mutex_unlock(&gHFATraceLock);
}

NSDictionary *HFAExactRuntimeMethodTraceStop(NSString *reason) {
    pthread_mutex_lock(&gHFATraceLock);
    BOOL wasArmed = gHFATraceArmed;
    gHFATraceArmed = NO;
    NSArray *events = [gHFATraceEvents copy] ?: @[];
    NSArray *interactions = [gHFATraceInteractions copy] ?: @[];
    NSTimeInterval started = gHFATraceStarted;
    NSTimeInterval requested = gHFATraceDuration;
    pthread_mutex_unlock(&gHFATraceLock);

    NSUInteger restoreFailures = 0;
    if (wasArmed && gHFADobbyDestroy && gHFARuntimeInvokeTarget) {
        if (gHFADobbyDestroy(gHFARuntimeInvokeTarget) != 0) restoreFailures = 1;
    }

    NSMutableDictionary *counts = [NSMutableDictionary dictionary];
    for (NSDictionary *event in events) {
        NSString *key = [NSString stringWithFormat:@"%@|%@|%@|%@",
                         event[@"assembly"] ?: @"",
                         event[@"namespace"] ?: @"",
                         event[@"class"] ?: @"",
                         event[@"method"] ?: @""];
        if (!key.length) continue;
        counts[key] = @([counts[key] unsignedIntegerValue] + 1);
    }
    NSArray *sortedKeys = [counts keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        return [b compare:a];
    }];
    NSMutableArray *candidates = [NSMutableArray array];
    for (NSString *key in sortedKeys)
        [candidates addObject:@{@"methodKey": key, @"postInteractionInvokeCount": counts[key]}];

    NSDictionary *summary = @{
        @"schema": @"com.hfa.exact-runtime-method-trace/v1",
        @"version": @"2.5.23-dev-exact-runtime-method-trace",
        @"status": wasArmed ? @"complete" : @"not-armed",
        @"reason": reason ?: @"stopped",
        @"mainExecutable": HFATraceMainExecutable(),
        @"targetImageAliasPolicy": @"real-CFBundleExecutable-never-@main",
        @"durationMs": @((HFATraceNow() - started) * 1000.0),
        @"requestedDurationSeconds": @(requested),
        @"interactionCount": @(interactions.count),
        @"eventCount": @(events.count),
        @"interactions": interactions,
        @"events": events,
        @"postInteractionCandidates": candidates,
        @"correlationRule": @"eventTime>=interactionTime&&delta<=500ms",
        @"futureInteractionAssociation": @NO,
        @"hookInstalled": @(wasArmed),
        @"hooksRestored": @(restoreFailures == 0),
        @"hookRestoreFailureCount": @(restoreFailures),
        @"instrumentationCodeModifiedTemporarily": @(wasArmed),
        @"gameStateWritten": @NO,
        @"analysisOnly": @YES
    };

    NSData *json = [NSJSONSerialization dataWithJSONObject:summary options:NSJSONWritingPrettyPrinted error:nil];
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"ExactRuntimeMethods.json")];
    [json writeToFile:path atomically:YES];

    pthread_mutex_lock(&gHFATraceLock);
    [gHFATraceEvents release]; gHFATraceEvents = nil;
    [gHFATraceInteractions release]; gHFATraceInteractions = nil;
    gHFARuntimeInvokeOriginal = NULL;
    gHFARuntimeInvokeTarget = NULL;
    gHFATraceStarted = 0;
    gHFATraceDuration = 0;
    pthread_mutex_unlock(&gHFATraceLock);

    [events release];
    [interactions release];
    HFADiagnosticsLog(@"exact-runtime-method-trace", summary[@"status"], summary);
    return summary;
}
