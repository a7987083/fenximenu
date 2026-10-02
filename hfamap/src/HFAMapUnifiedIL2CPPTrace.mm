#import "HFAMapUnifiedIL2CPPTrace.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
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

static pthread_mutex_t gLock = PTHREAD_MUTEX_INITIALIZER;
static BOOL gArmed = NO;
static NSTimeInterval gStarted = 0;
static NSTimeInterval gDuration = 0;
static NSMutableArray *gEvents = nil;
static NSMutableArray *gInteractions = nil;
static HFARuntimeInvokeFn gRuntimeInvokeOriginal = NULL;
static void *gRuntimeInvokeTarget = NULL;
static HFADobbyHookFn gDobbyHook = NULL;
static HFADobbyDestroyFn gDobbyDestroy = NULL;
static HFAMethodGetNameFn gMethodGetName = NULL;
static HFAMethodGetClassFn gMethodGetClass = NULL;
static HFAClassGetNameFn gClassGetName = NULL;
static HFAClassGetNamespaceFn gClassGetNamespace = NULL;
static HFAClassGetImageFn gClassGetImage = NULL;
static HFAImageGetNameFn gImageGetName = NULL;
static HFAMethodGetParamCountFn gMethodGetParamCount = NULL;
static IMP gOriginalSendAction = NULL;

static NSString *HFAS(const char *s) { return (s && *s) ? ([NSString stringWithUTF8String:s] ?: @"") : @""; }
static NSString *HFAP(const void *p) { return [NSString stringWithFormat:@"0x%llX",(unsigned long long)(uintptr_t)p]; }
static NSTimeInterval HFANow(void) { return NSDate.date.timeIntervalSince1970; }

static NSString *HFAControlLabel(id sender) {
    if (!sender) return @"";
    @try {
        if ([sender respondsToSelector:@selector(currentTitle)]) {
            id v = [sender valueForKey:@"currentTitle"]; if ([v isKindOfClass:NSString.class] && [v length]) return v;
        }
        if ([sender respondsToSelector:@selector(accessibilityLabel)]) {
            NSString *v = [sender accessibilityLabel]; if (v.length) return v;
        }
        if ([sender respondsToSelector:@selector(text)]) {
            id v = [sender valueForKey:@"text"]; if ([v isKindOfClass:NSString.class] && [v length]) return v;
        }
    } @catch (__unused id e) {}
    return NSStringFromClass(object_getClass(sender)) ?: @"";
}

static NSDictionary *HFAResolveMethod(const void *method) {
    if (!method || !gMethodGetName || !gMethodGetClass) return @{};
    void *klass = gMethodGetClass(method);
    if (!klass) return @{};
    const void *image = gClassGetImage ? gClassGetImage(klass) : NULL;
    return @{
        @"methodInfo": HFAP(method),
        @"assembly": gImageGetName && image ? HFAS(gImageGetName(image)) : @"",
        @"namespace": gClassGetNamespace ? HFAS(gClassGetNamespace(klass)) : @"",
        @"class": gClassGetName ? HFAS(gClassGetName(klass)) : @"",
        @"method": HFAS(gMethodGetName(method)),
        @"parameterCount": gMethodGetParamCount ? @(gMethodGetParamCount(method)) : @(-1),
        @"resolutionStatus": @"runtime_verified_metadata"
    };
}

static NSDictionary *HFAPrecedingInteractionLocked(NSTimeInterval eventTime) {
    for (NSDictionary *it in [gInteractions reverseObjectEnumerator]) {
        NSTimeInterval t = [it[@"time"] doubleValue];
        if (t > eventTime) continue;
        NSTimeInterval delta = eventTime - t;
        if (delta <= 0.50) {
            NSMutableDictionary *m = [it mutableCopy];
            m[@"afterInteractionMs"] = @(delta * 1000.0);
            return [m autorelease];
        }
        break;
    }
    return nil;
}

static void HFAAppendInteraction(id sender, SEL action, id target) {
    if (!gArmed) return;
    NSTimeInterval now = HFANow();
    NSDictionary *record = @{
        @"time": @(now),
        @"elapsedMs": @((now-gStarted)*1000.0),
        @"label": HFAControlLabel(sender) ?: @"",
        @"senderClass": sender ? (NSStringFromClass(object_getClass(sender)) ?: @"") : @"",
        @"targetClass": target ? (NSStringFromClass(object_getClass(target)) ?: @"") : @"",
        @"selector": action ? (NSStringFromSelector(action) ?: @"") : @""
    };
    pthread_mutex_lock(&gLock);
    if (gArmed && gInteractions.count < 128) [gInteractions addObject:record];
    pthread_mutex_unlock(&gLock);
}

static BOOL HFAUIApplicationSendAction(id self, SEL _cmd, SEL action, id target, id sender, UIEvent *event) {
    HFAAppendInteraction(sender, action, target);
    typedef BOOL (*Fn)(id,SEL,SEL,id,id,UIEvent *);
    return ((Fn)gOriginalSendAction)(self,_cmd,action,target,sender,event);
}

static void *HFARuntimeInvokeReplacement(const void *method, void *object, void **arguments, void **exception) {
    NSTimeInterval now = HFANow();
    NSDictionary *meta = gArmed ? HFAResolveMethod(method) : nil;
    HFARuntimeInvokeFn original = gRuntimeInvokeOriginal;
    void *result = original ? original(method,object,arguments,exception) : NULL;
    if (gArmed) {
        pthread_mutex_lock(&gLock);
        if (gArmed && gEvents.count < 512) {
            NSMutableDictionary *e = [NSMutableDictionary dictionaryWithDictionary:meta ?: @{}];
            e[@"time"] = @(now);
            e[@"elapsedMs"] = @((now-gStarted)*1000.0);
            e[@"object"] = HFAP(object);
            e[@"result"] = HFAP(result);
            NSDictionary *it = HFAPrecedingInteractionLocked(now);
            if (it) e[@"interaction"] = it;
            e[@"correlation"] = it ? @"post-interaction-only" : @"uncorrelated";
            [gEvents addObject:e];
        }
        pthread_mutex_unlock(&gLock);
    }
    return result;
}

static NSString *HFARealMainExecutableName(void) {
    NSString *name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleExecutable"];
    if (![name isKindOfClass:NSString.class] || !name.length) name = NSBundle.mainBundle.executablePath.lastPathComponent;
    return name.length ? name : @"MainExecutable";
}

static void HFAWriteTrace(NSString *status) {
    NSArray *events=nil,*interactions=nil;
    pthread_mutex_lock(&gLock);
    events=[[gEvents copy] autorelease] ?: @[];
    interactions=[[gInteractions copy] autorelease] ?: @[];
    pthread_mutex_unlock(&gLock);
    NSMutableDictionary *counts=[NSMutableDictionary dictionary];
    for (NSDictionary *e in events) {
        if (![e[@"correlation"] isEqual:@"post-interaction-only"]) continue;
        NSString *key=[NSString stringWithFormat:@"%@|%@|%@",e[@"assembly"]?:@"",e[@"class"]?:@"",e[@"method"]?:@""];
        counts[key]=@([counts[key] unsignedIntegerValue]+1);
    }
    NSArray *sorted=[counts keysSortedByValueUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b){
        return [b compare:a];
    }];
    NSMutableArray *candidates=[NSMutableArray array];
    for (NSString *key in sorted) [candidates addObject:@{@"methodKey":key,@"postInteractionInvokeCount":counts[key]}];
    NSDictionary *root=@{
        @"schema":@"com.hfa.unified-il2cpp-feature-trace/v1",
        @"analyzer":@"HFAMapUniversal v1.9.37.11 UnifiedIL2CPPRuntimeResolver",
        @"status":status?:@"unknown",
        @"bundleIdentifier":NSBundle.mainBundle.bundleIdentifier?:@"",
        @"mainExecutable":HFARealMainExecutableName(),
        @"correlationRule":@"eventTime >= interactionTime && delta <= 500ms",
        @"futureInteractionAssociation":@NO,
        @"interactionCount":@(interactions.count),
        @"eventCount":@(events.count),
        @"interactions":interactions,
        @"events":events,
        @"postInteractionCandidates":candidates,
        @"analysisOnly":@YES
    };
    NSData *data=[NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    NSString *path=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_IL2CPPFeatureTrace.json"];
    [data writeToFile:path atomically:YES];
}

BOOL HFAUnifiedIL2CPPTraceIsArmed(void) { return gArmed; }

NSDictionary *HFAUnifiedIL2CPPTraceArm(NSTimeInterval duration) {
    pthread_mutex_lock(&gLock);
    if (gArmed) { pthread_mutex_unlock(&gLock); return @{@"status":@"busy"}; }
    gDobbyHook=(HFADobbyHookFn)dlsym(RTLD_DEFAULT,"DobbyHook");
    gDobbyDestroy=(HFADobbyDestroyFn)dlsym(RTLD_DEFAULT,"DobbyDestroy");
    gRuntimeInvokeTarget=dlsym(RTLD_DEFAULT,"il2cpp_runtime_invoke");
    gMethodGetName=(HFAMethodGetNameFn)dlsym(RTLD_DEFAULT,"il2cpp_method_get_name");
    gMethodGetClass=(HFAMethodGetClassFn)dlsym(RTLD_DEFAULT,"il2cpp_method_get_class");
    gClassGetName=(HFAClassGetNameFn)dlsym(RTLD_DEFAULT,"il2cpp_class_get_name");
    gClassGetNamespace=(HFAClassGetNamespaceFn)dlsym(RTLD_DEFAULT,"il2cpp_class_get_namespace");
    gClassGetImage=(HFAClassGetImageFn)dlsym(RTLD_DEFAULT,"il2cpp_class_get_image");
    gImageGetName=(HFAImageGetNameFn)dlsym(RTLD_DEFAULT,"il2cpp_image_get_name");
    gMethodGetParamCount=(HFAMethodGetParamCountFn)dlsym(RTLD_DEFAULT,"il2cpp_method_get_param_count");
    gEvents=[[NSMutableArray alloc] init];
    gInteractions=[[NSMutableArray alloc] init];
    gStarted=HFANow(); gDuration=duration>0?duration:8.0;
    BOOL ready=gDobbyHook&&gDobbyDestroy&&gRuntimeInvokeTarget&&gMethodGetName&&gMethodGetClass&&gClassGetName;
    if (!ready) { pthread_mutex_unlock(&gLock); HFAWriteTrace(@"required-runtime-api-unavailable"); return @{@"status":@"required-runtime-api-unavailable"}; }
    if (gDobbyHook(gRuntimeInvokeTarget,(void *)&HFARuntimeInvokeReplacement,(void **)&gRuntimeInvokeOriginal)!=0 || !gRuntimeInvokeOriginal) {
        pthread_mutex_unlock(&gLock); HFAWriteTrace(@"hook-install-failed"); return @{@"status":@"hook-install-failed"};
    }
    Method m=class_getInstanceMethod(UIApplication.class,@selector(sendAction:to:from:forEvent:));
    gOriginalSendAction=method_getImplementation(m);
    method_setImplementation(m,(IMP)HFAUIApplicationSendAction);
    gArmed=YES;
    pthread_mutex_unlock(&gLock);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(gDuration*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        if (gArmed) HFAUnifiedIL2CPPTraceStop(@"timeout");
    });
    return @{@"status":@"armed",@"durationSeconds":@(gDuration),@"mainExecutable":HFARealMainExecutableName()};
}

NSDictionary *HFAUnifiedIL2CPPTraceStop(NSString *reason) {
    pthread_mutex_lock(&gLock);
    BOOL was=gArmed; gArmed=NO;
    if (gOriginalSendAction) {
        Method m=class_getInstanceMethod(UIApplication.class,@selector(sendAction:to:from:forEvent:));
        method_setImplementation(m,gOriginalSendAction); gOriginalSendAction=NULL;
    }
    if (was && gDobbyDestroy && gRuntimeInvokeTarget) gDobbyDestroy(gRuntimeInvokeTarget);
    gRuntimeInvokeOriginal=NULL;
    pthread_mutex_unlock(&gLock);
    HFAWriteTrace(was?@"complete":@"not-armed");
    return @{@"status":was?@"complete":@"not-armed",@"reason":reason?:@"manual",@"file":@"HFAMap_IL2CPPFeatureTrace.json"};
}
