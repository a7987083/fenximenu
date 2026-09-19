#import "ZPDescriptorObserver.h"
#import "ZPAppIdentity.h"
#import "HFAMapDiagnostics.h"
#import <objc/message.h>
#import <objc/runtime.h>
#include <pthread.h>

static pthread_mutex_t gZPObserverLock = PTHREAD_MUTEX_INITIALIZER;
static Class gZPObservedClass;
static NSString *gZPObservedImage;
static NSTimeInterval gZPObserverDeadline;
static NSUInteger gZPObservedEventCount;
static IMP gOrigIdentifier, gOrigOffset, gOrigSignature, gOrigRange, gOrigActive;
static const NSUInteger kZPMaxObserverEvents = 512;

static NSString *ZPDocs(void) { return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject]; }
static NSString *ZPPtr(const void *p) { return [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)p]; }

static NSDictionary *ZPObjectEvidence(id value) {
    if (!value) return @{ @"kind": @"nil" };
    NSMutableDictionary *d = [@{ @"kind": @"object", @"class": NSStringFromClass(object_getClass(value)) ?: @"?", @"pointer": ZPPtr((__bridge const void *)value) } mutableCopy];
    if ([value isKindOfClass:[NSString class]]) d[@"string"] = value;
    else if ([value isKindOfClass:[NSNumber class]]) d[@"number"] = value;
    return d;
}

static id ZPObjectGetter(id object, const char *name) {
    if (!object || !name) return nil;
    SEL sel = sel_registerName(name); Method m = class_getInstanceMethod(object_getClass(object), sel); if (!m) return nil;
    char *ret = method_copyReturnType(m); BOOL ok = ret && ret[0] == '@'; free(ret); if (!ok) return nil;
    @try { return ((id(*)(id,SEL))objc_msgSend)(object, sel); } @catch (__unused id e) { return nil; }
}
static NSNumber *ZPU64Getter(id object, const char *name) {
    SEL sel=sel_registerName(name); Method m=class_getInstanceMethod(object_getClass(object),sel); if(!m)return nil;
    char *ret=method_copyReturnType(m); BOOL ok=ret && (ret[0]=='Q'||ret[0]=='q'||ret[0]=='L'||ret[0]=='l'||ret[0]=='I'||ret[0]=='i'); free(ret); if(!ok)return nil;
    @try { return @(((uint64_t(*)(id,SEL))objc_msgSend)(object,sel)); } @catch(__unused id e){ return nil; }
}
static NSNumber *ZPBoolGetter(id object, const char *name) {
    SEL sel=sel_registerName(name); Method m=class_getInstanceMethod(object_getClass(object),sel); if(!m)return nil;
    char *ret=method_copyReturnType(m); BOOL ok=ret && (ret[0]=='B'||ret[0]=='c'); free(ret); if(!ok)return nil;
    @try { return @(((BOOL(*)(id,SEL))objc_msgSend)(object,sel)); } @catch(__unused id e){ return nil; }
}

static NSDictionary *ZPSnapshot(id object) {
    NSMutableDictionary *d=[NSMutableDictionary dictionary];
    id identifier=ZPObjectGetter(object,"identifier"); if(identifier)d[@"identifier"]=ZPObjectEvidence(identifier);
    id offset=ZPObjectGetter(object,"offset"); if(offset)d[@"offset"]=ZPObjectEvidence(offset);
    id signature=ZPObjectGetter(object,"signature"); if(signature)d[@"signature"]=ZPObjectEvidence(signature);
    NSNumber *range=ZPU64Getter(object,"range"); if(range)d[@"range"]=range;
    NSNumber *active=ZPBoolGetter(object,"active"); if(active)d[@"active"]=active;
    return d;
}

static BOOL ZPObserverTakeEventSlot(void) {
    pthread_mutex_lock(&gZPObserverLock);
    BOOL armed = gZPObservedClass && NSDate.date.timeIntervalSince1970 <= gZPObserverDeadline;
    BOOL allowed = armed && gZPObservedEventCount < kZPMaxObserverEvents;
    if (allowed) gZPObservedEventCount++;
    pthread_mutex_unlock(&gZPObserverLock);
    return allowed;
}

// Hot-path rule (v0.2.1): once an observed setter fires, do not re-enter the
// diagnostic subsystem and do not mutate a shared Foundation collection.
// Device logs from v0.2.0 proved DescriptorEvents.jsonl was written before the
// crash, while the subsequent descriptor-observer/event diagnostic was absent.
static void ZPAppendEvent(id object, SEL selector, NSDictionary *input) {
    if (!object || !selector) return;
    pthread_mutex_lock(&gZPObserverLock);
    BOOL classOK = gZPObservedClass && object_getClass(object) == gZPObservedClass;
    NSString *image = [gZPObservedImage copy];
    pthread_mutex_unlock(&gZPObserverLock);
    if (!classOK || !ZPObserverTakeEventSlot()) return;

    NSDictionary *event=@{
        @"schema":@"com.hfa.zpatchig.descriptor-event/v2",
        @"time":@(NSDate.date.timeIntervalSince1970),
        @"appIdentity":ZPAppIdentity(),
        @"image":image?:@"?",
        @"class":NSStringFromClass(object_getClass(object))?:@"?",
        @"descriptor":ZPPtr((__bridge const void *)object),
        @"selector":NSStringFromSelector(selector),
        @"input":input?:@{},
        @"snapshot":ZPSnapshot(object)?:@{}
    };
    NSData *line=[NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
    if(!line) return;
    NSMutableData *out=[line mutableCopy]; [out appendBytes:"\n" length:1];
    NSString *path=[ZPDocs() stringByAppendingPathComponent:ZPLogFilename(@"DescriptorEvents.jsonl")];
    NSFileManager *fm=NSFileManager.defaultManager;
    if(![fm fileExistsAtPath:path])[fm createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *h=[NSFileHandle fileHandleForWritingAtPath:path];
    @try { [h seekToEndOfFile]; [h writeData:out]; [h closeFile]; } @catch(__unused id e) {}
}

static IMP ZPOriginalForSelector(SEL sel) {
    if(sel_isEqual(sel,sel_registerName("setIdentifier:")))return gOrigIdentifier;
    if(sel_isEqual(sel,sel_registerName("setOffset:")))return gOrigOffset;
    if(sel_isEqual(sel,sel_registerName("setSignature:")))return gOrigSignature;
    if(sel_isEqual(sel,sel_registerName("setRange:")))return gOrigRange;
    if(sel_isEqual(sel,sel_registerName("setActive:")))return gOrigActive;
    return NULL;
}
static void ZPHookObject(id self, SEL _cmd, id value){ IMP orig=ZPOriginalForSelector(_cmd); if(orig)((void(*)(id,SEL,id))orig)(self,_cmd,value); ZPAppendEvent(self,_cmd,ZPObjectEvidence(value)); }
static void ZPHookU64(id self, SEL _cmd, uint64_t value){ IMP orig=ZPOriginalForSelector(_cmd); if(orig)((void(*)(id,SEL,uint64_t))orig)(self,_cmd,value); ZPAppendEvent(self,_cmd,@{ @"kind":@"u64",@"value":@(value) }); }
static void ZPHookBool(id self, SEL _cmd, BOOL value){ IMP orig=ZPOriginalForSelector(_cmd); if(orig)((void(*)(id,SEL,BOOL))orig)(self,_cmd,value); ZPAppendEvent(self,_cmd,@{ @"kind":@"bool",@"value":@(value) }); }

static Method ZPDirectMethod(Class cls, SEL sel) {
    unsigned count=0; Method *list=class_copyMethodList(cls,&count); Method found=NULL;
    for(unsigned i=0; list && i<count; ++i) if(sel_isEqual(method_getName(list[i]),sel)){ found=list[i]; break; }
    free(list); return found;
}

static BOOL ZPHookSetter(Class cls, const char *name, IMP replacement, IMP *slot, NSString **why, NSString **encodingOut) {
    SEL sel=sel_registerName(name);
    Method m=ZPDirectMethod(cls,sel);
    if(!m){if(why)*why=@"not-directly-implemented";return NO;}
    const char *encoding=method_getTypeEncoding(m);
    if(encodingOut)*encodingOut=encoding?[NSString stringWithUTF8String:encoding]:@"?";
    char *ret=method_copyReturnType(m); char rc=ret?ret[0]:'?'; free(ret);
    if(rc!='v'){if(why)*why=[NSString stringWithFormat:@"unsupported-return-%c",rc];return NO;}
    unsigned argc=method_getNumberOfArguments(m); if(argc!=3){if(why)*why=[NSString stringWithFormat:@"bad-arity-%u",argc];return NO;}
    char *arg=method_copyArgumentType(m,2); char c=arg?arg[0]:'?'; free(arg);
    if(replacement==(IMP)ZPHookObject && c!='@'){if(why)*why=[NSString stringWithFormat:@"unsupported-arg-%c",c];return NO;}
    if(replacement==(IMP)ZPHookU64 && !(c=='Q'||c=='q'||c=='L'||c=='l'||c=='I'||c=='i')){if(why)*why=[NSString stringWithFormat:@"unsupported-arg-%c",c];return NO;}
    if(replacement==(IMP)ZPHookBool && !(c=='B'||c=='c')){if(why)*why=[NSString stringWithFormat:@"unsupported-arg-%c",c];return NO;}
    IMP current=method_getImplementation(m); if(!current||current==replacement){if(why)*why=@"already-hooked-or-null";return NO;}
    *slot=current; method_setImplementation(m,replacement); return YES;
}

static void ZPRestoreSetter(Class cls,const char *name,IMP replacement,IMP orig){
    if(!cls||!orig)return; Method m=ZPDirectMethod(cls,sel_registerName(name)); if(!m)return;
    if(method_getImplementation(m)==replacement)method_setImplementation(m,orig);
}

void ZPDescriptorObserverDisarm(NSString *reason) {
    pthread_mutex_lock(&gZPObserverLock); Class cls=gZPObservedClass; NSUInteger eventCount=gZPObservedEventCount; gZPObservedClass=Nil; gZPObserverDeadline=0; pthread_mutex_unlock(&gZPObserverLock);
    if(!cls)return;
    ZPRestoreSetter(cls,"setIdentifier:",(IMP)ZPHookObject,gOrigIdentifier); ZPRestoreSetter(cls,"setOffset:",(IMP)ZPHookObject,gOrigOffset); ZPRestoreSetter(cls,"setSignature:",(IMP)ZPHookObject,gOrigSignature); ZPRestoreSetter(cls,"setRange:",(IMP)ZPHookU64,gOrigRange); ZPRestoreSetter(cls,"setActive:",(IMP)ZPHookBool,gOrigActive);
    HFADiagnosticsLog(@"descriptor-observer",@"disarmed",@{ @"reason":reason?:@"manual", @"class":NSStringFromClass(cls)?:@"?", @"eventCount":@(eventCount) });
}

NSDictionary *ZPDescriptorObserverArm(NSDictionary *candidate, NSDictionary *descriptor, NSTimeInterval duration) {
    ZPDescriptorObserverDisarm(@"rearm");
    NSString *className=descriptor[@"class"] ?: candidate[@"descriptorClass"]; Class cls=className.length?objc_getClass(className.UTF8String):Nil;
    if(!cls||class_getInstanceSize(cls)!=0xA0)return @{ @"status":@"not-armed",@"reason":@"descriptor-class-missing" };
    const char *classPath=class_getImageName(cls); NSString *expected=candidate[@"path"]?:@""; NSString *actual=classPath?[NSString stringWithUTF8String:classPath]:@"";
    if(expected.length && actual.length && ![expected isEqualToString:actual])return @{ @"status":@"not-armed",@"reason":@"descriptor-image-mismatch",@"actualImage":actual };
    duration=MAX(1.0,MIN(duration,30.0)); NSMutableArray *hooked=[NSMutableArray array]; NSMutableDictionary *skipped=[NSMutableDictionary dictionary]; NSMutableDictionary *encodings=[NSMutableDictionary dictionary]; NSString *why=nil,*enc=nil;
    if(ZPHookSetter(cls,"setIdentifier:",(IMP)ZPHookObject,&gOrigIdentifier,&why,&enc))[hooked addObject:@"setIdentifier:"]; else if(why)skipped[@"setIdentifier:"]=why; if(enc)encodings[@"setIdentifier:"]=enc; why=nil;enc=nil;
    if(ZPHookSetter(cls,"setOffset:",(IMP)ZPHookObject,&gOrigOffset,&why,&enc))[hooked addObject:@"setOffset:"]; else if(why)skipped[@"setOffset:"]=why; if(enc)encodings[@"setOffset:"]=enc; why=nil;enc=nil;
    if(ZPHookSetter(cls,"setSignature:",(IMP)ZPHookObject,&gOrigSignature,&why,&enc))[hooked addObject:@"setSignature:"]; else if(why)skipped[@"setSignature:"]=why; if(enc)encodings[@"setSignature:"]=enc; why=nil;enc=nil;
    if(ZPHookSetter(cls,"setRange:",(IMP)ZPHookU64,&gOrigRange,&why,&enc))[hooked addObject:@"setRange:"]; else if(why)skipped[@"setRange:"]=why; if(enc)encodings[@"setRange:"]=enc; why=nil;enc=nil;
    if(ZPHookSetter(cls,"setActive:",(IMP)ZPHookBool,&gOrigActive,&why,&enc))[hooked addObject:@"setActive:"]; else if(why)skipped[@"setActive:"]=why; if(enc)encodings[@"setActive:"]=enc;
    if(!hooked.count)return @{ @"status":@"not-armed",@"reason":@"no-supported-direct-setters",@"skipped":skipped,@"methodEncodings":encodings };
    pthread_mutex_lock(&gZPObserverLock); gZPObservedClass=cls; gZPObservedImage=[candidate[@"image"] copy]; gZPObserverDeadline=NSDate.date.timeIntervalSince1970+duration; gZPObservedEventCount=0; pthread_mutex_unlock(&gZPObserverLock);
    NSDictionary *result=@{ @"status":@"armed",@"class":className,@"image":candidate[@"image"]?:@"?",@"durationMs":@((NSUInteger)(duration*1000.0)),@"hookedSetters":hooked,@"skippedSetters":skipped,@"methodEncodings":encodings,@"logFile":ZPLogFilename(@"DescriptorEvents.jsonl") };
    HFADiagnosticsLog(@"descriptor-observer",@"armed",result);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(duration*NSEC_PER_SEC)),dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{ ZPDescriptorObserverDisarm(@"window-expired"); });
    return result;
}

NSDictionary *ZPDescriptorObserverStatus(void) {
    pthread_mutex_lock(&gZPObserverLock); BOOL armed=gZPObservedClass && NSDate.date.timeIntervalSince1970<=gZPObserverDeadline; NSDictionary *d=@{ @"armed":@(armed),@"class":gZPObservedClass?NSStringFromClass(gZPObservedClass):@"",@"image":gZPObservedImage?:@"",@"eventCount":@(gZPObservedEventCount),@"deadline":@(gZPObserverDeadline) }; pthread_mutex_unlock(&gZPObserverLock); return d;
}
