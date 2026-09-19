#import "ZPFeatureResolver.h"
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <pthread.h>

static pthread_mutex_t gZPFeatureLock=PTHREAD_MUTEX_INITIALIZER;
static NSMutableDictionary<NSString*,NSDictionary*> *gZPFeatures;

static NSString *ZPStringGetter(id object,const char *name){
    if(!object||!name)return nil; SEL sel=sel_registerName(name); Method m=class_getInstanceMethod(object_getClass(object),sel); if(!m)return nil;
    char *ret=method_copyReturnType(m); BOOL ok=ret&&ret[0]=='@'; free(ret); if(!ok)return nil;
    @try{ id v=((id(*)(id,SEL))objc_msgSend)(object,sel); if([v isKindOfClass:[NSString class]])return v; if([v isKindOfClass:[NSNumber class]])return [(NSNumber*)v stringValue]; }@catch(__unused id e){} return nil;
}
static NSString *ZPLabel(id object){
    NSString *s=ZPStringGetter(object,"currentTitle"); if(s.length)return s;
    s=ZPStringGetter(object,"text"); if(s.length)return s;
    s=ZPStringGetter(object,"accessibilityLabel"); if(s.length)return s;
    @try{ if([object respondsToSelector:@selector(titleLabel)]){ id l=((id(*)(id,SEL))objc_msgSend)(object,@selector(titleLabel)); s=ZPStringGetter(l,"text"); if(s.length)return s; } }@catch(__unused id e){}
    return nil;
}
static void ZPRegisterRanked(NSDictionary *record){
    NSString *identifier=record[@"identifier"]; if(!identifier.length)return;
    NSInteger rank=[record[@"evidenceRank"] integerValue];
    pthread_mutex_lock(&gZPFeatureLock); if(!gZPFeatures)gZPFeatures=[NSMutableDictionary dictionary]; NSDictionary *old=gZPFeatures[identifier]; if(!old||rank>=[old[@"evidenceRank"] integerValue])gZPFeatures[identifier]=record; pthread_mutex_unlock(&gZPFeatureLock);
}
static void ZPRegister(NSString *identifier,NSString *label,NSString *source,NSString *className,NSInteger rank){
    if(!identifier.length||!label.length)return; ZPRegisterRanked(@{@"identifier":identifier,@"label":label,@"key":[identifier hasSuffix:@"-switch"]?identifier:[identifier stringByAppendingString:@"-switch"],@"source":source?:@"?",@"class":className?:@"?",@"evidenceRank":@(rank)});
}
static void ZPInspectControl(UIControl *control){
    NSString *label=ZPLabel(control); if(!label.length)return;
    NSString *identifier=ZPStringGetter(control,"identifier"); if(identifier.length)ZPRegister(identifier,label,@"control",NSStringFromClass(object_getClass(control)),30);
    NSSet *targets=control.allTargets; NSUInteger seen=0;
    for(id target in targets){ if(++seen>64)break; NSString *tid=ZPStringGetter(target,"identifier"); if(tid.length)ZPRegister(tid,label,@"control-target",NSStringFromClass(object_getClass(target)),20); }
}
static void ZPWalk(UIView *view,NSUInteger depth,NSMutableSet<NSValue*> *seen){
    if(!view||depth>24||seen.count>4096)return; NSValue *k=[NSValue valueWithPointer:(__bridge const void*)view]; if([seen containsObject:k])return; [seen addObject:k];
    if([view isKindOfClass:[UIControl class]])ZPInspectControl((UIControl*)view);
    NSArray *subs=view.subviews; NSUInteger n=MIN(subs.count,(NSUInteger)512); for(NSUInteger i=0;i<n;i++)ZPWalk(subs[i],depth+1,seen);
}
void ZPFeatureResolverReset(void){ pthread_mutex_lock(&gZPFeatureLock); gZPFeatures=[NSMutableDictionary dictionary]; pthread_mutex_unlock(&gZPFeatureLock); }
NSArray<NSDictionary*> *ZPFeatureResolverCollect(void){
    NSCAssert(NSThread.isMainThread,@"ZPFeatureResolverCollect must run on main thread"); ZPFeatureResolverReset(); NSMutableSet *seen=[NSMutableSet set]; NSArray *windows=UIApplication.sharedApplication.windows?:@[]; NSUInteger n=MIN(windows.count,(NSUInteger)32); for(NSUInteger i=0;i<n;i++)ZPWalk(windows[i],0,seen);
    pthread_mutex_lock(&gZPFeatureLock); NSArray *out=[gZPFeatures.allValues copy]?:@[]; pthread_mutex_unlock(&gZPFeatureLock); return [out sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){return [a[@"identifier"] compare:b[@"identifier"] options:NSNumericSearch];}];
}
void ZPFeatureResolverMergeContainerFeatures(NSArray<NSDictionary*> *features){for(NSDictionary *f in features)if([f isKindOfClass:NSDictionary.class])ZPRegisterRanked(f);}
NSDictionary *ZPFeatureForIdentifier(NSString *identifier){ if(!identifier.length)return nil; pthread_mutex_lock(&gZPFeatureLock); NSDictionary *r=[gZPFeatures[identifier] copy]; pthread_mutex_unlock(&gZPFeatureLock); return r; }
