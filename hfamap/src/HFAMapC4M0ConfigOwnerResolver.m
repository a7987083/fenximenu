#import "HFAMapC4M0ConfigOwnerResolver.h"
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

static NSDictionary *gStatus;

static NSString *HFABaseName(const char *path){
    if(!path)return @"?";const char *s=strrchr(path,'/');return [NSString stringWithUTF8String:(s?s+1:path)]?:@"?";
}

static BOOL HFAPathIsAppLocal(const char *path){
    if(!path)return NO;NSString *p=[NSString stringWithUTF8String:path];NSString *home=NSHomeDirectory();
    return [p hasPrefix:home] || [p containsString:@"/Bundle/Application/"];
}

static NSDictionary *HFAIMPInfo(IMP imp){
    if(!imp)return nil;Dl_info di={0};if(!dladdr((const void*)imp,&di)||!di.dli_fbase||!di.dli_fname)return nil;
    uintptr_t a=(uintptr_t)imp,b=(uintptr_t)di.dli_fbase;
    return @{@"image":HFABaseName(di.dli_fname),@"path":[NSString stringWithUTF8String:di.dli_fname]?:@"?",@"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-b)],@"appLocal":@(HFAPathIsAppLocal(di.dli_fname))};
}

static NSDictionary *HFAMethodRecord(Class cls,SEL sel,BOOL classMethod){
    Method m=classMethod?class_getClassMethod(cls,sel):class_getInstanceMethod(cls,sel);if(!m)return nil;
    IMP imp=method_getImplementation(m);NSDictionary *ii=HFAIMPInfo(imp);if(!ii)return nil;
    return @{@"class":[NSString stringWithUTF8String:class_getName(cls)]?:@"?",@"selector":[NSString stringWithUTF8String:sel_getName(sel)]?:@"?",@"classMethod":@(classMethod),@"types":[NSString stringWithUTF8String:method_getTypeEncoding(m)?:"?"]?:@"?",@"implementation":ii};
}

NSDictionary *HFAC4M0ConfigOwnerResolve(void){
    @autoreleasepool{
        int count=objc_getClassList(NULL,0);if(count<=0)return @{@"available":@NO,@"reason":@"no-classes"};
        Class *classes=(Class*)calloc((size_t)count,sizeof(Class));count=objc_getClassList(classes,count);
        SEL config=sel_registerName("loadConfig:"), policies=sel_registerName("loadPolicies");
        NSMutableArray *candidates=[NSMutableArray array];
        for(int i=0;i<count;i++){
            Class cls=classes[i];if(!cls)continue;
            NSDictionary *r=nil;
            r=HFAMethodRecord(cls,config,NO);if([r[@"implementation"][@"appLocal"] boolValue])[candidates addObject:r];
            r=HFAMethodRecord(cls,config,YES);if([r[@"implementation"][@"appLocal"] boolValue])[candidates addObject:r];
            r=HFAMethodRecord(cls,policies,NO);if([r[@"implementation"][@"appLocal"] boolValue])[candidates addObject:r];
            r=HFAMethodRecord(cls,policies,YES);if([r[@"implementation"][@"appLocal"] boolValue])[candidates addObject:r];
        }
        free(classes);
        NSMutableDictionary *byImage=[NSMutableDictionary dictionary];
        for(NSDictionary *r in candidates){NSString *img=r[@"implementation"][@"image"]?:@"?";NSMutableArray *a=byImage[img];if(!a){a=[NSMutableArray array];byImage[img]=a;}[a addObject:r];}
        NSMutableArray *ranked=[NSMutableArray array];
        for(NSString *img in byImage){NSArray *a=byImage[img];NSUInteger score=0;BOOL hasConfig=NO,hasPolicies=NO;for(NSDictionary *r in a){NSString *s=r[@"selector"];if([s isEqualToString:@"loadConfig:"]){hasConfig=YES;score+=60;}if([s isEqualToString:@"loadPolicies"]){hasPolicies=YES;score+=40;}}[ranked addObject:@{@"image":img,@"score":@(score),@"hasLoadConfig":@(hasConfig),@"hasLoadPolicies":@(hasPolicies),@"methods":a}];}
        [ranked sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){NSInteger sa=[a[@"score"] integerValue],sb=[b[@"score"] integerValue];return sa>sb?NSOrderedAscending:(sa<sb?NSOrderedDescending:NSOrderedSame);}];
        NSDictionary *out=@{@"available":@YES,@"candidateCount":@(candidates.count),@"ownerImageCount":@(ranked.count),@"owners":ranked,@"readOnly":@YES,@"invoked":@NO,@"schema":@"com.hfa.c4m0-config-owner/v0.3.13.19"};
        [gStatus release];gStatus=[out retain];return out;
    }
}

NSDictionary *HFAC4M0ConfigOwnerStatus(void){return gStatus?:@{@"available":@NO,@"reason":@"not-run"};}

__attribute__((constructor)) static void HFAC4M0OwnerInit(void){
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{@autoreleasepool{HFAC4M0ConfigOwnerResolve();}});
}
