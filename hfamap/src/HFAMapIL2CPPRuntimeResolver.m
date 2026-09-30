#import "HFAMapIL2CPPRuntimeResolver.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_prot.h>
#import <dlfcn.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef void *(*HFADomainGetFn)(void);
typedef const void **(*HFADomainGetAssembliesFn)(const void *, size_t *);
typedef const void *(*HFAAssemblyGetImageFn)(const void *);
typedef const char *(*HFAImageGetNameFn)(const void *);
typedef size_t (*HFAImageGetClassCountFn)(const void *);
typedef void *(*HFAImageGetClassFn)(const void *, size_t);
typedef const char *(*HFAClassGetNameFn)(void *);
typedef const char *(*HFAClassGetNamespaceFn)(void *);
typedef const void *(*HFAClassGetMethodsFn)(void *, void **);
typedef const char *(*HFAMethodGetNameFn)(const void *);
typedef uint32_t (*HFAMethodGetParamCountFn)(const void *);
typedef void *(*HFAMethodGetPointerFn)(const void *);

static void *gHandle;
static NSString *gUnityPath;
static uintptr_t gUnityBase;
static BOOL gReady;
static NSString *gLastError;
static HFADomainGetFn gDomainGet;
static HFADomainGetAssembliesFn gDomainGetAssemblies;
static HFAAssemblyGetImageFn gAssemblyGetImage;
static HFAImageGetNameFn gImageGetName;
static HFAImageGetClassCountFn gImageGetClassCount;
static HFAImageGetClassFn gImageGetClass;
static HFAClassGetNameFn gClassGetName;
static HFAClassGetNamespaceFn gClassGetNamespace;
static HFAClassGetMethodsFn gClassGetMethods;
static HFAMethodGetNameFn gMethodGetName;
static HFAMethodGetParamCountFn gMethodGetParamCount;
static HFAMethodGetPointerFn gMethodGetPointer;
static NSMutableDictionary *gCache;
static NSUInteger gResolveCount;
static NSUInteger gHitCount;
static NSUInteger gBudgetMissCount;

static void HFALog(const char *fmt, ...) {
    @autoreleasepool {
        NSString *p=[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f=fopen(p.fileSystemRepresentation,"a");if(!f)return;
        va_list ap;va_start(ap,fmt);vfprintf(f,fmt,ap);va_end(ap);fflush(f);fclose(f);
    }
}

static NSString *HFAString(const char *s){ if(!s)return @""; NSString *v=[NSString stringWithUTF8String:s]; return v?:@""; }

static void *HFASym(const char *name){ void *p=gHandle?dlsym(gHandle,name):NULL; if(!p)p=dlsym(RTLD_DEFAULT,name); return p; }

static BOOL HFAFindUnity(void){
    gUnityBase=0; [gUnityPath release]; gUnityPath=nil;
    uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++){
        const char *cp=_dyld_get_image_name(i); if(!cp)continue;
        NSString *path=[NSString stringWithUTF8String:cp]; NSString *name=path.lastPathComponent;
        if([name isEqualToString:@"UnityFramework"] || [path rangeOfString:@"UnityFramework.framework/UnityFramework" options:NSCaseInsensitiveSearch].location!=NSNotFound){
            gUnityPath=[path copy]; gUnityBase=(uintptr_t)_dyld_get_image_header(i); return gUnityBase!=0;
        }
    }
    return NO;
}

static BOOL HFAExecutableUnityAddress(uintptr_t address){
    if(!gUnityBase||!address)return NO;
    const struct mach_header_64 *mh=(const struct mach_header_64 *)gUnityBase; if(mh->magic!=MH_MAGIC_64)return NO;
    const uint8_t *c=(const uint8_t *)(mh+1),*end=c+mh->sizeofcmds; uint64_t vmBase=UINT64_MAX;
    for(uint32_t i=0;i<mh->ncmds;i++){ if(c+sizeof(struct load_command)>end)return NO; const struct load_command *lc=(const struct load_command *)c; if(lc->cmdsize<sizeof(*lc)||c+lc->cmdsize>end)return NO; if(lc->cmd==LC_SEGMENT_64){ const struct segment_command_64 *s=(const struct segment_command_64 *)c; if(strncmp(s->segname,SEG_TEXT,16)==0)vmBase=s->vmaddr; } c+=lc->cmdsize; }
    if(vmBase==UINT64_MAX)return NO; c=(const uint8_t *)(mh+1);
    for(uint32_t i=0;i<mh->ncmds;i++){ const struct load_command *lc=(const struct load_command *)c; if(lc->cmd==LC_SEGMENT_64){ const struct segment_command_64 *s=(const struct segment_command_64 *)c; if((s->initprot&VM_PROT_EXECUTE)&&s->vmaddr>=vmBase){ uintptr_t st=gUnityBase+(uintptr_t)(s->vmaddr-vmBase),fn=st+(uintptr_t)s->vmsize; if(address>=st&&address<fn)return YES; }} c+=lc->cmdsize; }
    return NO;
}

static uintptr_t HFAMethodPointer(const void *method, NSString **source){
    if(source)*source=@"unavailable"; if(!method)return 0;
    if(gMethodGetPointer){ uintptr_t p=(uintptr_t)gMethodGetPointer(method); if(HFAExecutableUnityAddress(p)){ if(source)*source=@"il2cpp_method_get_pointer"; return p; }}
    uintptr_t words[2]={0,0}; memcpy(words,method,sizeof(words));
    for(NSUInteger i=0;i<2;i++) if(HFAExecutableUnityAddress(words[i])){ if(source)*source=[NSString stringWithFormat:@"MethodInfo[%lu]",(unsigned long)i]; return words[i]; }
    return 0;
}

void HFAIL2CPPRefresh(void){
    @synchronized([NSObject class]){
        gReady=NO; [gLastError release]; gLastError=nil;
        if(!gCache)gCache=[[NSMutableDictionary alloc]init]; else [gCache removeAllObjects];
        if(!HFAFindUnity()){ gLastError=[@"UnityFramework not loaded" copy]; HFALog("[V031311-IL2CPP] available=0 reason=unity-not-loaded\n"); return; }
#ifdef RTLD_NOLOAD
        gHandle=dlopen(gUnityPath.fileSystemRepresentation,RTLD_LAZY|RTLD_NOLOAD);
#else
        gHandle=dlopen(gUnityPath.fileSystemRepresentation,RTLD_LAZY);
#endif
        gDomainGet=(HFADomainGetFn)HFASym("il2cpp_domain_get");
        gDomainGetAssemblies=(HFADomainGetAssembliesFn)HFASym("il2cpp_domain_get_assemblies");
        gAssemblyGetImage=(HFAAssemblyGetImageFn)HFASym("il2cpp_assembly_get_image");
        gImageGetName=(HFAImageGetNameFn)HFASym("il2cpp_image_get_name");
        gImageGetClassCount=(HFAImageGetClassCountFn)HFASym("il2cpp_image_get_class_count");
        gImageGetClass=(HFAImageGetClassFn)HFASym("il2cpp_image_get_class");
        gClassGetName=(HFAClassGetNameFn)HFASym("il2cpp_class_get_name");
        gClassGetNamespace=(HFAClassGetNamespaceFn)HFASym("il2cpp_class_get_namespace");
        gClassGetMethods=(HFAClassGetMethodsFn)HFASym("il2cpp_class_get_methods");
        gMethodGetName=(HFAMethodGetNameFn)HFASym("il2cpp_method_get_name");
        gMethodGetParamCount=(HFAMethodGetParamCountFn)HFASym("il2cpp_method_get_param_count");
        gMethodGetPointer=(HFAMethodGetPointerFn)HFASym("il2cpp_method_get_pointer");
        gReady=gDomainGet&&gDomainGetAssemblies&&gAssemblyGetImage&&gImageGetName&&gImageGetClassCount&&gImageGetClass&&gClassGetName&&gClassGetNamespace&&gClassGetMethods&&gMethodGetName;
        if(!gReady)gLastError=[@"required IL2CPP runtime exports unavailable" copy];
        HFALog("[V031311-IL2CPP] available=%u unity=%s methodPointerAPI=%u\n",gReady,[gUnityPath UTF8String]?:"?",gMethodGetPointer!=NULL);
    }
}

static void HFAEnsureReady(void){ static dispatch_once_t once; dispatch_once(&once,^{ HFAIL2CPPRefresh(); }); }

NSDictionary *HFAIL2CPPResolverStatus(void){
    HFAEnsureReady();
    return @{ @"available":@(gReady), @"unityPath":gUnityPath?:@"", @"unityBase":[NSString stringWithFormat:@"0x%llX",(unsigned long long)gUnityBase], @"methodPointerAPI":@(gMethodGetPointer!=NULL), @"lastError":gLastError?:@"", @"resolveCount":@(gResolveCount), @"hitCount":@(gHitCount), @"budgetMissCount":@(gBudgetMissCount) };
}

NSDictionary *HFAIL2CPPResolveNativeAddress(const void *address){
    HFAEnsureReady(); uintptr_t target=(uintptr_t)address; if(!gReady||!HFAExecutableUnityAddress(target))return nil;
    NSString *key=[NSString stringWithFormat:@"%llX",(unsigned long long)target];
    @synchronized(gCache){ id cached=[gCache objectForKey:key]; if(cached){ return cached==[NSNull null]?nil:cached; }}
    gResolveCount++;
    CFAbsoluteTime started=CFAbsoluteTimeGetCurrent(); const CFTimeInterval budget=0.35; NSUInteger visited=0;
    void *domain=gDomainGet(); if(!domain)return nil; size_t ac=0; const void **assemblies=gDomainGetAssemblies(domain,&ac); if(!assemblies)return nil;
    for(size_t a=0;a<ac;a++){
        const void *image=gAssemblyGetImage(assemblies[a]); if(!image)continue; NSString *assembly=HFAString(gImageGetName(image)); size_t cc=gImageGetClassCount(image);
        for(size_t c=0;c<cc;c++){
            if((visited&0x3FF)==0 && CFAbsoluteTimeGetCurrent()-started>budget){ gBudgetMissCount++; @synchronized(gCache){[gCache setObject:[NSNull null] forKey:key];} HFALog("[V031311-IL2CPP-MISS] address=0x%llX reason=budget methods=%lu\n",(unsigned long long)target,(unsigned long)visited); return nil; }
            void *klass=gImageGetClass(image,c); if(!klass)continue; NSString *cn=HFAString(gClassGetName(klass)),*ns=HFAString(gClassGetNamespace(klass)); void *it=NULL; const void *m=NULL;
            while((m=gClassGetMethods(klass,&it))!=NULL){ visited++; NSString *src=nil; uintptr_t p=HFAMethodPointer(m,&src); if(p!=target)continue; NSString *mn=HFAString(gMethodGetName(m)); NSInteger argc=gMethodGetParamCount?(NSInteger)gMethodGetParamCount(m):-1; uint64_t rva=gUnityBase&&p>=gUnityBase?(uint64_t)(p-gUnityBase):0; NSString *classPath=ns.length?[NSString stringWithFormat:@"%@.%@",ns,cn]:cn; NSDictionary *hit=@{ @"resolved":@YES,@"assembly":assembly?:@"",@"namespace":ns?:@"",@"class":cn?:@"",@"method":mn?:@"",@"argumentCount":@(argc),@"methodInfo":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(uintptr_t)m],@"methodPointer":[NSString stringWithFormat:@"0x%llX",(unsigned long long)p],@"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)rva],@"pointerSource":src?:@"unavailable",@"canonical":[NSString stringWithFormat:@"%@!%@::%@/%ld",assembly?:@"?",classPath?:@"?",mn?:@"?",(long)argc],@"exactPointerMatch":@YES };
                @synchronized(gCache){[gCache setObject:hit forKey:key];} gHitCount++; HFALog("[V031311-IL2CPP-HIT] address=0x%llX rva=0x%llX assembly=%s class=%s.%s method=%s argc=%ld source=%s\n",(unsigned long long)target,(unsigned long long)rva,[assembly UTF8String]?:"?",[ns UTF8String]?:"?",[cn UTF8String]?:"?",[mn UTF8String]?:"?",(long)argc,[src UTF8String]?:"?"); return hit; }
        }
    }
    @synchronized(gCache){[gCache setObject:[NSNull null] forKey:key];}
    HFALog("[V031311-IL2CPP-MISS] address=0x%llX reason=no-exact-method methods=%lu\n",(unsigned long long)target,(unsigned long)visited); return nil;
}
