#import "HFAMapRuntimeModificationTruth.h"
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/vm_prot.h>
#import <dlfcn.h>
#include <stdint.h>
#include <string.h>

static NSString *HFATBaseName(const char *path){
    if(!path)return @"?";const char *s=strrchr(path,'/');return [NSString stringWithUTF8String:s?s+1:path]?:@"?";
}

static int HFATImageIndex(NSString *name){
    if(!name.length)return -1;uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++){const char *p=_dyld_get_image_name(i);if(!p)continue;NSString *b=HFATBaseName(p);if([b isEqualToString:name]||[[NSString stringWithUTF8String:p] isEqualToString:name])return (int)i;}
    return -1;
}

static uintptr_t HFATRuntimeAddress(NSString *image,NSString *rva){
    if(!image.length||!rva.length)return 0;int idx=HFATImageIndex(image);if(idx<0)return 0;
    const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header((uint32_t)idx);if(!h||h->magic!=MH_MAGIC_64)return 0;
    char *end=NULL;uint64_t raw=strtoull(rva.UTF8String,&end,0);if(!end||*end)return 0;intptr_t slide=_dyld_get_image_vmaddr_slide((uint32_t)idx);
    uint64_t minVM=UINT64_MAX;BOOL preferred=NO;const uint8_t *cur=(const uint8_t*)(h+1),*limit=cur+h->sizeofcmds;
    for(uint32_t i=0;i<h->ncmds;i++){if(cur+sizeof(struct load_command)>limit)break;const struct load_command *lc=(const struct load_command*)cur;if(lc->cmdsize<sizeof(*lc)||cur+lc->cmdsize>limit)break;
        if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;if(strcmp(seg->segname,"__PAGEZERO")&&seg->vmsize&&seg->vmaddr<minVM)minVM=seg->vmaddr;if(seg->vmsize&&raw>=seg->vmaddr&&raw<seg->vmaddr+seg->vmsize)preferred=YES;}cur+=lc->cmdsize;}
    if(preferred)return (uintptr_t)((int64_t)raw+slide);if(minVM!=UINT64_MAX)return (uintptr_t)((int64_t)(minVM+raw)+slide);return 0;
}

static BOOL HFATRange(uintptr_t address,size_t size,BOOL executable){
    if(!address||!size)return NO;uint64_t end=(uint64_t)address+(uint64_t)size;uint32_t n=_dyld_image_count();
    for(uint32_t i=0;i<n;i++){const struct mach_header_64 *h=(const struct mach_header_64*)_dyld_get_image_header(i);if(!h||h->magic!=MH_MAGIC_64)continue;intptr_t slide=_dyld_get_image_vmaddr_slide(i);const uint8_t *cur=(const uint8_t*)(h+1),*limit=cur+h->sizeofcmds;
        for(uint32_t j=0;j<h->ncmds;j++){if(cur+sizeof(struct load_command)>limit)break;const struct load_command *lc=(const struct load_command*)cur;if(lc->cmdsize<sizeof(*lc)||cur+lc->cmdsize>limit)break;
            if(lc->cmd==LC_SEGMENT_64&&lc->cmdsize>=sizeof(struct segment_command_64)){const struct segment_command_64 *seg=(const struct segment_command_64*)cur;vm_prot_t need=executable?VM_PROT_EXECUTE:VM_PROT_READ;if(seg->initprot&need){uint64_t s=(uint64_t)((int64_t)seg->vmaddr+(int64_t)slide),e=s+seg->vmsize;if((uint64_t)address>=s&&end<=e)return YES;}}cur+=lc->cmdsize;}}
    return NO;
}

static NSData *HFATHex(NSString *hex){
    if(!hex.length||(hex.length&1))return nil;NSMutableData *d=[NSMutableData dataWithCapacity:hex.length/2];const char *s=hex.UTF8String;
    for(NSUInteger i=0;i<hex.length;i+=2){char b[3]={s[i],s[i+1],0};char *e=NULL;unsigned long v=strtoul(b,&e,16);if(!e||*e)return nil;uint8_t x=(uint8_t)v;[d appendBytes:&x length:1];}return d;
}

static NSString *HFATHexData(NSData *d){
    if(!d.length)return @"";const uint8_t *b=d.bytes;NSMutableString *s=[NSMutableString stringWithCapacity:d.length*2];for(NSUInteger i=0;i<d.length;i++)[s appendFormat:@"%02X",b[i]];return s;
}

static NSDictionary *HFATAddressInfo(uintptr_t a){
    if(!a)return @{};Dl_info d={0};if(!dladdr((void*)a,&d)||!d.dli_fbase||!d.dli_fname)return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a] };
    return @{ @"address":[NSString stringWithFormat:@"0x%llX",(unsigned long long)a],@"image":HFATBaseName(d.dli_fname),@"rva":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-(uintptr_t)d.dli_fbase)],@"symbol":d.dli_sname?[NSString stringWithUTF8String:d.dli_sname]:@"" };
}

static NSDictionary *HFATVerifyPatch(NSDictionary *e){
    NSString *image=[e[@"target"] description]?:@"";NSString *rva=[e[@"offset"] description]?:@"";NSData *orig=HFATHex([e[@"original"] description]);NSData *enabled=HFATHex([e[@"enabled"] description]);NSUInteger n=MAX(orig.length,enabled.length);uintptr_t a=HFATRuntimeAddress(image,rva);
    NSMutableDictionary *o=[NSMutableDictionary dictionary];o[@"mechanism"]=@"fixed-patch";o[@"targetImage"]=image;o[@"targetRVA"]=rva;o[@"featureId"]=[e[@"featureId"] description]?:@"";o[@"ownerClass"]=[e[@"ownerClass"] description]?:@"";o[@"analyzerBackendId"]=e[@"analyzerBackendId"]?:@0;o[@"original"]=[e[@"original"] description]?:@"";o[@"enabled"]=[e[@"enabled"] description]?:@"";
    if(!a||!n||!HFATRange(a,n,NO)){o[@"state"]=@"unreadable";o[@"verified"]=@NO;return o;}
    NSData *cur=[NSData dataWithBytes:(void*)a length:n];o[@"runtimeBytes"]=HFATHexData(cur);o[@"runtimeAddress"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)a];NSString *state=@"unknown";if(orig.length==n&&[cur isEqualToData:orig])state=@"original";else if(enabled.length==n&&[cur isEqualToData:enabled])state=@"enabled";o[@"state"]=state;o[@"verified"]=@YES;
    NSLog(@"[V031313-PATCH-STATE] backend=%@ owner=%@ feature=%@ target=%@+%@ state=%@ bytes=%@",o[@"analyzerBackendId"],o[@"ownerClass"],o[@"featureId"],image,rva,state,o[@"runtimeBytes"]);return o;
}

static NSDictionary *HFATVerifyHook(NSDictionary *b,NSString *menuImage){
    NSString *targetImage=[b[@"targetImage"] description]?:@"";NSString *targetRVA=[b[@"targetRVA"] description]?:@"";NSString *replacementRVA=[b[@"replacementRVA"] description]?:@"";NSString *slotRVA=[b[@"originalSlotRVA"] description]?:@"";
    uintptr_t target=HFATRuntimeAddress(targetImage,targetRVA),replacement=HFATRuntimeAddress(menuImage,replacementRVA),slot=HFATRuntimeAddress(menuImage,slotRVA),original=0;BOOL slotReadable=slot&&HFATRange(slot,sizeof(uintptr_t),NO);if(slotReadable)memcpy(&original,(void*)slot,sizeof(original));
    BOOL targetExec=target&&HFATRange(target,4,YES),replacementExec=replacement&&HFATRange(replacement,4,YES),originalExec=original&&HFATRange(original,4,YES);BOOL installed=targetExec&&replacementExec&&slotReadable&&original!=0&&originalExec;
    NSMutableDictionary *o=[NSMutableDictionary dictionary];o[@"mechanism"]=@"runtime-hook";o[@"backendId"]=b[@"backendId"]?:@0;o[@"targetImage"]=targetImage;o[@"targetRVA"]=targetRVA;o[@"replacementImage"]=menuImage?:@"";o[@"replacementRVA"]=replacementRVA;o[@"originalSlotRVA"]=slotRVA;o[@"targetExecutable"]=@(targetExec);o[@"replacementExecutable"]=@(replacementExec);o[@"slotReadable"]=@(slotReadable);o[@"originalExecutable"]=@(originalExec);o[@"installed"]=@(installed);o[@"semanticType"]=[b[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?[b[@"semanticEvidence"] objectForKey:@"semanticType"]?:b[@"semanticType"]?:@"":b[@"semanticType"]?:@"";if(original)o[@"originalPointer"]=HFATAddressInfo(original);if(target)o[@"targetAddress"]=HFATAddressInfo(target);if(replacement)o[@"replacementAddress"]=HFATAddressInfo(replacement);
    NSLog(@"[V031313-HOOK-STATE] backend=%@ target=%@+%@ replacement=%@+%@ slot=%@ original=0x%llX installed=%u semantic=%@",o[@"backendId"],targetImage,targetRVA,menuImage,replacementRVA,slotRVA,(unsigned long long)original,installed?1:0,o[@"semanticType"]);return o;
}

NSDictionary *HFARuntimeModificationTruthBuild(NSArray *ledger,NSString *directory){
    NSMutableArray *patches=[NSMutableArray array],*hooks=[NSMutableArray array],*startup=[NSMutableArray array];NSMutableSet *menuIds=[NSMutableSet set];NSUInteger enabled=0,original=0,unknown=0,unreadable=0;
    for(NSDictionary *e in ledger?:@[]){if(![e isKindOfClass:NSDictionary.class])continue;if(![[e[@"original"] description] length]||![[e[@"enabled"] description] length])continue;NSDictionary *v=HFATVerifyPatch(e);[patches addObject:v];NSString *fid=[e[@"featureId"] description]?:@"";if(fid.length)[menuIds addObject:fid];if([[e[@"ownerClass"] description] isEqual:@"startup-owned"])[startup addObject:v];NSString *st=v[@"state"]?:@"";if([st isEqual:@"enabled"])enabled++;else if([st isEqual:@"original"])original++;else if([st isEqual:@"unreadable"])unreadable++;else unknown++;}
    NSString *analyzerPath=[directory stringByAppendingPathComponent:@"HFAMap_RuntimeAnalyzer_v0311.json"];NSData *data=[NSData dataWithContentsOfFile:analyzerPath];NSDictionary *root=nil;if(data.length)root=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];NSString *menuImage=[root[@"image"] isKindOfClass:NSString.class]?root[@"image"]:@"";NSArray *backends=[root[@"backends"] isKindOfClass:NSArray.class]?root[@"backends"]:@[];NSUInteger installedHooks=0;
    for(NSDictionary *b in backends){if(![[b[@"backendType"] description] isEqual:@"runtime-semantic"])continue;NSDictionary *v=HFATVerifyHook(b,menuImage);[hooks addObject:v];if([v[@"installed"] boolValue])installedHooks++;}
    NSUInteger menuFeatureCount=menuIds.count+hooks.count,startupFeatureCount=startup.count,effectiveFeatureCount=menuFeatureCount+startupFeatureCount;
    NSDictionary *out=@{@"schema":@"com.hfa.runtime-modification-truth/v0.3.13.13",@"analysisOnly":@YES,@"menuFeatureCount":@(menuFeatureCount),@"startupFeatureCount":@(startupFeatureCount),@"effectiveFeatureCount":@(effectiveFeatureCount),@"fixedPatchSiteCount":@(patches.count),@"runtimeHookCount":@(hooks.count),@"installedHookCount":@(installedHooks),@"enabledPatchCount":@(enabled),@"originalPatchCount":@(original),@"unknownPatchCount":@(unknown),@"unreadablePatchCount":@(unreadable),@"patches":patches,@"runtimeHooks":hooks,@"startupModifications":startup};
    NSLog(@"[V031313-TRUTH-SUMMARY] menu=%lu startup=%lu effective=%lu patchSites=%lu hooks=%lu installedHooks=%lu enabled=%lu original=%lu unknown=%lu unreadable=%lu",(unsigned long)menuFeatureCount,(unsigned long)startupFeatureCount,(unsigned long)effectiveFeatureCount,(unsigned long)patches.count,(unsigned long)hooks.count,(unsigned long)installedHooks,(unsigned long)enabled,(unsigned long)original,(unsigned long)unknown,(unsigned long)unreadable);return out;
}
