#import "HFAMapRuntimeRootGraphResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

static const NSUInteger kHFARootMaxViews = 1024;
static const NSUInteger kHFARootMaxControls = 256;
static const NSUInteger kHFARootMaxRoots = 256;
static const NSUInteger kHFARootMaxNodes = 384;
static const NSUInteger kHFARootMaxDepth = 4;
static const NSUInteger kHFARootMaxFields = 4096;
static const NSUInteger kHFARootMaxContainerItems = 64;
static const NSUInteger kHFARootMaxMethodsPerClass = 96;
static const NSUInteger kHFARootMaxObservedImages = 256;

typedef struct { const struct mach_header *header; intptr_t slide; } HFAObservedImage;
static HFAObservedImage gHFAObservedImages[kHFARootMaxObservedImages];
static uint32_t gHFAObservedImageCount;

static void HFAImageAdded(const struct mach_header *mh, intptr_t slide) {
    uint32_t index = gHFAObservedImageCount;
    if (index >= kHFARootMaxObservedImages) return;
    gHFAObservedImages[index].header = mh;
    gHFAObservedImages[index].slide = slide;
    gHFAObservedImageCount = index + 1;
}
__attribute__((constructor)) static void HFARuntimeRootGraphConstructor(void) {
    _dyld_register_func_for_add_image(HFAImageAdded);
}

static NSString *HFAHex(uint64_t value) { return [NSString stringWithFormat:@"0x%llX",(unsigned long long)value]; }
static NSString *HFAImageForClass(Class cls) {
    const char *path = cls ? class_getImageName(cls) : NULL;
    return path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
}
static NSString *HFAImageForObject(id object) { return object ? HFAImageForClass(object_getClass(object)) : @""; }

static NSString *HFARoleForName(NSString *name) {
    NSString *l = name.lowercaseString;
    if ([l containsString:@"offset"] || [l containsString:@"rva"] || [l containsString:@"address"]) return @"address-field";
    if ([l containsString:@"patch"] || [l containsString:@"bytes"] || [l containsString:@"instruction"] || [l containsString:@"original"] || [l containsString:@"replace"]) return @"patch-field";
    if ([l containsString:@"image"] || [l containsString:@"library"] || [l containsString:@"module"] || [l containsString:@"macho"] || [l containsString:@"path"]) return @"target-image-field";
    if ([l containsString:@"feature"] || [l containsString:@"title"] || [l containsString:@"label"] || [l isEqualToString:@"name"] || [l hasSuffix:@"name"]) return @"feature-field";
    if ([l containsString:@"callback"] || [l containsString:@"handler"] || [l containsString:@"action"] || [l containsString:@"block"]) return @"callback-field";
    if ([l containsString:@"method"] || [l containsString:@"class"] || [l containsString:@"assembly"] || [l containsString:@"namespace"]) return @"managed-identity-field";
    return @"field";
}

static BOOL HFAReadMemory(uint64_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),(vm_address_t)address,(vm_size_t)size,(vm_address_t)buffer,&copied);
    return kr == KERN_SUCCESS && copied == (vm_size_t)size;
}

static NSDictionary *HFAImageIdentityAtIndex(uint32_t index) {
    const struct mach_header *mh = _dyld_get_image_header(index);
    const char *rawPath = _dyld_get_image_name(index);
    if (!mh || mh->magic != MH_MAGIC_64) return nil;
    intptr_t slide = _dyld_get_image_vmaddr_slide(index);
    const struct mach_header_64 *h=(const struct mach_header_64 *)mh;
    const uint8_t *cursor=(const uint8_t *)(h+1);
    uint64_t preferred=UINT64_MAX, low=UINT64_MAX, high=0;
    for(uint32_t i=0;i<h->ncmds;i++){
        const struct load_command *lc=(const struct load_command *)cursor;
        if(!lc->cmdsize) break;
        if(lc->cmd==LC_SEGMENT_64 && lc->cmdsize>=sizeof(struct segment_command_64)){
            const struct segment_command_64 *seg=(const struct segment_command_64 *)cursor;
            if(seg->vmsize){ preferred=MIN(preferred,seg->vmaddr); low=MIN(low,seg->vmaddr+(uint64_t)slide); high=MAX(high,seg->vmaddr+(uint64_t)slide+seg->vmsize); }
        }
        cursor+=lc->cmdsize;
    }
    if(preferred==UINT64_MAX) preferred=0;
    if(low==UINT64_MAX) low=(uint64_t)(uintptr_t)mh;
    NSString *path=rawPath?[NSString stringWithUTF8String:rawPath]:@"";
    return @{@"index":@(index),@"path":path?:@"",@"fileName":path.lastPathComponent?:@"",@"runtimeBase":@(preferred+(uint64_t)slide),@"runtimeLow":@(low),@"runtimeHigh":@(high),@"slide":@((long long)slide)};
}
static NSArray *HFAAllImages(void){ NSMutableArray *a=[NSMutableArray array]; for(uint32_t i=0;i<_dyld_image_count();i++){NSDictionary *r=HFAImageIdentityAtIndex(i); if(r)[a addObject:r];} return a; }

static NSDictionary *HFAAddressContext(uint64_t address, NSArray *images) {
    if(!address) return nil;
    NSMutableDictionary *r=[NSMutableDictionary dictionaryWithObject:HFAHex(address) forKey:@"runtimeVA"];
    Dl_info info={};
    if(dladdr((const void *)(uintptr_t)address,&info) && info.dli_fbase && info.dli_fname){
        NSString *p=[NSString stringWithUTF8String:info.dli_fname]?:@"";
        r[@"dladdrPath"]=p; r[@"dladdrImage"]=p.lastPathComponent?:@""; r[@"dladdrLoadBase"]=HFAHex((uint64_t)(uintptr_t)info.dli_fbase);
        if(info.dli_sname) r[@"symbol"]=[NSString stringWithUTF8String:info.dli_sname]?:@"";
    }
    for(NSDictionary *im in images){
        uint64_t low=[im[@"runtimeLow"] unsignedLongLongValue], high=[im[@"runtimeHigh"] unsignedLongLongValue];
        if(address<low || address>=high) continue;
        uint64_t base=[im[@"runtimeBase"] unsignedLongLongValue];
        r[@"image"]=im[@"fileName"]?:@""; r[@"path"]=im[@"path"]?:@"";
        if(address>=base){uint64_t rva=address-base; r[@"rva"]=@(rva); r[@"rvaHex"]=HFAHex(rva); r[@"addressSemantics"]=@"runtime-va-proven-to-loaded-image-rva";}
        break;
    }
    return r.count>1?r:nil;
}
static NSArray *HFARVACandidates(uint64_t raw, NSArray *images) {
    if(!raw) return @[];
    NSMutableArray *a=[NSMutableArray array];
    for(NSDictionary *im in images){
        uint64_t base=[im[@"runtimeBase"] unsignedLongLongValue], low=[im[@"runtimeLow"] unsignedLongLongValue], high=[im[@"runtimeHigh"] unsignedLongLongValue];
        if(high<=low || raw>high-low) continue;
        uint64_t runtime=base+raw; if(runtime<low || runtime>=high) continue;
        [a addObject:@{@"image":im[@"fileName"]?:@"",@"path":im[@"path"]?:@"",@"rawValue":@(raw),@"rawHex":HFAHex(raw),@"candidateRuntimeVA":HFAHex(runtime),@"addressSemantics":@"rva-candidate-unverified"}];
    }
    return a;
}

static NSString *HFAControlLabel(UIControl *control){
    if([control isKindOfClass:UIButton.class]){NSString *t=[(UIButton *)control titleForState:UIControlStateNormal]; if(t.length)return t;}
    if(control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope=control;
    for(NSUInteger d=0;scope&&d<3;d++,scope=scope.superview){NSMutableArray *q=[NSMutableArray arrayWithObject:scope]; for(NSUInteger i=0;i<q.count&&i<32;i++){UIView *v=q[i]; if([v isKindOfClass:UILabel.class]&&[(UILabel *)v text].length)return [(UILabel *)v text]; for(UIView *c in v.subviews)if(q.count<32)[q addObject:c];}}
    return @"";
}

static NSArray *HFAClassFingerprint(Class cls, NSString *menuImage, NSArray *images){
    NSMutableArray *hier=[NSMutableArray array]; NSUInteger depth=0,budget=kHFARootMaxMethodsPerClass;
    for(Class cur=cls;cur&&depth<8;cur=class_getSuperclass(cur),depth++){
        NSString *img=HFAImageForClass(cur); NSMutableDictionary *cr=[@{@"class":NSStringFromClass(cur)?:@"",@"image":img?:@"",@"instanceSize":@(class_getInstanceSize(cur)),@"menuOwned":@([img isEqualToString:menuImage])} mutableCopy];
        if([img isEqualToString:menuImage]&&budget){NSMutableArray *methods=[NSMutableArray array]; unsigned count=0; Method *list=class_copyMethodList(cur,&count); for(unsigned i=0;list&&i<count&&budget;i++,budget--){SEL sel=method_getName(list[i]); NSString *name=sel?NSStringFromSelector(sel):@""; IMP imp=method_getImplementation(list[i]); NSMutableDictionary *m=[@{@"selector":name?:@"",@"role":HFARoleForName(name?:@""),@"typeEncoding":method_getTypeEncoding(list[i])?[NSString stringWithUTF8String:method_getTypeEncoding(list[i])]:@"",@"implementation":HFAHex((uint64_t)(uintptr_t)imp)} mutableCopy]; NSDictionary *ctx=HFAAddressContext((uint64_t)(uintptr_t)imp,images); if(ctx)m[@"addressContext"]=ctx; [methods addObject:m]; [m release];} if(list)free(list); cr[@"methods"]=methods;}
        [hier addObject:cr]; [cr release];
    }
    return hier;
}
static NSString *HFAPropertyBackingIvarName(objc_property_t p){const char *attrs=property_getAttributes(p); if(!attrs)return nil; for(NSString *piece in [[NSString stringWithUTF8String:attrs] componentsSeparatedByString:@","])if([piece hasPrefix:@"V"]&&piece.length>1)return [piece substringFromIndex:1]; return nil;}
static size_t HFAScalarWidth(const char *type){if(!type||!*type)return 0; while(*type&&strchr("rnNoORV",*type))type++; switch(*type){case 'B':case 'c':case 'C':return 1;case 's':case 'S':return 2;case 'i':case 'I':case 'f':return 4;case 'l':case 'L':return sizeof(long);case 'q':case 'Q':case 'd':case '^':case '*':case '#':case ':':return 8;default:return 0;}}

static NSDictionary *HFAObjectValueSummary(id value, NSString *role, NSArray *images){
    if(!value)return @{@"kind":@"nil"};
    NSMutableDictionary *r=[@{@"kind":@"object",@"token":[NSString stringWithFormat:@"%p",value],@"class":NSStringFromClass(object_getClass(value))?:@"",@"classImage":HFAImageForObject(value)} mutableCopy];
    if([value isKindOfClass:NSString.class]){NSString *s=value; r[@"string"]=s.length<=512?s:[s substringToIndex:512];}
    else if([value isKindOfClass:NSNumber.class]){r[@"number"]=value; if([role isEqualToString:@"address-field"])r[@"rvaCandidates"]=HFARVACandidates([(NSNumber *)value unsignedLongLongValue],images);}
    else if([value isKindOfClass:NSData.class]){NSData *d=value; NSUInteger n=MIN((NSUInteger)d.length,(NSUInteger)64); const uint8_t *b=(const uint8_t *)d.bytes; NSMutableString *hex=[NSMutableString stringWithCapacity:n*2]; for(NSUInteger i=0;b&&i<n;i++)[hex appendFormat:@"%02X",b[i]]; r[@"dataLength"]=@(d.length); r[@"dataPrefixHex"]=hex;}
    else if([value isKindOfClass:NSArray.class]||[value isKindOfClass:NSDictionary.class]||[value isKindOfClass:NSSet.class]){r[@"container"]=@YES; r[@"count"]=@([(id)value count]);}
    return [r autorelease];
}

static NSDictionary *HFAReadIvarValue(id object, Class owner, Ivar ivar, NSString *semantic, NSArray *images, NSUInteger *budget){
    if(!object||!ivar||!*budget)return nil; --(*budget); ptrdiff_t off=ivar_getOffset(ivar); const char *type=ivar_getTypeEncoding(ivar); NSString *name=semantic.length?semantic:(ivar_getName(ivar)?[NSString stringWithUTF8String:ivar_getName(ivar)]:@""); NSString *role=HFARoleForName(name?:@"");
    NSMutableDictionary *r=[@{@"semanticName":name?:@"",@"role":role,@"ownerClass":NSStringFromClass(owner)?:@"",@"ownerImage":HFAImageForClass(owner),@"ivarName":ivar_getName(ivar)?[NSString stringWithUTF8String:ivar_getName(ivar)]:@"",@"offset":@(off),@"offsetHex":off>=0?HFAHex((uint64_t)off):@"",@"typeEncoding":type?[NSString stringWithUTF8String:type]:@""} mutableCopy];
    const char *t=type; while(t&&*t&&strchr("rnNoORV",*t))t++;
    if(t&&*t=='@'){id value=object_getIvar(object,ivar); r[@"value"]=HFAObjectValueSummary(value,role,images); if(value)r[@"objectValue"]=value;}
    else {size_t width=HFAScalarWidth(t); uint64_t raw=0; if(width&&off>=0&&width<=sizeof(raw)&&HFAReadMemory((uint64_t)(uintptr_t)object+(uint64_t)off,&raw,width)){r[@"rawValue"]=@(raw); r[@"rawHex"]=HFAHex(raw); NSDictionary *ctx=HFAAddressContext(raw,images); if(ctx)r[@"addressContext"]=ctx; if([role isEqualToString:@"address-field"])r[@"rvaCandidates"]=HFARVACandidates(raw,images);}}
    return [r autorelease];
}

static NSArray *HFAFieldsForObject(id object, NSString *menuImage, NSArray *images, NSMutableArray *children, NSUInteger *budget){
    NSMutableArray *fields=[NSMutableArray array]; NSMutableSet *seen=[NSMutableSet set]; NSUInteger depth=0;
    for(Class cls=object_getClass(object);cls&&depth<8;cls=class_getSuperclass(cls),depth++){
        if(![HFAImageForClass(cls) isEqualToString:menuImage])continue;
        unsigned ic=0; Ivar *ivars=class_copyIvarList(cls,&ic);
        for(unsigned i=0;ivars&&i<ic&&*budget;i++){NSString *key=[NSString stringWithFormat:@"%@:%td",NSStringFromClass(cls),ivar_getOffset(ivars[i])]; if([seen containsObject:key])continue; [seen addObject:key]; NSDictionary *f=HFAReadIvarValue(object,cls,ivars[i],nil,images,budget); if(!f)continue; id child=f[@"objectValue"]; if(child)[children addObject:child]; NSMutableDictionary *clean=[[f mutableCopy] autorelease]; [clean removeObjectForKey:@"objectValue"]; [fields addObject:clean];}
        if(ivars)free(ivars);
        unsigned pc=0; objc_property_t *props=class_copyPropertyList(cls,&pc);
        for(unsigned i=0;props&&i<pc&&*budget;i++){const char *rn=property_getName(props[i]); NSString *pn=rn?[NSString stringWithUTF8String:rn]:@""; NSString *back=HFAPropertyBackingIvarName(props[i]); if(!back.length)continue; Ivar iv=class_getInstanceVariable(cls,back.UTF8String); if(!iv)continue; NSString *key=[NSString stringWithFormat:@"%@:%td:%@",NSStringFromClass(cls),ivar_getOffset(iv),pn]; if([seen containsObject:key])continue; [seen addObject:key]; NSDictionary *f=HFAReadIvarValue(object,cls,iv,pn,images,budget); if(!f)continue; NSMutableDictionary *pf=[[f mutableCopy] autorelease]; id child=pf[@"objectValue"]; if(child)[children addObject:child]; [pf removeObjectForKey:@"objectValue"]; pf[@"source"]=@"property-backing-ivar"; [fields addObject:pf];}
        if(props)free(props);
    }
    return fields;
}
static NSArray *HFAContainerChildren(id object){NSMutableArray *a=[NSMutableArray array]; if([object isKindOfClass:NSArray.class]){NSArray *v=object; for(NSUInteger i=0;i<MIN(v.count,kHFARootMaxContainerItems);i++)if(v[i])[a addObject:v[i]];} else if([object isKindOfClass:NSDictionary.class]){NSArray *v=[(NSDictionary *)object allValues]; for(NSUInteger i=0;i<MIN(v.count,kHFARootMaxContainerItems);i++)if(v[i])[a addObject:v[i]];} else if([object isKindOfClass:NSSet.class]){NSArray *v=[(NSSet *)object allObjects]; for(NSUInteger i=0;i<MIN(v.count,kHFARootMaxContainerItems);i++)if(v[i])[a addObject:v[i]];} return a;}

static NSDictionary *HFADescriptorClassification(NSArray *fields, NSArray *fingerprint){
    NSMutableSet *roles=[NSMutableSet set]; BOOL hasRuntimeValue=NO;
    for(NSDictionary *f in fields){NSString *r=f[@"role"]; if(r.length&&![r isEqualToString:@"field"])[roles addObject:r]; if(f[@"rawValue"]||f[@"value"])hasRuntimeValue=YES;}
    for(NSDictionary *c in fingerprint)for(NSDictionary *m in c[@"methods"]?:@[]){NSString *r=m[@"role"]; if(r.length&&![r isEqualToString:@"field"])[roles addObject:r];}
    BOOL address=[roles containsObject:@"address-field"],patch=[roles containsObject:@"patch-field"],target=[roles containsObject:@"target-image-field"],feature=[roles containsObject:@"feature-field"];
    BOOL ok=hasRuntimeValue&&((address&&patch)||(address&&target)||(feature&&(address||patch))||roles.count>=3); if(!ok)return nil;
    return @{@"classification":(address&&patch)?@"patch-object-candidate":@"descriptor-candidate",@"roles":[[roles allObjects] sortedArrayUsingSelector:@selector(compare:)],@"verified":@NO,@"canonicalEligible":@NO,@"addressSemantics":@"unknown-until-consumer-and-live-byte-validation"};
}

static NSDictionary *HFABuildGraph(NSArray *rootObjects, NSArray *rootRecords, NSString *menuImage, NSArray *images){
    NSMutableArray *queue=[NSMutableArray array],*nodes=[NSMutableArray array],*descriptors=[NSMutableArray array]; NSHashTable *seen=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality]; NSUInteger fieldBudget=kHFARootMaxFields;
    for(id obj in rootObjects)if(obj&&queue.count<kHFARootMaxRoots)[queue addObject:@{@"object":obj,@"depth":@0}];
    for(NSUInteger index=0;index<queue.count&&nodes.count<kHFARootMaxNodes;index++){
        NSDictionary *e=queue[index]; id obj=e[@"object"]; NSUInteger depth=[e[@"depth"] unsignedIntegerValue]; if(!obj||[seen containsObject:obj])continue; [seen addObject:obj]; NSString *img=HFAImageForObject(obj); BOOL menuOwned=[img isEqualToString:menuImage]; BOOL container=[obj isKindOfClass:NSArray.class]||[obj isKindOfClass:NSDictionary.class]||[obj isKindOfClass:NSSet.class]; if(!menuOwned&&!container)continue;
        NSArray *fingerprint=menuOwned?HFAClassFingerprint(object_getClass(obj),menuImage,images):@[]; NSMutableArray *children=[NSMutableArray array]; NSArray *fields=menuOwned?HFAFieldsForObject(obj,menuImage,images,children,&fieldBudget):@[]; if(container)[children addObjectsFromArray:HFAContainerChildren(obj)];
        NSMutableDictionary *node=[@{@"token":[NSString stringWithFormat:@"%p",obj],@"class":NSStringFromClass(object_getClass(obj))?:@"",@"classImage":img?:@"",@"depth":@(depth),@"menuOwned":@(menuOwned),@"foundationContainer":@(container),@"classFingerprint":fingerprint,@"fields":fields} mutableCopy]; NSDictionary *classification=menuOwned?HFADescriptorClassification(fields,fingerprint):nil; if(classification){node[@"descriptor"]=classification; [descriptors addObject:@{@"token":node[@"token"],@"class":node[@"class"],@"classification":classification[@"classification"],@"roles":classification[@"roles"],@"verified":@NO,@"canonicalEligible":@NO}];} [nodes addObject:node]; [node release];
        if(depth>=kHFARootMaxDepth)continue; for(id child in children){if(!child||[seen containsObject:child]||queue.count>=kHFARootMaxNodes*2)continue; NSString *ci=HFAImageForObject(child); BOOL cc=[child isKindOfClass:NSArray.class]||[child isKindOfClass:NSDictionary.class]||[child isKindOfClass:NSSet.class]; if([ci isEqualToString:menuImage]||cc)[queue addObject:@{@"object":child,@"depth":@(depth+1)}];}
    }
    return @{@"roots":rootRecords?:@[],@"nodes":nodes,@"descriptorCandidates":descriptors,@"rootCount":@(rootRecords.count),@"nodeCount":@(nodes.count),@"descriptorCandidateCount":@(descriptors.count),@"fieldBudgetRemaining":@(fieldBudget),@"truncated":@(nodes.count>=kHFARootMaxNodes||fieldBudget==0)};
}

static NSDictionary *HFAUIRoots(NSString *menuImage, NSArray *images){
    NSMutableArray *queue=[NSMutableArray array],*roots=[NSMutableArray array],*objects=[NSMutableArray array]; NSHashTable *seenViews=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality],*seenRoots=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality]; NSUInteger controls=0;
    for(UIWindow *w in UIApplication.sharedApplication.windows)if(w)[queue addObject:w];
    for(NSUInteger index=0;index<queue.count&&index<kHFARootMaxViews;index++){
        UIView *view=queue[index]; if([seenViews containsObject:view])continue; [seenViews addObject:view]; for(UIView *c in view.subviews)if(queue.count<kHFARootMaxViews)[queue addObject:c];
        if([HFAImageForObject(view) isEqualToString:menuImage]&&objects.count<kHFARootMaxRoots&&![seenRoots containsObject:view]){[seenRoots addObject:view];[objects addObject:view];[roots addObject:@{@"source":@"menu-owned-view",@"objectToken":[NSString stringWithFormat:@"%p",view],@"class":NSStringFromClass(object_getClass(view))?:@"",@"classImage":HFAImageForObject(view)}];}
        if(![view isKindOfClass:UIControl.class]||controls>=kHFARootMaxControls)continue; controls++; UIControl *control=(UIControl *)view;
        for(id target in control.allTargets){if(![HFAImageForObject(target) isEqualToString:menuImage])continue; NSMutableArray *actions=[NSMutableArray array]; for(NSNumber *evn in @[@(UIControlEventTouchUpInside),@(UIControlEventValueChanged)]){UIControlEvents ev=(UIControlEvents)evn.unsignedLongLongValue; for(NSString *action in [control actionsForTarget:target forControlEvent:ev]?:@[]){SEL sel=NSSelectorFromString(action); Method method=sel?class_getInstanceMethod(object_getClass(target),sel):NULL; IMP imp=method?method_getImplementation(method):NULL; NSMutableDictionary *a=[@{@"selector":action?:@"",@"typeEncoding":method&&method_getTypeEncoding(method)?[NSString stringWithUTF8String:method_getTypeEncoding(method)]:@"",@"event":ev==UIControlEventTouchUpInside?@"touch-up-inside":@"value-changed",@"implementation":HFAHex((uint64_t)(uintptr_t)imp),@"selectorInvokedByResolver":@NO} mutableCopy]; NSDictionary *ctx=imp?HFAAddressContext((uint64_t)(uintptr_t)imp,images):nil; if(ctx)a[@"addressContext"]=ctx; [actions addObject:a]; [a release];}}
            if(![seenRoots containsObject:target]&&objects.count<kHFARootMaxRoots){[seenRoots addObject:target];[objects addObject:target];}
            [roots addObject:@{@"source":@"ui-control-target-action",@"label":HFAControlLabel(control),@"controlToken":[NSString stringWithFormat:@"%p",control],@"controlClass":NSStringFromClass(object_getClass(control))?:@"",@"targetToken":[NSString stringWithFormat:@"%p",target],@"targetClass":NSStringFromClass(object_getClass(target))?:@"",@"targetImage":HFAImageForObject(target),@"actions":actions}];
        }
    }
    return @{@"records":roots,@"objects":objects,@"viewCount":@(seenViews.count),@"controlCount":@(controls)};
}

static NSArray *HFAObservedImageSnapshot(void){NSMutableArray *a=[NSMutableArray array]; uint32_t count=MIN(gHFAObservedImageCount,(uint32_t)kHFARootMaxObservedImages); for(uint32_t o=0;o<count;o++){const struct mach_header *header=gHFAObservedImages[o].header; for(uint32_t i=0;i<_dyld_image_count();i++){if(_dyld_get_image_header(i)!=header)continue; const char *raw=_dyld_get_image_name(i); NSString *p=raw?[NSString stringWithUTF8String:raw]:@""; [a addObject:@{@"path":p?:@"",@"fileName":p.lastPathComponent?:@"",@"header":HFAHex((uint64_t)(uintptr_t)header),@"slide":@((long long)gHFAObservedImages[o].slide)}]; break;}} return a;}

static NSDictionary *HFAResolveOnMain(NSString *path, NSDictionary *loaded, NSError **error){
    NSString *menuImage=path.lastPathComponent?:@""; if(!menuImage.length){if(error)*error=[NSError errorWithDomain:@"com.hfa.runtime-root-graph" code:1 userInfo:@{NSLocalizedDescriptionKey:@"missing-menu-image"}]; return nil;}
    NSArray *images=HFAAllImages(); NSDictionary *ui=HFAUIRoots(menuImage,images); NSDictionary *graph=HFABuildGraph(ui[@"objects"]?:@[],ui[@"records"]?:@[],menuImage,images);
    NSDictionary *result=@{@"schema":@"com.hfa.runtime-root-graph/v1",@"buildVersion":@"2.5.9-dev",@"componentVersion":@"2.5.9-dev-runtime-root-descriptor-graph",@"policy":@"UNIVERSAL-ROOTED-READ-ONLY-NO-SAMPLE-SPECIAL-CASES",@"menuImage":menuImage,@"menuPath":path?:@"",@"uiInventory":@{@"viewCount":ui[@"viewCount"]?:@0,@"controlCount":ui[@"controlCount"]?:@0},@"dyldObserver":@{@"registered":@YES,@"observedImageCount":@(gHFAObservedImageCount),@"images":HFAObservedImageSnapshot()},@"graph":graph,@"loadedEvidenceSummary":@{@"classCount":loaded[@"classCount"]?:@0,@"instanceCount":loaded[@"instanceCount"]?:@0,@"globalRelationCount":loaded[@"globalRelationCount"]?:@0,@"recordCandidateCount":loaded[@"recordCandidateCount"]?:@0},@"safety":@{@"knownUIKitFoundationSelectorsInvoked":@YES,@"unknownSelectorInvoked":@NO,@"impReplaced":@NO,@"inlineHookInstalled":@NO,@"memoryWritten":@NO,@"gameStateWritten":@NO,@"objectGraphReadOnly":@YES}};
    HFADiagnosticsLog(@"runtime-root-graph",@"complete",@{@"menuImage":menuImage,@"rootCount":graph[@"rootCount"]?:@0,@"nodeCount":graph[@"nodeCount"]?:@0,@"descriptorCandidateCount":graph[@"descriptorCandidateCount"]?:@0,@"memoryWritten":@NO}); return result;
}

NSDictionary *HFAMapResolveRuntimeRootGraph(NSString *path, NSDictionary *loaded, NSError **error){
    if(NSThread.isMainThread)return HFAResolveOnMain(path,loaded?:@{},error);
    __block NSDictionary *result=nil; __block NSError *inner=nil; dispatch_sync(dispatch_get_main_queue(),^{result=[HFAResolveOnMain(path,loaded?:@{},&inner) retain]; [inner retain];}); if(error&&inner)*error=[inner autorelease]; else [inner release]; return [result autorelease];
}
BOOL HFAMapPersistRuntimeRootGraph(NSDictionary *graph,NSError **error){if(!graph)return NO; NSData *json=[NSJSONSerialization dataWithJSONObject:graph options:NSJSONWritingPrettyPrinted error:error]; if(!json)return NO; NSString *docs=[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject]; if(!docs.length)return NO; NSString *path=[docs stringByAppendingPathComponent:HFAOutputFileName(@"RuntimeRootGraph.json")]; BOOL ok=[json writeToFile:path options:NSDataWritingAtomic error:error]; HFADiagnosticsLog(@"runtime-root-graph",ok?@"persisted":@"persist-failed",@{@"output":path?:@""}); return ok;}
