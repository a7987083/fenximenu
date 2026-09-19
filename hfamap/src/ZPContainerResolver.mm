#import "ZPContainerResolver.h"
#import "ZPEvidenceGraph.h"
#import "ZPFeatureResolver.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static const NSUInteger kMaxViews=2048,kMaxTargets=128,kMaxContainers=256,kMaxChildren=64,kMaxFields=48,kMaxClassDepth=12;
static NSString *ZPPtr(id o){return [NSString stringWithFormat:@"0x%llX",(unsigned long long)(uintptr_t)(__bridge const void*)o];}
static NSString *ZPImageForObject(id o){if(!o)return @"";const char *p=class_getImageName(object_getClass(o));return p?[[NSString stringWithUTF8String:p] lastPathComponent]:@"";}
static BOOL ZPCandidateOwned(id o,NSString *image){return o&&image.length&&[ZPImageForObject(o) isEqualToString:image];}
static NSString *ZPNormalizeKey(NSString *k){if(!k.length)return @"";while([k hasPrefix:@"_"])k=[k substringFromIndex:1];return k.lowercaseString;}
static NSDictionary *ZPObjectDictionary(id o){
    if(!o)return nil;if([o isKindOfClass:NSDictionary.class])return o;
    NSMutableDictionary *d=[NSMutableDictionary dictionary];NSUInteger depth=0;
    for(Class c=object_getClass(o);c&&c!=NSObject.class&&depth<kMaxClassDepth;c=class_getSuperclass(c),depth++){
        unsigned count=0;Ivar *iv=class_copyIvarList(c,&count);count=MIN(count,64U);
        for(unsigned i=0;i<count;i++){
            const char *name=ivar_getName(iv[i]),*enc=ivar_getTypeEncoding(iv[i]);if(!name||!enc||enc[0]!='@')continue;
            id v=nil;@try{v=object_getIvar(o,iv[i]);}@catch(__unused id e){v=nil;}if(v)d[[NSString stringWithUTF8String:name]]=v;
        }
        free(iv);
    }
    return d.count?d:nil;
}
static id ZPValueForAliases(NSDictionary *d,NSArray<NSString*> *aliases){if(!d.count)return nil;for(id key in d){if(![key isKindOfClass:NSString.class])continue;NSString *n=ZPNormalizeKey(key);for(NSString *a in aliases)if([n isEqualToString:a])return d[key];}return nil;}
static NSString *ZPStringValue(id v){if([v isKindOfClass:NSString.class])return v;if([v isKindOfClass:NSNumber.class])return [(NSNumber*)v stringValue];return nil;}
static NSString *ZPControlLabel(UIControl *c){if([c isKindOfClass:UIButton.class]){NSString *s=[(UIButton*)c titleForState:UIControlStateNormal];if(s.length)return s;}if(c.accessibilityLabel.length)return c.accessibilityLabel;return @"";}
static NSDictionary *ZPFieldEvidence(id object){
    if(!object)return @{};Class cls=object_getClass(object);size_t instanceSize=cls?class_getInstanceSize(cls):0;
    if(!cls||instanceSize==0||instanceSize>1024)return @{@"class":cls?(NSStringFromClass(cls)?:@"?"):@"?",@"instanceSize":@(instanceSize),@"offsetSemantics":@"objc-instance-ivar-only",@"fields":@[],@"reason":@"instance-size-out-of-range"};
    NSMutableArray *fields=[NSMutableArray array];NSUInteger depth=0;
    for(Class c=cls;c&&c!=NSObject.class&&fields.count<kMaxFields&&depth<kMaxClassDepth;c=class_getSuperclass(c),depth++){
        unsigned count=0;Ivar *iv=class_copyIvarList(c,&count);count=MIN(count,64U);
        for(unsigned i=0;i<count&&fields.count<kMaxFields;i++){
            const char *name=ivar_getName(iv[i]),*enc=ivar_getTypeEncoding(iv[i]);if(!name||!enc)continue;ptrdiff_t off=ivar_getOffset(iv[i]);
            if(off<0||(size_t)off>=instanceSize)continue;
            NSMutableDictionary *e=[@{@"field":[NSString stringWithUTF8String:name],@"encoding":[NSString stringWithUTF8String:enc],@"ivarOffset":[NSString stringWithFormat:@"0x%tx",off],@"offsetSemantics":@"objc-instance-ivar-only"} mutableCopy];
            if(enc[0]=='@'){
                id v=nil;@try{v=object_getIvar(object,iv[i]);}@catch(__unused id ex){v=nil;}
                if(v){e[@"valueClass"]=NSStringFromClass(object_getClass(v))?:@"?";e[@"pointer"]=ZPPtr(v);if([v isKindOfClass:NSString.class])e[@"value"]=[(NSString*)v length]>160?[(NSString*)v substringToIndex:160]:v;else if([v isKindOfClass:NSNumber.class])e[@"value"]=v;else if([v isKindOfClass:NSData.class]){NSData *data=v;NSUInteger n=MIN((NSUInteger)32,data.length);const uint8_t *b=static_cast<const uint8_t *>(data.bytes);NSMutableString *h=[NSMutableString string];for(NSUInteger j=0;j<n;j++)[h appendFormat:@"%02X",b[j]];e[@"hexPrefix"]=h;e[@"byteLength"]=@(data.length);}}
            }
            [fields addObject:e];
        }
        free(iv);
    }
    return @{@"class":NSStringFromClass(cls)?:@"?",@"instanceSize":@(instanceSize),@"offsetSemantics":@"objc-instance-ivar-only",@"fields":fields};
}
NSDictionary *ZPContainerCaptureSeeds(NSString *candidateImage,NSTimeInterval deadline){
    NSCAssert(NSThread.isMainThread,@"ZPContainerCaptureSeeds must run on main thread");
    NSMutableArray *queue=[NSMutableArray array],*seeds=[NSMutableArray array];for(UIWindow *w in UIApplication.sharedApplication.windows)if(w)[queue addObject:w];
    NSHashTable *seen=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality],*targets=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];NSUInteger views=0;
    while(queue.count&&views<kMaxViews&&NSDate.date.timeIntervalSince1970<=deadline){UIView *v=queue.firstObject;[queue removeObjectAtIndex:0];if([seen containsObject:v])continue;[seen addObject:v];views++;if([v isKindOfClass:UIControl.class]){UIControl *c=(UIControl*)v;NSString *label=ZPControlLabel(c);for(id t in c.allTargets){if(targets.count>=kMaxTargets)break;if([targets containsObject:t]||!ZPCandidateOwned(t,candidateImage))continue;[targets addObject:t];NSString *uiNode=ZPEvidenceGraphAddNode(@"ui-control",@{@"label":label?:@"",@"class":NSStringFromClass(object_getClass(c))?:@"?",@"source":@"auxiliary"});NSString *targetNode=ZPEvidenceGraphAddNode(@"menu-target",@{@"class":NSStringFromClass(object_getClass(t))?:@"?",@"image":candidateImage?:@"",@"pointer":ZPPtr(t)});ZPEvidenceGraphAddEdge(uiNode,@"targets",targetNode,@{@"strength":@"auxiliary"});[seeds addObject:@{@"value":t,@"label":label?:@"",@"targetNode":targetNode}];}}
        for(UIView *s in v.subviews)if(queue.count+views<kMaxViews)[queue addObject:s];
    }
    return @{@"status":NSDate.date.timeIntervalSince1970>deadline?@"timeout":@"complete",@"seeds":seeds,@"metrics":@{@"views":@(views),@"targets":@(targets.count),@"seedCount":@(seeds.count)}};
}
NSDictionary *ZPContainerResolve(NSString *candidateImage,NSDictionary *snapshot,NSTimeInterval deadline){
    NSMutableArray *containers=[NSMutableArray arrayWithArray:snapshot[@"seeds"]?:@[]],*registry=[NSMutableArray array],*descriptors=[NSMutableArray array];NSHashTable *seen=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    for(NSUInteger cursor=0;cursor<containers.count&&cursor<kMaxContainers&&NSDate.date.timeIntervalSince1970<=deadline;cursor++){
        id object=containers[cursor][@"value"];if(!object||[seen containsObject:object])continue;[seen addObject:object];NSDictionary *d=ZPObjectDictionary(object);if(!d)continue;
        NSString *label=ZPStringValue(ZPValueForAliases(d,@[@"label",@"title",@"name",@"displayname"]));NSString *identifier=ZPStringValue(ZPValueForAliases(d,@[@"identifier",@"id"]));NSString *containerNode=ZPEvidenceGraphAddNode(@"container",@{@"class":NSStringFromClass(object_getClass(object))?:@"?",@"pointer":ZPPtr(object),@"image":ZPImageForObject(object)?:@""});NSString *parent=containers[cursor][@"targetNode"];if([parent isKindOfClass:NSString.class])ZPEvidenceGraphAddEdge(parent,@"reaches",containerNode,@{@"strength":@"structural"});
        if(label.length&&identifier.length){NSDictionary *feature=@{@"identifier":identifier,@"label":label,@"key":[identifier hasSuffix:@"-switch"]?identifier:[identifier stringByAppendingString:@"-switch"],@"source":@"feature-container",@"class":NSStringFromClass(object_getClass(object))?:@"?",@"evidenceRank":@100};[registry addObject:feature];ZPFeatureResolverMergeContainerFeatures(@[feature]);NSString *featureNode=ZPEvidenceGraphAddNode(@"feature",feature);ZPEvidenceGraphAddEdge(containerNode,@"defines",featureNode,@{@"strength":@"primary",@"reason":@"same-container-label-identifier"});}
        for(id key in d){if(![key isKindOfClass:NSString.class])continue;id value=d[key];if([value isKindOfClass:NSArray.class]){NSUInteger idx=0;for(id child in (NSArray*)value){if(idx++>=kMaxChildren||containers.count>=kMaxContainers)break;if(ZPCandidateOwned(child,candidateImage)){NSDictionary *ev=ZPFieldEvidence(child);NSMutableDictionary *r=[ev mutableCopy];r[@"arrayField"]=key;r[@"index"]=@(idx-1);r[@"containerLabel"]=label?:@"";r[@"containerIdentifier"]=identifier?:@"";[descriptors addObject:r];NSString *descriptorNode=ZPEvidenceGraphAddNode(@"descriptor",@{@"class":ev[@"class"]?:@"?",@"instanceSize":ev[@"instanceSize"]?:@0,@"pointer":ZPPtr(child),@"image":candidateImage?:@""});ZPEvidenceGraphAddEdge(containerNode,@"contains-descriptor",descriptorNode,@{@"arrayField":key,@"index":@(idx-1),@"strength":label.length&&identifier.length?@"primary":@"structural"});for(NSDictionary *f in ev[@"fields"]?:@[]){NSString *fieldNode=ZPEvidenceGraphAddNode(@"objc-ivar",f);ZPEvidenceGraphAddEdge(descriptorNode,@"has-ivar",fieldNode,@{@"addressSemantics":@"objc-instance-ivar-only"});}[containers addObject:@{@"value":child,@"label":label?:@"",@"targetNode":containerNode}];}else if([child isKindOfClass:NSDictionary.class]||[child isKindOfClass:NSArray.class])[containers addObject:@{@"value":child,@"label":label?:@"",@"targetNode":containerNode}];}}
            else if([value isKindOfClass:NSDictionary.class]||[value isKindOfClass:NSArray.class]){if(containers.count<kMaxContainers)[containers addObject:@{@"value":value,@"label":label?:@"",@"targetNode":containerNode}];}
            else if(![value isKindOfClass:NSString.class]&&![value isKindOfClass:NSNumber.class]&&![value isKindOfClass:NSData.class]&&ZPCandidateOwned(value,candidateImage)){if(containers.count<kMaxContainers)[containers addObject:@{@"value":value,@"label":label?:@"",@"targetNode":containerNode}];}}
    }
    return @{@"status":NSDate.date.timeIntervalSince1970>deadline?@"timeout":@"complete",@"registry":registry,@"descriptorEvidence":descriptors,@"metrics":@{@"containers":@(MIN(containers.count,kMaxContainers)),@"features":@(registry.count),@"descriptors":@(descriptors.count)}};
}
