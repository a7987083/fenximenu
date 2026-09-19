#import "ZPContainerResolver.h"
#import "ZPEvidenceGraph.h"
#import "ZPFeatureResolver.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

// v0.4.2: capture follows the v2.2.3 proven two-pass shape.
// Main-thread capture only snapshots UI roots/targets. Evidence-graph mutation,
// container traversal and ivar inspection happen later on the worker queue.
static const NSUInteger kMaxViews=768,kMaxTargets=192,kMaxContainers=256,kMaxChildren=64,kMaxFields=48;
static NSString *ZPPtr(id o){return [NSString stringWithFormat:@"0x%llX",(unsigned long long)(uintptr_t)(__bridge const void*)o];}
static NSString *ZPImageForObject(id o){if(!o)return @"";const char *p=class_getImageName(object_getClass(o));return p?[[NSString stringWithUTF8String:p] lastPathComponent]:@"";}
static BOOL ZPCandidateOwned(id o,NSString *image){return o&&image.length&&[ZPImageForObject(o) isEqualToString:image];}
static NSString *ZPNormalizeKey(NSString *k){if(!k.length)return @"";while([k hasPrefix:@"_"])k=[k substringFromIndex:1];return k.lowercaseString;}

static NSDictionary *ZPObjectDictionary(id o){
    if(!o)return nil;if([o isKindOfClass:NSDictionary.class])return o;
    NSMutableDictionary *d=[NSMutableDictionary dictionary];NSUInteger depth=0;
    for(Class c=object_getClass(o);c&&c!=NSObject.class&&depth++<12;c=class_getSuperclass(c)){
        unsigned count=0;Ivar *iv=class_copyIvarList(c,&count);count=MIN(count,64U);
        for(unsigned i=0;i<count;i++){
            const char *name=ivar_getName(iv[i]),*enc=ivar_getTypeEncoding(iv[i]);if(!name||!enc||enc[0]!='@')continue;
            id v=nil;@try{v=object_getIvar(o,iv[i]);}@catch(__unused id e){v=nil;}if(v)d[[NSString stringWithUTF8String:name]]=v;
        }
        free(iv);
    }
    return d.count?d:nil;
}
static id ZPValueForAliases(NSDictionary *d,NSArray<NSString*> *aliases){
    if(!d.count)return nil;for(NSString *key in d){if(![key isKindOfClass:NSString.class])continue;NSString *n=ZPNormalizeKey(key);for(NSString *a in aliases)if([n isEqualToString:a])return d[key];}return nil;
}
static NSString *ZPStringValue(id v){if([v isKindOfClass:NSString.class])return v;if([v isKindOfClass:NSNumber.class])return [(NSNumber*)v stringValue];return nil;}
static NSString *ZPControlLabel(UIControl *c){
    if([c isKindOfClass:UIButton.class]){NSString *s=[(UIButton*)c titleForState:UIControlStateNormal];if(s.length)return s;}
    if(c.accessibilityLabel.length)return c.accessibilityLabel;
    UIView *scope=c;
    for(NSUInteger depth=0;scope&&depth<3;depth++,scope=scope.superview){
        NSMutableArray<UIView*> *q=[NSMutableArray arrayWithObject:scope];
        for(NSUInteger i=0;i<q.count&&i<32;i++){UIView *v=q[i];if([v isKindOfClass:UILabel.class]&&[(UILabel*)v text].length)return [(UILabel*)v text];for(UIView *s in v.subviews)if(q.count<32)[q addObject:s];}
    }
    return @"";
}
static NSArray<UIView*> *ZPCollectRoots(NSTimeInterval deadline){
    NSMutableArray<UIView*> *roots=[NSMutableArray array],*queue=[NSMutableArray array];
    for(UIWindow *w in UIApplication.sharedApplication.windows)if(w)[queue addObject:w];
    NSHashTable *seen=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    while(queue.count&&roots.count<kMaxViews&&NSDate.date.timeIntervalSince1970<=deadline){
        UIView *v=queue.firstObject;[queue removeObjectAtIndex:0];if([seen containsObject:v])continue;[seen addObject:v];[roots addObject:v];
        for(UIView *s in v.subviews)if(queue.count+roots.count<kMaxViews)[queue addObject:s];
    }
    return roots;
}
static NSDictionary *ZPFieldEvidence(id object){
    if(!object)return @{};Class cls=object_getClass(object);NSUInteger size=class_getInstanceSize(cls);if(!cls||size==0||size>1024)return @{};
    NSMutableArray *fields=[NSMutableArray array];NSUInteger depth=0;
    for(Class c=cls;c&&c!=NSObject.class&&fields.count<kMaxFields&&depth++<12;c=class_getSuperclass(c)){
        unsigned count=0;Ivar *iv=class_copyIvarList(c,&count);count=MIN(count,64U);
        for(unsigned i=0;i<count&&fields.count<kMaxFields;i++){
            const char *name=ivar_getName(iv[i]),*enc=ivar_getTypeEncoding(iv[i]);if(!name||!enc)continue;
            NSMutableDictionary *e=[@{@"field":[NSString stringWithUTF8String:name],@"encoding":[NSString stringWithUTF8String:enc],@"ivarOffset":[NSString stringWithFormat:@"0x%tx",ivar_getOffset(iv[i])],@"offsetSemantics":@"objc-instance-ivar-only"} mutableCopy];
            if(enc[0]=='@'){
                id v=nil;@try{v=object_getIvar(object,iv[i]);}@catch(__unused id ex){v=nil;}
                if(v){e[@"valueClass"]=NSStringFromClass(object_getClass(v))?:@"?";e[@"pointer"]=ZPPtr(v);if([v isKindOfClass:NSString.class])e[@"value"]=[(NSString*)v length]>160?[(NSString*)v substringToIndex:160]:v;else if([v isKindOfClass:NSNumber.class])e[@"value"]=v;else if([v isKindOfClass:NSData.class]){NSData *data=v;NSUInteger n=MIN((NSUInteger)32,data.length);const uint8_t *b=static_cast<const uint8_t *>(data.bytes);NSMutableString *h=[NSMutableString string];for(NSUInteger j=0;j<n;j++)[h appendFormat:@"%02X",b[j]];e[@"hexPrefix"]=h;e[@"byteLength"]=@(data.length);}}
            }
            [fields addObject:e];
        }
        free(iv);
    }
    return @{@"class":NSStringFromClass(cls)?:@"?",@"instanceSize":@(size),@"offsetSemantics":@"objc-instance-ivar-only",@"fields":fields};
}

NSDictionary *ZPContainerCaptureSeeds(NSString *candidateImage,NSTimeInterval deadline){
    NSCAssert(NSThread.isMainThread,@"ZPContainerCaptureSeeds must run on main thread");
    NSArray<UIView*> *roots=ZPCollectRoots(deadline);NSHashTable *seenTargets=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];NSMutableArray *seeds=[NSMutableArray array];
    for(UIView *view in roots){
        if(NSDate.date.timeIntervalSince1970>deadline)break;if(![view isKindOfClass:UIControl.class])continue;
        UIControl *control=(UIControl*)view;NSString *label=ZPControlLabel(control);
        for(id target in control.allTargets){
            if(seenTargets.count>=kMaxTargets||[seenTargets containsObject:target])continue;if(!ZPCandidateOwned(target,candidateImage))continue;[seenTargets addObject:target];
            [seeds addObject:@{@"value":target,@"label":label?:@"",@"class":NSStringFromClass(object_getClass(target))?:@"?",@"controlClass":NSStringFromClass(object_getClass(control))?:@"?",@"image":candidateImage?:@"",@"pointer":ZPPtr(target)}];
        }
    }
    return @{@"status":NSDate.date.timeIntervalSince1970>deadline?@"timeout":@"complete",@"seeds":seeds,@"metrics":@{@"views":@(roots.count),@"targets":@(seenTargets.count),@"seedCount":@(seeds.count)}};
}

NSDictionary *ZPContainerResolve(NSString *candidateImage,NSDictionary *snapshot,NSTimeInterval deadline){
    NSMutableArray *containers=[NSMutableArray arrayWithArray:snapshot[@"seeds"]?:@[]],*registry=[NSMutableArray array],*descriptors=[NSMutableArray array];
    NSHashTable *seen=[NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    for(NSUInteger cursor=0;cursor<containers.count&&cursor<kMaxContainers&&NSDate.date.timeIntervalSince1970<=deadline;cursor++){
        NSDictionary *seed=containers[cursor];id object=seed[@"value"];if(!object||[seen containsObject:object])continue;[seen addObject:object];NSDictionary *d=ZPObjectDictionary(object);if(!d)continue;
        NSString *label=ZPStringValue(ZPValueForAliases(d,@[@"label",@"title",@"name",@"displayname"]));if(!label.length)label=seed[@"label"]?:@"";
        NSString *identifier=ZPStringValue(ZPValueForAliases(d,@[@"identifier",@"id"]));
        NSString *parent=seed[@"targetNode"];
        if(![parent isKindOfClass:NSString.class]||!parent.length){NSString *uiNode=ZPEvidenceGraphAddNode(@"ui-control",@{@"label":seed[@"label"]?:@"",@"class":seed[@"controlClass"]?:@"?",@"source":@"auxiliary"});parent=ZPEvidenceGraphAddNode(@"menu-target",@{@"class":seed[@"class"]?:NSStringFromClass(object_getClass(object))?:@"?",@"image":seed[@"image"]?:candidateImage?:@"",@"pointer":seed[@"pointer"]?:ZPPtr(object)});ZPEvidenceGraphAddEdge(uiNode,@"targets",parent,@{@"strength":@"auxiliary"});}
        NSString *containerNode=ZPEvidenceGraphAddNode(@"container",@{@"class":NSStringFromClass(object_getClass(object))?:@"?",@"pointer":ZPPtr(object),@"image":ZPImageForObject(object)?:@""});ZPEvidenceGraphAddEdge(parent,@"reaches",containerNode,@{@"strength":@"structural"});
        if(label.length&&identifier.length){NSDictionary *feature=@{@"identifier":identifier,@"label":label,@"key":[identifier hasSuffix:@"-switch"]?identifier:[identifier stringByAppendingString:@"-switch"],@"source":@"feature-container",@"class":NSStringFromClass(object_getClass(object))?:@"?",@"evidenceRank":@100};[registry addObject:feature];ZPFeatureResolverMergeContainerFeatures(@[feature]);NSString *featureNode=ZPEvidenceGraphAddNode(@"feature",feature);ZPEvidenceGraphAddEdge(containerNode,@"defines",featureNode,@{@"strength":@"primary",@"reason":@"same-container-label-identifier"});}
        for(NSString *key in d){id value=d[key];if([value isKindOfClass:NSArray.class]){NSUInteger idx=0;for(id child in (NSArray*)value){if(idx++>=kMaxChildren||containers.count>=kMaxContainers)break;if(ZPCandidateOwned(child,candidateImage)){NSDictionary *ev=ZPFieldEvidence(child);if(ev.count){NSMutableDictionary *r=[ev mutableCopy];r[@"arrayField"]=key;r[@"index"]=@(idx-1);r[@"containerLabel"]=label?:@"";r[@"containerIdentifier"]=identifier?:@"";[descriptors addObject:r];NSString *descriptorNode=ZPEvidenceGraphAddNode(@"descriptor",@{@"class":ev[@"class"]?:@"?",@"instanceSize":ev[@"instanceSize"]?:@0,@"pointer":ZPPtr(child),@"image":candidateImage?:@""});ZPEvidenceGraphAddEdge(containerNode,@"contains-descriptor",descriptorNode,@{@"arrayField":key,@"index":@(idx-1),@"strength":label.length&&identifier.length?@"primary":@"structural"});for(NSDictionary *f in ev[@"fields"]?:@[]){NSString *fieldNode=ZPEvidenceGraphAddNode(@"objc-ivar",f);ZPEvidenceGraphAddEdge(descriptorNode,@"has-ivar",fieldNode,@{@"addressSemantics":@"objc-instance-ivar-only"});}}[containers addObject:@{@"value":child,@"label":label?:@"",@"targetNode":containerNode}];}else if([child isKindOfClass:NSDictionary.class]||[child isKindOfClass:NSArray.class])[containers addObject:@{@"value":child,@"label":label?:@"",@"targetNode":containerNode}];}}
            else if([value isKindOfClass:NSDictionary.class]||ZPCandidateOwned(value,candidateImage)){if(containers.count<kMaxContainers)[containers addObject:@{@"value":value,@"label":label?:@"",@"targetNode":containerNode}];}}
    }
    return @{@"status":NSDate.date.timeIntervalSince1970>deadline?@"timeout":@"complete",@"registry":registry,@"descriptorEvidence":descriptors,@"metrics":@{@"containers":@(MIN(containers.count,kMaxContainers)),@"features":@(registry.count),@"descriptors":@(descriptors.count)}};
}
