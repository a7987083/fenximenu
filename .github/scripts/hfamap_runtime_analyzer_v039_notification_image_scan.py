from pathlib import Path

P=Path('hfamap/src/HFAMap5MDispatcherResolver.m')
s=P.read_text()

extern='extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);'
anchor='static NSMutableDictionary<NSString *, NSMutableDictionary *> *gHFA5MFeatures;'
if extern not in s:
    if anchor not in s: raise SystemExit('v039 dispatcher extern anchor missing')
    s=s.replace(anchor,extern+'\n\n'+anchor,1)

reset='void HFA5MDispatcherReset(void) {'
if reset not in s: raise SystemExit('v039 dispatcher reset anchor missing')
if 'HFA5MImageObserverBridgesForNotification' not in s:
    helper=r'''
static NSArray *HFA5MImageObserverBridgesForNotification(NSString *image, NSString *notification) {
    if(!image.length||!notification.length)return @[];
    static NSMutableDictionary *cache=nil;
    NSString *key=[NSString stringWithFormat:@"%@|%@",image,notification];
    @synchronized([NSObject class]){if(!cache)cache=[NSMutableDictionary dictionary];NSArray *hit=cache[key];if(hit)return hit;}
    Class classes[768]={0};unsigned classCount=HFAAppLocalCopyClassesForImage(image.UTF8String,classes,768);
    NSMutableArray *out=[NSMutableArray array];NSUInteger methodCount=0;BOOL budgetExceeded=NO;CFAbsoluteTime started=CFAbsoluteTimeGetCurrent();
    for(unsigned ci=0;ci<classCount&&ci<768&&!budgetExceeded;ci++){
        Class cls=classes[ci];if(!cls)continue;
        for(int pass=0;pass<2&&!budgetExceeded;pass++){
            Class owner=pass?object_getClass(cls):cls;if(!owner)continue;unsigned count=0;Method *methods=class_copyMethodList(owner,&count);
            for(unsigned mi=0;methods&&mi<count;mi++){
                if(methodCount>=320||CFAbsoluteTimeGetCurrent()-started>0.30){budgetExceeded=YES;break;}methodCount++;
                SEL sel=method_getName(methods[mi]);IMP imp=method_getImplementation(methods[mi]);NSDictionary *scan=HFA5MScanMethod(owner,sel,imp);if(!scan.count)continue;
                NSArray *regs=[scan[@"observerRegistrations"] isKindOfClass:NSArray.class]?scan[@"observerRegistrations"]:@[];
                for(NSDictionary *reg in regs){if(![[reg[@"name"] description] isEqual:notification])continue;NSMutableDictionary *bridge=[scan mutableCopy];bridge[@"observerRegistration"]=reg;bridge[@"observerSelector"]=reg[@"registrationSelector"]?:@"unknown";bridge[@"observerClass"]=[NSString stringWithUTF8String:class_getName(cls)?:"?"]?:@"?";bridge[@"discovery"]=@"image-wide-notification-registration";HFA5MAppendUnique(out,bridge,@[@"image",@"rva",@"observerSelector"]);if(out.count>=24)break;}
                if(out.count>=24)break;
            }
            free(methods);if(out.count>=24)break;
        }
    }
    HFA5MLog([NSString stringWithFormat:@"[V039-NOTIFY-XREF] image=%@ notification=%@ classes=%u methods=%lu bridges=%lu budget=%@",image,notification,classCount,(unsigned long)methodCount,(unsigned long)out.count,budgetExceeded?@"exceeded":@"ok"]);
    NSArray *result=[out copy];@synchronized([NSObject class]){cache[key]=result;}return result;
}
'''
    s=s.replace(reset,helper+'\n'+reset,1)

old='NSArray *bridges = HFA5MObserverBridgesForNotification(cls, name);'
new='NSDictionary *ai=[resolved[@"action"] isKindOfClass:NSDictionary.class]?resolved[@"action"]:nil;NSString *actionImage=[ai[@"image"] isKindOfClass:NSString.class]?ai[@"image"]:nil;NSArray *bridges=actionImage.length?HFA5MImageObserverBridgesForNotification(actionImage,name):HFA5MObserverBridgesForNotification(cls,name);'
if old not in s: raise SystemExit('v039 observer call anchor missing')
s=s.replace(old,new,1)

P.write_text(s)
for required in ['HFA5MImageObserverBridgesForNotification','[V039-NOTIFY-XREF]','image-wide-notification-registration','HFAAppLocalCopyClassesForImage']:
    if required not in s: raise SystemExit('missing '+required)
for forbidden in ['0x2D98AC8','0x2D9887C','0x2E25904']:
    if forbidden in s: raise SystemExit('fixed RVA leaked into v039 dispatcher layer')
print('v0.3.9 image-wide notification consumer discovery applied')
