from pathlib import Path

P=Path('hfamap/src/HFAMap5MDispatcherResolver.m')
s=P.read_text()

def once(old,new,label):
    global s
    n=s.count(old)
    if n!=1: raise SystemExit(f'{label}: expected 1 match, got {n}')
    s=s.replace(old,new,1)

vars='''    NSMutableOrderedSet<NSString *> *selectorNames = [NSMutableOrderedSet orderedSet];\n    NSMutableArray<NSDictionary *> *notifications = [NSMutableArray array];'''
once(vars,vars+'\n    NSMutableArray<NSDictionary *> *observerRegistrations = [NSMutableArray array];','observer vars')

post='''            if (strcmp(name, "postNotificationName:object:userInfo:") == 0) {\n                NSUInteger upper = MIN(count, j + 8);\n                for (NSUInteger k = j + 1; k < upper; k++) {\n                    unsigned cfReg = 0;\n                    uintptr_t cfPage = 0;\n                    uintptr_t cfPC = start + k * 4;\n                    if (!HFA5MDecodeADRP(words[k], cfPC, &cfReg, &cfPage)) continue;\n                    for (NSUInteger q = k + 1; q < upper && q <= k + 3; q++) {\n                        unsigned rd = 0, rn2 = 0;\n                        uint64_t cfOffset = 0;\n                        if (!HFA5MDecodeADDX(words[q], &rd, &rn2, &cfOffset) || rd != 2 || rn2 != cfReg) continue;\n                        NSString *notification = HFA5MConstantStringAt(cfPage + (uintptr_t)cfOffset, layout);\n                        if (notification.length) {\n                            NSDictionary *entry = @{ @"name": notification,\n                                                     @"selector": @"postNotificationName:object:userInfo:" };\n                            HFA5MAppendUnique(notifications, entry, @[@"name", @"selector"]);\n                        }\n                        break;\n                    }\n                    if (notifications.count) break;\n                }\n            }'''
extra=post+r'''
            if (strcmp(name, "addObserver:selector:name:object:") == 0) {
                NSUInteger upper=MIN(count,j+18); SEL cbSEL=NULL; NSString *notification=nil;
                for(NSUInteger k=j+1;k<upper;k++){
                    unsigned rg=0; uintptr_t pg=0; if(!HFA5MDecodeADRP(words[k],start+k*4,&rg,&pg))continue;
                    for(NSUInteger q=k+1;q<upper&&q<=k+3;q++){
                        unsigned rt=0,rn=0,rd=0; uint64_t of=0;
                        if(!cbSEL&&HFA5MDecodeLDRX(words[q],&rt,&rn,&of)&&rt==3&&rn==rg)cbSEL=HFA5MSelectorFromSlot(pg+(uintptr_t)of,layout);
                        if(!notification&&HFA5MDecodeADDX(words[q],&rd,&rn,&of)&&rd==4&&rn==rg)notification=HFA5MConstantStringAt(pg+(uintptr_t)of,layout);
                    }
                }
                if(cbSEL&&notification.length){
                    NSMutableDictionary *e=[@{@"name":notification,@"registrationSelector":@"addObserver:selector:name:object:",@"callbackSelector":NSStringFromSelector(cbSEL),@"callbackResolved":@NO} mutableCopy];
                    Method m=class_getInstanceMethod(cls,cbSEL); if(m){NSDictionary *a=HFA5MAddressInfo((const void*)method_getImplementation(m));if(a){NSMutableDictionary *c=[a mutableCopy];c[@"selector"]=NSStringFromSelector(cbSEL);e[@"callback"]=c;e[@"callbackResolved"]=@YES;}}
                    HFA5MAppendUnique(observerRegistrations,e,@[@"name",@"callbackSelector"]);
                }
            }
            if (strcmp(name, "addObserverForName:object:queue:usingBlock:") == 0) {
                NSUInteger upper=MIN(count,j+18);NSString *notification=nil;
                for(NSUInteger k=j+1;k<upper&&!notification;k++){
                    unsigned rg=0;uintptr_t pg=0;if(!HFA5MDecodeADRP(words[k],start+k*4,&rg,&pg))continue;
                    for(NSUInteger q=k+1;q<upper&&q<=k+3;q++){unsigned rd=0,rn=0;uint64_t of=0;if(HFA5MDecodeADDX(words[q],&rd,&rn,&of)&&rd==2&&rn==rg){notification=HFA5MConstantStringAt(pg+(uintptr_t)of,layout);if(notification)break;}}
                }
                if(notification.length){NSDictionary *e=@{@"name":notification,@"registrationSelector":@"addObserverForName:object:queue:usingBlock:",@"callbackResolved":@NO};HFA5MAppendUnique(observerRegistrations,e,@[@"name",@"registrationSelector"]);}
            }'''
once(post,extra,'observer registration scan')

result='''    if (selectorNames.count) result[@"calledSelectors"] = selectorNames.array;\n    if (notifications.count) result[@"notifications"] = notifications;\n    return result;'''
once(result,'''    if (selectorNames.count) result[@"calledSelectors"] = selectorNames.array;\n    if (notifications.count) result[@"notifications"] = notifications;\n    if (observerRegistrations.count) result[@"observerRegistrations"] = observerRegistrations;\n    return result;''','observer result')

# Replace bridge resolver with structured registration matching.
start=s.find('static NSArray *HFA5MObserverBridgesForNotification(')
if start<0: raise SystemExit('observer bridge missing')
b=s.find('{',start);depth=0;end=None;ins=False;esc=False
for i in range(b,len(s)):
    ch=s[i]
    if ins:
        if esc:esc=False
        elif ch=='\\':esc=True
        elif ch=='"':ins=False
        continue
    if ch=='"':ins=True;continue
    if ch=='{':depth+=1
    elif ch=='}':
        depth-=1
        if depth==0:end=i+1;break
if end is None: raise SystemExit('observer bridge unterminated')
bridge=r'''static NSArray *HFA5MObserverBridgesForNotification(Class cls, NSString *notification) {
    if(!cls||!notification.length)return @[];NSMutableArray *out=[NSMutableArray array];unsigned count=0;Method *methods=class_copyMethodList(cls,&count);
    for(unsigned i=0;methods&&i<count;i++){
        NSDictionary *scan=HFA5MScanMethod(cls,method_getName(methods[i]),method_getImplementation(methods[i]));NSArray *regs=[scan[@"observerRegistrations"] isKindOfClass:NSArray.class]?scan[@"observerRegistrations"]:@[];
        for(NSDictionary *reg in regs){if(![[reg[@"name"] description] isEqual:notification])continue;NSMutableDictionary *x=[scan mutableCopy];x[@"observerRegistration"]=reg;x[@"observerSelector"]=reg[@"registrationSelector"]?:@"unknown";HFA5MAppendUnique(out,x,@[@"selector",@"rva",@"observerSelector"]);if(out.count>=24)break;}
        if(out.count>=24)break;
    }
    free(methods);return out;
}'''
s=s[:start]+bridge+s[end:]

ready='''    copy[@"dispatcherResolved"] = @(actions.count > 0);\n    copy[@"downstreamCallbackResolved"] = @(blocks.count > 0);\n    return copy;'''
once(ready,r'''    copy[@"dispatcherResolved"] = @(actions.count > 0);
    NSArray *bridges=[copy[@"observerBridges"] isKindOfClass:NSArray.class]?copy[@"observerBridges"]:@[];BOOL cb=NO;
    for(NSDictionary *x in bridges){NSDictionary *r=[x[@"observerRegistration"] isKindOfClass:NSDictionary.class]?x[@"observerRegistration"]:nil;if([r[@"callbackResolved"] boolValue]&&[r[@"callback"] isKindOfClass:NSDictionary.class]){cb=YES;break;}}
    copy[@"downstreamCallbackResolved"] = @(blocks.count > 0 || cb);
    copy[@"observerCallbackResolved"] = @(cb);
    return copy;''','downstream readiness')

if 'HFA5MDispatcherEvidenceReadiness' not in s:
    s+=r'''

NSDictionary *HFA5MDispatcherEvidenceReadiness(void){
    NSUInteger features=gHFA5MFeatures.count,actions=0,callbacks=0;
    for(NSString *key in gHFA5MFeatures){NSDictionary *e=HFA5MDispatcherEvidenceForIdentifier(key);actions += [[e[@"actions"] isKindOfClass:NSArray.class]?e[@"actions"]:@[] count];if([e[@"downstreamCallbackResolved"] boolValue])callbacks++;}
    return @{@"status":features?@"ready":@"empty",@"features":@(features),@"actions":@(actions),@"downstreamCallbacks":@(callbacks)};
}
'''

P.write_text(s)
for x in ['observerRegistrations','addObserver:selector:name:object:','observerCallbackResolved','HFA5MDispatcherEvidenceReadiness']:
    if x not in s: raise SystemExit('missing '+x)
print('v0.3.8 structured downstream observer evidence applied')
