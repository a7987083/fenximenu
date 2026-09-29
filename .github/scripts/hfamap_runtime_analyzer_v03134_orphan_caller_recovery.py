from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=TRACE.read_text()

sig='static void HFA0313BridgeAnalyzerStaticBackends(NSArray *backends,NSMutableArray *ledger,NSMutableArray *candidates)'
pos=s.find(sig)
if pos<0: raise SystemExit('caller recovery bridge anchor missing')

helpers=r'''
static BOOL HFA03134DecodeBL(uint32_t w,uintptr_t pc,uintptr_t *target){
    if((w&0xFC000000u)!=0x94000000u)return NO;
    int64_t imm=(int64_t)(w&0x03FFFFFFu);if(imm&0x02000000LL)imm|=~0x03FFFFFFLL;
    if(target)*target=(uintptr_t)((int64_t)pc+(imm<<2));return YES;
}
static NSArray *HFA03134CallerFunctions(uintptr_t callee,HFA03134MenuLayout l){
    if(!callee||!l.textStart||l.textEnd<=l.textStart)return @[];
    NSMutableOrderedSet *out=[NSMutableOrderedSet orderedSet];
    for(uintptr_t p=l.textStart;p+4<=l.textEnd;p+=4){uint32_t w=0;memcpy(&w,(void*)p,4);uintptr_t t=0;if(!HFA03134DecodeBL(w,p,&t)||t!=callee)continue;uintptr_t fs=HFA03134GuessOwnerStart(p,l);if(!fs||fs==callee)continue;[out addObject:@(fs)];if(out.count>=16)break;}
    return out.array?:@[];
}
static NSDictionary *HFA03134FunctionRegistrationEvidence(uintptr_t start,HFA03134MenuLayout l){
    if(!start||start<l.textStart||start>=l.textEnd)return @{};uintptr_t end=MIN(start+0x1000u,l.textEnd);
    NSMutableOrderedSet *strings=[NSMutableOrderedSet orderedSet],*keys=[NSMutableOrderedSet orderedSet];const uint32_t *w=(const uint32_t*)start;NSUInteger n=(end-start)/4;
    for(NSUInteger i=0;i<n;i++){uint32_t ins=w[i];if(ins==0xD65F03C0u&&i>4)break;uintptr_t ip=start+i*4,target=0;unsigned r=0;BOOL ok=HFA03134ADR(ins,ip,&r,&target);if(!ok){uintptr_t page=0;if(HFA03134ADRP(ins,ip,&r,&page)){for(NSUInteger q=i+1;q<n&&q<=i+3;q++){unsigned rd=0,rn=0;uint64_t imm=0;if(HFA03134ADD(w[q],&rd,&rn,&imm)&&rn==r){target=page+(uintptr_t)imm;ok=YES;break;}}}}if(!ok)continue;NSString *str=HFA03134StringAt(target,l);if(!str.length)continue;[strings addObject:str];if([str hasSuffix:@"-switch"]&&str.length>7)[keys addObject:str];if(strings.count>=48)break;}
    NSMutableDictionary *ev=[@{@"functionRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(start-l.base)],@"registrationHints":strings.array?:@[],@"exactSwitchKeys":keys.array?:@[]} mutableCopy];if(keys.count==1)ev[@"exactSwitchKey"]=keys.firstObject;return ev;
}
static NSDictionary *HFA03134CallerRegistrationEvidence(NSDictionary *ownerEv,HFA03134MenuLayout l){
    NSString *rv=[ownerEv[@"ownerFunctionRVA"] description];if(!rv.length)return @{};uint64_t off=strtoull(rv.UTF8String,NULL,0);if(!off)return @{};uintptr_t callee=l.base+(uintptr_t)off;
    NSArray *callers=HFA03134CallerFunctions(callee,l);NSMutableOrderedSet *keys=[NSMutableOrderedSet orderedSet],*hints=[NSMutableOrderedSet orderedSet];NSMutableArray *records=[NSMutableArray array];
    for(NSNumber *n in callers){NSDictionary *ev=HFA03134FunctionRegistrationEvidence(n.unsignedLongLongValue,l);if(!ev.count)continue;[records addObject:ev];for(NSString *k in [ev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?ev[@"exactSwitchKeys"]:@[])if(k.length)[keys addObject:k];for(NSString *h in [ev[@"registrationHints"] isKindOfClass:NSArray.class]?ev[@"registrationHints"]:@[])if(h.length)[hints addObject:h];}
    NSMutableDictionary *out=[@{@"callerCount":@(callers.count),@"callers":records,@"exactSwitchKeys":keys.array?:@[],@"registrationHints":hints.array?:@[]} mutableCopy];if(keys.count==1)out[@"exactSwitchKey"]=keys.firstObject;return out;
}
'''
if 'HFA03134CallerRegistrationEvidence' not in s:
    s=s[:pos]+helpers+'\n'+s[pos:]

old='''        if(owners.count==0){for(NSUInteger i=clusterStart;i<end;i++){NSDictionary *be=ordered[i][@"backend"];NSString *rbid=[be[@"backendId"] description]?:@"";NSDictionary *ev=registrationEvidenceByBackend[rbid];NSString *fn=[ev[@"ownerFunctionRVA"] description];if(fn.length)[ownerFunctions addObject:fn];for(NSString *k in [ev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?ev[@"exactSwitchKeys"]:@[])if(k.length)[exactKeys addObject:k];for(NSString *h in [ev[@"registrationHints"] isKindOfClass:NSArray.class]?ev[@"registrationHints"]:@[])if(h.length)[allHints addObject:h];}
            if(exactKeys.count==1){NSString *key=exactKeys.firstObject;NSString *fid=[key substringToIndex:key.length-7];if(fid.length)recovered=@{@"featureId":fid,@"title":fid,@"key":key,@"descriptorIndex":@(-1),@"source":@"static-registration-key",@"clusterId":clusterId,@"ownerFunctions":ownerFunctions.array?:@[],@"registrationHints":allHints.array?:@[]};}
        }'''
new='''        if(owners.count==0){NSMutableOrderedSet *callerKeys=[NSMutableOrderedSet orderedSet];NSMutableOrderedSet *callerHints=[NSMutableOrderedSet orderedSet];NSMutableArray *callerEvidence=[NSMutableArray array];
            for(NSUInteger i=clusterStart;i<end;i++){NSDictionary *be=ordered[i][@"backend"];NSString *rbid=[be[@"backendId"] description]?:@"";NSDictionary *ev=registrationEvidenceByBackend[rbid];NSString *fn=[ev[@"ownerFunctionRVA"] description];if(fn.length)[ownerFunctions addObject:fn];for(NSString *k in [ev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?ev[@"exactSwitchKeys"]:@[])if(k.length)[exactKeys addObject:k];for(NSString *h in [ev[@"registrationHints"] isKindOfClass:NSArray.class]?ev[@"registrationHints"]:@[])if(h.length)[allHints addObject:h];
                if(exactKeys.count==0&&haveRegistrationLayout&&ev.count){NSDictionary *cev=HFA03134CallerRegistrationEvidence(ev,registrationLayout);if(cev.count){[callerEvidence addObject:cev];for(NSString *k in [cev[@"exactSwitchKeys"] isKindOfClass:NSArray.class]?cev[@"exactSwitchKeys"]:@[])if(k.length)[callerKeys addObject:k];for(NSString *h in [cev[@"registrationHints"] isKindOfClass:NSArray.class]?cev[@"registrationHints"]:@[])if(h.length)[callerHints addObject:h];}}
            }
            NSString *key=nil;NSString *source=nil;if(exactKeys.count==1){key=exactKeys.firstObject;source=@"static-registration-key";}else if(exactKeys.count==0&&callerKeys.count==1){key=callerKeys.firstObject;source=@"static-caller-registration-key";}
            if(key.length){NSString *fid=[key substringToIndex:key.length-7];if(fid.length)recovered=@{@"featureId":fid,@"title":fid,@"key":key,@"descriptorIndex":@(-1),@"source":source,@"clusterId":clusterId,@"ownerFunctions":ownerFunctions.array?:@[],@"registrationHints":allHints.array?:@[],@"callerRegistrationHints":callerHints.array?:@[],@"callerEvidence":callerEvidence?:@[]};}
            if(!recovered&&callerEvidence.count){HFALog("[V03134-CALLER-RECOVERY] cluster=%s status=unresolved callerKeys=%u callers=%u hints=%u values=%s\\n",clusterId.UTF8String?:"?",(unsigned)callerKeys.count,(unsigned)callerEvidence.count,(unsigned)callerHints.count,[[callerHints.array componentsJoinedByString:@"|"] UTF8String]?:"");}
        }'''
if old not in s: raise SystemExit('caller recovery orphan block anchor missing')
s=s.replace(old,new,1)

s=s.replace('source=static-registration-key feature=%s key=%s functions=%u hints=%u','source=%s feature=%s key=%s functions=%u hints=%u',1)
s=s.replace('clusterId.UTF8String?:"?",[recovered[@"featureId"] UTF8String]?:"?",[recovered[@"key"] UTF8String]?:"?",(unsigned)ownerFunctions.count,(unsigned)allHints.count','clusterId.UTF8String?:"?",[recovered[@"source"] UTF8String]?:"?",[recovered[@"featureId"] UTF8String]?:"?",[recovered[@"key"] UTF8String]?:"?",(unsigned)ownerFunctions.count,(unsigned)allHints.count',1)

TRACE.write_text(s)
out=TRACE.read_text()
for marker in ['HFA03134CallerRegistrationEvidence','static-caller-registration-key','[V03134-CALLER-RECOVERY]']:
    if marker not in out: raise SystemExit('missing caller recovery marker '+marker)
print('v0.3.13.4 generic caller-level orphan recovery applied')
