from pathlib import Path

P=Path('hfamap/src/HFAMap5MDispatcherResolver.m')
s=P.read_text()

anchor='static BOOL HFA5MDecodeADDX(uint32_t insn, unsigned *rdOut, unsigned *rnOut, uint64_t *offsetOut) {'
if anchor not in s: raise SystemExit('v0310 decoder anchor missing')
if 'HFA0310ResolveNearbyBlockInvoke' not in s:
    helper=r'''
static BOOL HFA0310DecodeSTRX(uint32_t w,unsigned *rt,unsigned *rn,uint64_t *off){
    if((w&0xFFC00000u)!=0xF9000000u)return NO;
    if(rt)*rt=w&31u;if(rn)*rn=(w>>5)&31u;if(off)*off=(uint64_t)((w>>10)&0xFFFu)*8u;return YES;
}
static NSDictionary *HFA0310ResolveNearbyBlockInvoke(const uint32_t *words,NSUInteger count,uintptr_t start,NSUInteger callIndex,HFA5MImageLayout layout){
    if(!words||!count||callIndex>=count)return @{};
    NSUInteger lo=callIndex>40?callIndex-40:0;NSMutableArray *candidates=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(NSUInteger i=lo;i<callIndex;i++){
        unsigned r=0;uintptr_t page=0;if(!HFA5MDecodeADRP(words[i],start+i*4,&r,&page))continue;
        for(NSUInteger q=i+1;q<callIndex&&q<=i+3;q++){
            unsigned rd=0,rn=0;uint64_t imm=0;if(!HFA5MDecodeADDX(words[q],&rd,&rn,&imm)||rn!=r)continue;uintptr_t target=page+(uintptr_t)imm;
            if(!HFA5MRangeContains(layout.text,target,4))continue;
            for(NSUInteger k=q+1;k<callIndex&&k<=q+18;k++){
                unsigned rt=0,base=0;uint64_t off=0;if(!HFA0310DecodeSTRX(words[k],&rt,&base,&off)||rt!=rd||base!=31)continue;
                NSString *key=[NSString stringWithFormat:@"%llX|%llu",(unsigned long long)target,(unsigned long long)off];if([seen containsObject:key])continue;[seen addObject:key];NSMutableDictionary *x=[[HFA5MAddressInfo((const void*)target)?:@{} mutableCopy];x[@"discovery"]=@"stack-block-code-pointer";x[@"stackOffset"]=@(off);[candidates addObject:x];
            }
        }
    }
    if(candidates.count==1){NSMutableDictionary *out=[candidates[0] mutableCopy];out[@"resolved"]=@YES;out[@"confidence"]=@"strong";return out;}
    return @{@"resolved":@NO,@"candidateCount":@(candidates.count),@"candidates":candidates?:@[]};
}
'''
    s=s.replace(anchor,helper+'\n'+anchor,1)

old='''                if(notification.length){NSDictionary *e=@{@"name":notification,@"registrationSelector":@"addObserverForName:object:queue:usingBlock:",@"callbackResolved":@NO};HFA5MAppendUnique(observerRegistrations,e,@[@"name",@"registrationSelector"]);}'''
if old not in s: raise SystemExit('v0310 block observer anchor missing')
new=r'''                if(notification.length){
                    NSDictionary *bi=HFA0310ResolveNearbyBlockInvoke(words,count,start,j,layout);BOOL resolved=[bi[@"resolved"] boolValue];NSMutableDictionary *e=[@{@"name":notification,@"registrationSelector":@"addObserverForName:object:queue:usingBlock:",@"callbackResolved":@(resolved),@"callbackKind":@"block-invoke-static"} mutableCopy];
                    if(resolved){NSMutableDictionary *cb=[bi mutableCopy];[cb removeObjectForKey:@"resolved"];e[@"callback"]=cb;}else if([bi[@"candidates"] isKindOfClass:NSArray.class])e[@"blockInvokeCandidates"]=bi[@"candidates"];
                    HFA5MLog([NSString stringWithFormat:@"[V0310-BLOCK-INVOKE] notification=%@ candidates=%@ resolved=%@",notification,bi[@"candidateCount"]?:@(resolved?1:0),resolved?@"yes":@"no"]);HFA5MAppendUnique(observerRegistrations,e,@[@"name",@"registrationSelector"]);
                }'''
s=s.replace(old,new,1)
P.write_text(s)
for required in ['HFA0310ResolveNearbyBlockInvoke','stack-block-code-pointer','block-invoke-static','[V0310-BLOCK-INVOKE]']:
    if required not in s: raise SystemExit('missing '+required)
print('v0.3.10 bounded block observer invoke resolver applied')
