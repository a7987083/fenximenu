from pathlib import Path

P = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s = P.read_text()
scan = 'unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos = s.find(scan)
if pos < 0:
    raise SystemExit('v0311 scan anchor missing')

if 'HFAV0311FullTextStateXrefCandidates' not in s:
    helper = r'''
static BOOL HFAV0311DecodeADR(uint32_t w, uintptr_t pc, unsigned *rd, uintptr_t *target) {
    if ((w & 0x9F000000u) != 0x10000000u) return NO;
    uint64_t imm=((uint64_t)((w>>5)&0x7FFFFu)<<2)|((w>>29)&3u);
    int64_t sx=(int64_t)((imm^(1ULL<<20))-(1ULL<<20));
    if(rd)*rd=w&31u;if(target)*target=(uintptr_t)((int64_t)pc+sx);return YES;
}
static BOOL HFAV0311DecodeMemUnsigned(uint32_t w,unsigned *rn,uint64_t *off,NSString **access){
    uint32_t op=w&0xFFC00000u;uint64_t scale=0;NSString *a=nil;
    if(op==0xF9400000u){scale=8;a=@"read";}else if(op==0xF9000000u){scale=8;a=@"write";}
    else if(op==0xB9400000u){scale=4;a=@"read";}else if(op==0xB9000000u){scale=4;a=@"write";}else return NO;
    if(rn)*rn=(w>>5)&31u;if(off)*off=(uint64_t)((w>>10)&0xFFFu)*scale;if(access)*access=a;return YES;
}
static BOOL HFAV0311MatchState(uintptr_t target,const uintptr_t *states,NSUInteger count,uintptr_t *matched){for(NSUInteger i=0;i<count;i++)if(states[i]==target){if(matched)*matched=target;return YES;}return NO;}
static BOOL HFAV0311IsFrameStart(uint32_t w){return w==0xD503233Fu||w==0xD503237Fu||((w&0xFFC07FFFu)==0xA9807BFDu);}
static uintptr_t HFAV0311GuessFunctionStart(uintptr_t pc,HFAV02Layout l,NSString **kindOut){
    Dl_info di={0};if(dladdr((void*)pc,&di)&&di.dli_fbase&&(uintptr_t)di.dli_fbase==l.base&&di.dli_saddr){uintptr_t a=(uintptr_t)di.dli_saddr;if(a>=l.text.start&&a<=pc&&pc-a<=0x10000u){if(kindOut)*kindOut=@"symbol";return a;}}
    uintptr_t lo=pc>0x1000u?pc-0x1000u:l.text.start;if(lo<l.text.start)lo=l.text.start;uintptr_t p=pc&~(uintptr_t)3;
    while(p>=lo+4){uint32_t w=0,prev=0;memcpy(&w,(void*)p,4);memcpy(&prev,(void*)(p-4),4);if(HFAV0311IsFrameStart(w)){if(kindOut)*kindOut=@"prologue";return p;}if(prev==0xD65F03C0u){if(kindOut)*kindOut=@"post-ret";return p;}if(p<lo+8)break;p-=4;}
    return 0;
}
static void HFAV0311AppendTextXref(NSMutableArray *hits,NSMutableSet *seen,uintptr_t state,uintptr_t pc,HFAV02Layout l,NSString *form,NSString *access){
    NSString *key=[NSString stringWithFormat:@"%llX|%llX|%@",(unsigned long long)state,(unsigned long long)pc,form?:@"?"];if([seen containsObject:key]||hits.count>=256)return;[seen addObject:key];NSMutableDictionary *x=[@{@"runtimeAddress":@((unsigned long long)state),@"xrefRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(pc-l.base)],@"materialization":form?:@"unknown",@"confidence":@"candidate"} mutableCopy];if(access.length)x[@"accessHint"]=access;[hits addObject:x];
}
static NSArray *HFAV0311FullTextStateXrefCandidates(NSDictionary *sem,NSArray *helperEvidence,HFAV02Layout l,NSDictionary **metaOut){
    NSMutableDictionary *backend=HFAV039BackendStateIndex(sem,helperEvidence);if(!backend.count||!l.text.start||l.text.end<=l.text.start){if(metaOut)*metaOut=@{};return @[];}
    uintptr_t states[64]={0};NSUInteger stateCount=0;for(NSNumber *n in backend){if(stateCount>=64)break;states[stateCount++]=(uintptr_t)[n unsignedLongLongValue];}
    uintptr_t textBytes=l.text.end-l.text.start,maxBytes=0x2000000u,scanBytes=MIN(textBytes,maxBytes);BOOL truncated=textBytes>scanBytes;NSUInteger instructionCount=scanBytes/4;NSMutableArray *hits=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    const uint32_t *words=(const uint32_t*)l.text.start;
    for(NSUInteger i=0;i<instructionCount&&hits.count<256;i++){
        uint32_t w=words[i];uintptr_t pc=l.text.start+i*4,matched=0;unsigned reg=0;uintptr_t target=0;
        if(HFAV0311DecodeADR(w,pc,&reg,&target)&&HFAV0311MatchState(target,states,stateCount,&matched))HFAV0311AppendTextXref(hits,seen,matched,pc,l,@"adr",nil);
        uintptr_t page=0;if(HFAV02ADRP(w,pc,&reg,&page)){
            for(NSUInteger q=i+1;q<instructionCount&&q<=i+3;q++){
                unsigned rd=0,rn=0;uint64_t imm=0;if(HFAV02ADD(words[q],&rd,&rn,&imm)&&rn==reg){target=page+(uintptr_t)imm;if(HFAV0311MatchState(target,states,stateCount,&matched))HFAV0311AppendTextXref(hits,seen,matched,pc,l,@"adrp-add",nil);}
                NSString *access=nil;uint64_t off=0;if(HFAV0311DecodeMemUnsigned(words[q],&rn,&off,&access)&&rn==reg){target=page+(uintptr_t)off;if(HFAV0311MatchState(target,states,stateCount,&matched))HFAV0311AppendTextXref(hits,seen,matched,l.text.start+q*4,l,@"adrp-mem",access);}
            }
        }
    }
    NSMutableDictionary *owners=[NSMutableDictionary dictionary];for(NSDictionary *h in hits){BOOL ok=NO;uint64_t rv=HFAV032HexValue(h[@"xrefRVA"],&ok);if(!ok)continue;uintptr_t pc=l.base+(uintptr_t)rv;NSString *kind=nil;uintptr_t start=HFAV0311GuessFunctionStart(pc,l,&kind);if(!start)continue;NSNumber *k=@((unsigned long long)start);NSMutableArray *a=owners[k];if(!a){a=[NSMutableArray array];owners[k]=a;}NSMutableDictionary *x=[h mutableCopy];x[@"ownerRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(start-l.base)];x[@"ownerKind"]=kind?:@"unknown";[a addObject:x];}
    NSMutableArray *out=[NSMutableArray array];NSUInteger analyzed=0;for(NSNumber *owner in owners){if(analyzed>=64)break;uintptr_t start=(uintptr_t)[owner unsignedLongLongValue];uintptr_t end=MIN(start+0x4000u,l.text.end);NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(start,0,end)?:@{};}@catch(NSException *ex){analyzed++;continue;}analyzed++;
        NSArray *sas=[ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[];for(NSDictionary *h in owners[owner]){NSNumber *n=[h[@"runtimeAddress"] isKindOfClass:NSNumber.class]?h[@"runtimeAddress"]:nil;if(!n)continue;NSDictionary *consumer=nil;for(NSDictionary *sa in sas){if([sa[@"exact"] boolValue]&&[sa[@"runtimeAddress"] isEqual:n]){consumer=sa;break;}}NSArray *ba=[backend[n] isKindOfClass:NSArray.class]?backend[n]:@[];NSDictionary *bw=HFAV037FirstAccess(ba,@"write"),*br=HFAV037FirstAccess(ba,@"read");NSString *rel=@"exact-address-materialization-candidate";if(consumer){NSString *ca=[consumer[@"access"] description];if(bw&&[ca isEqual:@"read"])rel=@"receiver-consumer-candidate";else if((bw||br)&&([ca isEqual:@"write"]||bw))rel=@"exact-shared-state-candidate";}
            NSMutableDictionary *x=[h mutableCopy];x[@"relation"]=rel;x[@"origin"]=@"full-text-exact-state-xref";x[@"semanticType"]=ev[@"semanticType"]?:@"unknown-runtime";if(consumer)x[@"consumerAccess"]=consumer;if(bw||br)x[@"backendAccess"]=bw?:br;[out addObject:x];if(out.count>=64)break;}if(out.count>=64)break;}
    if(metaOut)*metaOut=@{@"engine":@"full-text-prefilter",@"textBytes":@((unsigned long long)textBytes),@"instructionsScanned":@(instructionCount),@"rawXrefCount":@(hits.count),@"candidateFunctionCount":@(owners.count),@"scannedMethods":@(analyzed),@"candidateCount":@(out.count),@"budgetExceeded":@(truncated),@"textTruncated":@(truncated)};return out;
}
'''
    s = s[:pos] + helper + '\n' + s[pos:]

old = 'NSDictionary *xrefMeta39=nil;NSArray *xref39=HFAV039StateXrefCandidates(sev,helper36,image,l,&xrefMeta39);if(xref39.count)bb[@"stateXrefConsumers"]=xref39;if(xrefMeta39.count)bb[@"stateXrefMeta"]=xrefMeta39;'
if old not in s:
    raise SystemExit('v0311 state xref call anchor missing')
new = 'NSDictionary *xrefMeta311=nil;NSArray *xref311=HFAV0311FullTextStateXrefCandidates(sev,helper36,l,&xrefMeta311);if(xref311.count)bb[@"stateXrefConsumers"]=xref311;if(xrefMeta311.count){bb[@"stateXrefMeta"]=xrefMeta311;bb[@"stateXrefEngine"]=@"full-text-prefilter";}'
s = s.replace(old,new,1)
s = s.replace('if(xrefMeta39.count)HFAV02Log([NSString stringWithFormat:@"[V039-STATE-XREF] backend=%@ methods=%@ candidates=%@ budget=%@",bb[@"backendId"]?:@0,xrefMeta39[@"scannedMethods"]?:@0,xrefMeta39[@"candidateCount"]?:@0,[xrefMeta39[@"budgetExceeded"] boolValue]?@"exceeded":@"ok"]);',
'''if(xrefMeta311.count)HFAV02Log([NSString stringWithFormat:@"[V0311-STATE-XREF] backend=%@ instructions=%@ rawXrefs=%@ functions=%@ candidates=%@ truncated=%@",bb[@"backendId"]?:@0,xrefMeta311[@"instructionsScanned"]?:@0,xrefMeta311[@"rawXrefCount"]?:@0,xrefMeta311[@"candidateFunctionCount"]?:@0,xrefMeta311[@"candidateCount"]?:@0,[xrefMeta311[@"textTruncated"] boolValue]?@"yes":@"no"]);''',1)

P.write_text(s)
for required in ['HFAV0311FullTextStateXrefCandidates','full-text-exact-state-xref','full-text-prefilter','[V0311-STATE-XREF]','instructionsScanned']:
    if required not in s:
        raise SystemExit('missing '+required)
print('v0.3.11 full-text exact-state xref prefilter applied')
