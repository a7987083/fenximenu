from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'
s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos=s.find(scan)
if pos<0: raise SystemExit('v0311 scan entry missing')

if 'HFAV0311ConsumerGraph' not in s:
    helper=r'''
static BOOL HFAV0311StackStoreReg(const uint32_t *words,NSUInteger from,NSUInteger to,unsigned reg,NSString **form,int64_t *offset){for(NSUInteger k=from;k<to;k++){uint32_t w=words[k];if((w&0xFFC00000u)==0xF9000000u&&((w>>5)&31u)==31u&&(w&31u)==reg){if(form)*form=@"str-x";if(offset)*offset=(int64_t)(((w>>10)&0xFFFu)*8u);return YES;}if((w&0xFFC00000u)==0xA9000000u&&((w>>5)&31u)==31u){unsigned r0=w&31u,r1=(w>>10)&31u;if(r0==reg||r1==reg){int64_t imm=(int64_t)((w>>15)&0x7Fu);if(imm&0x40)imm-=0x80;if(form)*form=@"stp-x";if(offset)*offset=imm*8;return YES;}}}return NO;}
static NSArray *HFAV0311NestedBlockCandidates(NSString *rva,HFAV02Layout l){BOOL ok=NO;uint64_t rv=HFAV032HexValue(rva,&ok);if(!ok||!rv)return @[];uintptr_t start=l.base+(uintptr_t)rv;if(start<l.text.start||start>=l.text.end)return @[];NSUInteger maxCount=MIN((NSUInteger)256,(NSUInteger)((l.text.end-start)/4));const uint32_t *words=(const uint32_t*)start;NSMutableArray *out=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(NSUInteger i=0;i<maxCount&&out.count<12;i++){uint32_t w=words[i];if(w==0xD65F03C0u&&i>8)break;uintptr_t pc=start+i*4,target=0;unsigned reg=0;NSString *mat=nil;if(HFAV0311DecodeADR(w,pc,&reg,&target)){mat=@"adr";}else{uintptr_t page=0;if(!HFAV02ADRP(w,pc,&reg,&page))continue;BOOL found=NO;for(NSUInteger q=i+1;q<maxCount&&q<=i+3;q++){unsigned rd=0,rn=0;uint64_t imm=0;if(HFAV02ADD(words[q],&rd,&rn,&imm)&&rn==reg){target=page+(uintptr_t)imm;reg=rd;mat=@"adrp-add";i=q;found=YES;break;}}if(!found)continue;}if(target<l.text.start||target>=l.text.end)continue;NSString *store=nil;int64_t off=0;NSUInteger stop=MIN(maxCount,i+20);if(!HFAV0311StackStoreReg(words,i+1,stop,reg,&store,&off))continue;NSString *key=[NSString stringWithFormat:@"%llX",(unsigned long long)target];if([seen containsObject:key])continue;[seen addObject:key];NSString *trva=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(target-l.base)];NSDictionary *ev=HFAV039SemanticAtRVA(trva,l);[out addObject:@{@"rva":trva,@"materialization":mat?:@"unknown",@"stackStore":store?:@"unknown",@"stackOffset":@(off),@"confidence":@"candidate",@"origin":@"nested-stack-block",@"semanticType":ev[@"semanticType"]?:@"unknown-runtime",@"stateAccessCount":@([[ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[] count])}];}
    return out;
}
static void HFAV0311AppendCallbackValue(NSMutableArray *dst,id value,NSString *origin){if(!dst||!value)return;if([value isKindOfClass:NSArray.class]){for(id x in (NSArray*)value)HFAV0311AppendCallbackValue(dst,x,origin);return;}if([value isKindOfClass:NSDictionary.class]){NSDictionary *d=value;NSString *rv=[d[@"rva"] isKindOfClass:NSString.class]?d[@"rva"]:nil;if(rv.length){NSMutableDictionary *x=[d mutableCopy];x[@"origin"]=origin?:@"callback";[dst addObject:x];return;}for(id k in d){id v=d[k];if([v isKindOfClass:NSDictionary.class]||[v isKindOfClass:NSArray.class])HFAV0311AppendCallbackValue(dst,v,origin);}return;}}
static NSArray *HFAV0311FeatureCallbackSeeds(NSDictionary *f){NSMutableArray *out=[NSMutableArray array];for(NSDictionary *b in [f[@"observerBridges"] isKindOfClass:NSArray.class]?f[@"observerBridges"]:@[]){NSDictionary *r=[b[@"observerRegistration"] isKindOfClass:NSDictionary.class]?b[@"observerRegistration"]:nil;if([r[@"callback"] isKindOfClass:NSDictionary.class])HFAV0311AppendCallbackValue(out,r[@"callback"],@"observer-callback");HFAV0311AppendCallbackValue(out,r[@"blockInvokeCandidates"],@"observer-block-candidate");}
    HFAV0311AppendCallbackValue(out,f[@"dictionaryBlocks"],@"dictionary-block");HFAV0311AppendCallbackValue(out,f[@"downstreamCallback"],@"downstream-callback");HFAV0311AppendCallbackValue(out,f[@"downstreamCallbacks"],@"downstream-callback");HFAV0311AppendCallbackValue(out,f[@"callbacks"],@"callback");
    for(NSDictionary *a in [f[@"actions"] isKindOfClass:NSArray.class]?f[@"actions"]:@[]){HFAV0311AppendCallbackValue(out,a[@"dictionaryBlocks"],@"action-dictionary-block");NSDictionary *d=[a[@"dispatcher"] isKindOfClass:NSDictionary.class]?a[@"dispatcher"]:nil;HFAV0311AppendCallbackValue(out,d[@"dictionaryBlocks"],@"dispatcher-dictionary-block");HFAV0311AppendCallbackValue(out,d[@"downstreamCallback"],@"dispatcher-downstream");HFAV0311AppendCallbackValue(out,d[@"downstreamCallbacks"],@"dispatcher-downstream");}
    NSMutableArray *uniq=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];for(NSDictionary *x in out){NSString *key=[NSString stringWithFormat:@"%@|%@|%@",x[@"image"]?:@"",x[@"rva"]?:@"",x[@"origin"]?:@""];if([seen containsObject:key])continue;[seen addObject:key];[uniq addObject:x];if(uniq.count>=32)break;}return uniq;
}
static NSDictionary *HFAV0311ConsumerGraph(NSArray *runtime,const char *selectedImage,HFAV02Layout l){NSString *selected=selectedImage?[NSString stringWithUTF8String:selectedImage]:@"";NSMutableArray *features=[NSMutableArray array];NSUInteger notificationCount=0,resolvedCallbacks=0,candidateCallbacks=0,helperCount=0,nestedCount=0;
    for(NSDictionary *f in runtime?:@[]){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSArray *notifications=HFAV0310FeatureNotifications(f);notificationCount+=notifications.count;NSArray *seeds=HFAV0311FeatureCallbackSeeds(f);NSMutableArray *callbacks=[NSMutableArray array];NSMutableArray *candidates=[NSMutableArray array];
        for(NSDictionary *seed in seeds){NSString *rv=[seed[@"rva"] isKindOfClass:NSString.class]?seed[@"rva"]:nil;NSString *im=[seed[@"image"] isKindOfClass:NSString.class]?seed[@"image"]:nil;BOOL candidate=[[seed[@"confidence"] description] isEqual:@"candidate"]||[[seed[@"origin"] description] containsString:@"candidate"];if(!rv.length){if(candidate){[candidates addObject:seed];candidateCallbacks++;}continue;}NSMutableDictionary *x=[seed mutableCopy];if(!im.length||[im isEqual:selected]){NSDictionary *ev=HFAV039SemanticAtRVA(rv,l);x[@"semanticType"]=ev[@"semanticType"]?:@"unknown-runtime";x[@"stateAccessCount"]=@([[ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[] count]);NSArray *hc=[ev[@"helperCalls"] isKindOfClass:NSArray.class]?ev[@"helperCalls"]:@[];NSMutableArray *helpers=[NSMutableArray array];NSMutableSet *hs=[NSMutableSet set];for(NSDictionary *h in hc){if(helpers.count>=6)break;NSString *hr=[h[@"targetRVA"] isKindOfClass:NSString.class]?h[@"targetRVA"]:nil;if(!hr.length||[hs containsObject:hr])continue;[hs addObject:hr];NSDictionary *hev=HFAV039SemanticAtRVA(hr,l);[helpers addObject:@{@"rva":hr,@"semanticType":hev[@"semanticType"]?:@"unknown-runtime",@"stateAccessCount":@([[hev[@"stateAccesses"] isKindOfClass:NSArray.class]?hev[@"stateAccesses"]:@[] count])}];}if(helpers.count){x[@"helpers"]=helpers;helperCount+=helpers.count;}NSArray *nested=HFAV0311NestedBlockCandidates(rv,l);if(nested.count){x[@"nestedBlocks"]=nested;nestedCount+=nested.count;}}
            if(candidate){x[@"confidence"]=@"candidate";[candidates addObject:x];candidateCallbacks++;}else{[callbacks addObject:x];resolvedCallbacks++;}}
        NSMutableDictionary *g=[@{@"identifier":identifier,@"notifications":notifications,@"callbacks":callbacks,@"callbackCandidates":candidates} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])g[@"title"]=f[@"title"];if(callbacks.count)g[@"status"]=@"resolved-callback";else if(candidates.count)g[@"status"]=@"candidate-only";else if(notifications.count)g[@"status"]=@"notification-only";else g[@"status"]=@"no-notification";[features addObject:g];}
    HFAV02Log([NSString stringWithFormat:@"[V0311-CONSUMER-GRAPH] features=%lu notifications=%lu resolvedCallbacks=%lu candidates=%lu helpers=%lu nestedBlocks=%lu",(unsigned long)features.count,(unsigned long)notificationCount,(unsigned long)resolvedCallbacks,(unsigned long)candidateCallbacks,(unsigned long)helperCount,(unsigned long)nestedCount]);return @{@"features":features,@"featureCount":@(features.count),@"notificationCount":@(notificationCount),@"resolvedCallbackCount":@(resolvedCallbacks),@"candidateCallbackCount":@(candidateCallbacks),@"helperCount":@(helperCount),@"nestedBlockCount":@(nestedCount),@"policy":@"diagnostic-only-unless-exact-state-binding"};
}
'''
    s=s[:pos]+helper+'\n'+s[pos:]

old='NSDictionary *consumerGraph310=HFAV0310ConsumerGraph(runtime,image,l);'
if old not in s: raise SystemExit('v0311 consumer graph assignment anchor missing')
s=s.replace(old,'NSDictionary *consumerGraph311=HFAV0311ConsumerGraph(runtime,image,l);',1)
old='@"consumerGraph":consumerGraph310'
if old not in s: raise SystemExit('v0311 consumer graph root anchor missing')
s=s.replace(old,'@"consumerGraph":consumerGraph311',1)

s=s.replace('com.hfa.runtime-analyzer/v0.3.10','com.hfa.runtime-analyzer/v0.3.11',1)
s=s.replace('HFAEnableIL2CPPEnrichmentV0310','HFAEnableIL2CPPEnrichmentV0311')
out='NSString *p310=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0310.json");'
if out not in s: raise SystemExit('v0311 output anchor missing')
s=s.replace(out,'NSString *p311=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0311.json");'+out,1)
write='[json writeToFile:p310 atomically:YES];[json writeToFile:p39 atomically:YES];'
if write not in s: raise SystemExit('v0311 write anchor missing')
s=s.replace(write,'[json writeToFile:p311 atomically:YES];'+write,1)
idx=s.rfind('[V038-SCAN-END]')
if idx>=0:s=s[:idx]+'[V0311-SCAN-END]'+s[idx+len('[V038-SCAN-END]'):]
SRC.write_text(s)

SEM.write_text(SEM.read_text().replace('HFAMap_RuntimeAnalyzer_v0310_stage.log','HFAMap_RuntimeAnalyzer_v0311_stage.log'))
ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.10 NotificationConsumerGraph','HFAMap RuntimeAnalyzer v0.3.11 ADRFullTextXrefConsumer',2).replace('com.hfa.runtime-analyzer.v0310','com.hfa.runtime-analyzer.v0311')
UI.write_text(ui)

ss=SRC.read_text()
for required in ['HFAV0311NestedBlockCandidates','HFAV0311FeatureCallbackSeeds','HFAV0311ConsumerGraph','nested-stack-block','[V0311-CONSUMER-GRAPH]','[V0311-SCAN-END]','HFAMap_RuntimeAnalyzer_v0311.json','com.hfa.runtime-analyzer/v0.3.11','HFAEnableIL2CPPEnrichmentV0311']:
    if required not in ss: raise SystemExit('missing '+required)
print('v0.3.11 unified consumer graph and nested block evidence applied')
