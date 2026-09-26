from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'

s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos=s.find(scan)
if pos<0: raise SystemExit('scan entry missing')

if 'HFAV037StateConsumerBindings' not in s:
    helpers=r'''
static void HFAV037CollectStateIndex(NSMutableDictionary *dst,NSDictionary *sem,NSString *origin){
    if(!dst||![sem isKindOfClass:NSDictionary.class])return;
    NSArray *a=[sem[@"stateAccesses"] isKindOfClass:NSArray.class]?sem[@"stateAccesses"]:@[];
    for(NSDictionary *e in a){if(![e[@"exact"] boolValue])continue;NSNumber *n=[e[@"runtimeAddress"] isKindOfClass:NSNumber.class]?e[@"runtimeAddress"]:nil;NSString *access=[e[@"access"] isKindOfClass:NSString.class]?e[@"access"]:nil;if(!n||!access.length)continue;NSMutableArray *bucket=dst[n];if(!bucket){bucket=[NSMutableArray array];dst[n]=bucket;}NSMutableDictionary *x=[e mutableCopy];x[@"origin"]=origin?:@"semantic";[bucket addObject:x];}
}
static NSDictionary *HFAV037FirstAccess(NSArray *a,NSString *access){for(NSDictionary *x in a)if([[x[@"access"] description] isEqual:access])return x;return nil;}
static NSArray *HFAV037StateConsumerBindings(NSArray *runtime,NSDictionary *sem,NSArray *helperEvidence,const char *selectedImage,HFAV02Layout l){
    NSMutableDictionary *backend=[NSMutableDictionary dictionary];HFAV037CollectStateIndex(backend,sem,@"backend");
    for(NSDictionary *h in helperEvidence?:@[]){NSDictionary *ev=[h[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?h[@"semanticEvidence"]:@{};HFAV037CollectStateIndex(backend,ev,@"helper");}
    if(!backend.count)return @[];NSMutableArray *out=[NSMutableArray array];
    for(NSDictionary *f in runtime?:@[]){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSDictionary *action=HFAV036ActionSemantic(f,selectedImage,l);NSMutableDictionary *ai=[NSMutableDictionary dictionary];HFAV037CollectStateIndex(ai,action,@"feature-action");if(!ai.count)continue;
        NSNumber *match=nil;NSDictionary *be=nil,*ae=nil;NSString *relation=nil;
        for(NSNumber *n in ai){NSArray *ba=backend[n];NSArray *aa=ai[n];if(!ba.count||!aa.count)continue;NSDictionary *bw=HFAV037FirstAccess(ba,@"write");NSDictionary *br=HFAV037FirstAccess(ba,@"read");NSDictionary *ar=HFAV037FirstAccess(aa,@"read");NSDictionary *aw=HFAV037FirstAccess(aa,@"write");if(bw&&ar){match=n;be=bw;ae=ar;relation=@"receiver-consumer";break;}if((bw||br)&&(aw||ar)&&(bw||aw)){match=n;be=bw?:br;ae=aw?:ar;relation=@"shared-state-access";break;}}
        if(!match)continue;NSMutableDictionary *b=[@{@"identifier":identifier,@"confidence":@"strong",@"evidence":relation?:@"state-access",@"matchedRuntimeAddress":match} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])b[@"title"]=f[@"title"];if([f[@"type"] isKindOfClass:NSString.class])b[@"controlType"]=f[@"type"];if([be[@"sourceRVA"] isKindOfClass:NSString.class])b[@"matchedSourceRVA"]=be[@"sourceRVA"];if([ae[@"sourceRVA"] isKindOfClass:NSString.class])b[@"consumerSourceRVA"]=ae[@"sourceRVA"];b[@"backendAccess"]=be?:@{};b[@"consumerAccess"]=ae?:@{};[out addObject:b];
    }
    return out;
}
static unsigned HFAV037NodePriority(NSString *kind){if([kind isEqual:@"conditional-return-path"])return 0;if([kind isEqual:@"constant-return"])return 1;if([kind isEqual:@"operation"])return 2;if([kind isEqual:@"conditional-branch"])return 3;if([kind isEqual:@"return"])return 4;return 9;}
static NSArray *HFAV037SemanticNodeBindings(NSArray *bindings,NSDictionary *sem){
    NSArray *nodes=[sem[@"semanticNodes"] isKindOfClass:NSArray.class]?sem[@"semanticNodes"]:@[];if(!nodes.count)return bindings?:@[];NSMutableArray *out=[NSMutableArray array];
    for(NSDictionary *x in bindings?:@[]){NSMutableDictionary *b=[x mutableCopy];if([b[@"branchBinding"] isKindOfClass:NSDictionary.class]){[out addObject:b];continue;}BOOL sok=NO;uint64_t sr=HFAV032HexValue(b[@"matchedSourceRVA"],&sok);if(!sok){[out addObject:b];continue;}NSDictionary *best=nil;uint64_t bestScore=UINT64_MAX,bestDelta=UINT64_MAX;
        for(NSDictionary *n in nodes){BOOL nok=NO;uint64_t nr=HFAV032HexValue(n[@"rva"],&nok);if(!nok||nr<sr)continue;uint64_t d=nr-sr;if(d>0xA0)continue;NSString *kind=[n[@"kind"] isKindOfClass:NSString.class]?n[@"kind"]:@"";unsigned p=HFAV037NodePriority(kind);if(p>=9)continue;uint64_t score=d+(uint64_t)p*0x18;if(score<bestScore){best=n;bestScore=score;bestDelta=d;}}
        if(best){NSMutableDictionary *bb=[@{@"kind":best[@"kind"]?:@"semantic-node",@"nodeRVA":best[@"rva"]?:@"",@"sourceRVA":b[@"matchedSourceRVA"]?:@"",@"distance":@(bestDelta),@"confidence":bestDelta<=0x50?@"strong":@"medium",@"evidence":@"reachable-cfg-semantic-node"} mutableCopy];for(NSString *k in @[@"op",@"value",@"targetRVA",@"fallthroughRVA",@"targetReachesReturn",@"fallthroughReachesReturn"])if(best[k])bb[k]=best[k];b[@"branchBinding"]=bb;}
        [out addObject:b];
    }
    return out;
}
'''
    s=s[:pos]+helpers+s[pos:]

old='''NSArray *helper36=HFAV036ExpandHelperEvidence(sev,l);if(helper36.count){bb[@"helperEvidence"]=helper36;HFAV02Log([NSString stringWithFormat:@"[V036-HELPER] backend=%@ helpers=%lu",bb[@"backendId"]?:@0,(unsigned long)helper36.count]);}NSArray *direct36=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);NSArray *shared36=HFAV036SharedStateBindings(runtime,sev,helper36,image,l);NSArray *fb=HFAV036BranchBindings(HFAV036MergeBindings(direct36,shared36),sev);if(shared36.count)HFAV02Log([NSString stringWithFormat:@"[V036-SHARED-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)shared36.count]);'''
if old not in s: raise SystemExit('v037 binding sequence anchor missing')
new='''NSArray *helper36=HFAV036ExpandHelperEvidence(sev,l);if(helper36.count){bb[@"helperEvidence"]=helper36;HFAV02Log([NSString stringWithFormat:@"[V037-HELPER] backend=%@ helpers=%lu",bb[@"backendId"]?:@0,(unsigned long)helper36.count]);}NSArray *direct36=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);NSArray *shared36=HFAV036SharedStateBindings(runtime,sev,helper36,image,l);NSArray *state37=HFAV037StateConsumerBindings(runtime,sev,helper36,image,l);NSArray *merged37=HFAV036MergeBindings(HFAV036MergeBindings(direct36,shared36),state37);NSArray *legacyBranch37=HFAV036BranchBindings(merged37,sev);NSArray *fb=HFAV037SemanticNodeBindings(legacyBranch37,sev);if(shared36.count)HFAV02Log([NSString stringWithFormat:@"[V037-SHARED-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)shared36.count]);if(state37.count)HFAV02Log([NSString stringWithFormat:@"[V037-STATE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)state37.count]);NSUInteger nodeBound=0;for(NSDictionary *fx in fb)if([fx[@"branchBinding"] isKindOfClass:NSDictionary.class])nodeBound++;if(nodeBound)HFAV02Log([NSString stringWithFormat:@"[V037-NODE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)nodeBound]);'''
s=s.replace(old,new,1)

s=s.replace('com.hfa.runtime-analyzer/v0.3.6','com.hfa.runtime-analyzer/v0.3.7',1)
s=s.replace('[V036-','[V037-')
s=s.replace('HFAEnableIL2CPPEnrichmentV036','HFAEnableIL2CPPEnrichmentV037')
out='NSString *p36=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v036.json");'
if out not in s: raise SystemExit('v037 output anchor missing')
s=s.replace(out,'NSString *p37=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v037.json");'+out,1)
write='[json writeToFile:p36 atomically:YES];[json writeToFile:p35 atomically:YES];'
if write not in s: raise SystemExit('v037 write anchor missing')
s=s.replace(write,'[json writeToFile:p37 atomically:YES];'+write,1)
SRC.write_text(s)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.6 RuntimeSemanticCompletion','HFAMap RuntimeAnalyzer v0.3.7 ControlFlowConsumerBinding',2).replace('com.hfa.runtime-analyzer.v036','com.hfa.runtime-analyzer.v037')
UI.write_text(u)

ss=SRC.read_text()
for required in ['HFAV037StateConsumerBindings','receiver-consumer','shared-state-access','HFAV037SemanticNodeBindings','reachable-cfg-semantic-node','[V037-STATE-BIND]','[V037-NODE-BIND]','HFAMap_RuntimeAnalyzer_v037.json','com.hfa.runtime-analyzer/v0.3.7','HFAEnableIL2CPPEnrichmentV037']:
    if required not in ss: raise SystemExit('missing '+required)
for forbidden in ['0x2D98AC8','0x2D9887C','0x2E25904']:
    if forbidden in ss: raise SystemExit('fixed target leaked into v037 generic runtime layer')
print('v0.3.7 receiver consumer + helper state + semantic node binding applied')
