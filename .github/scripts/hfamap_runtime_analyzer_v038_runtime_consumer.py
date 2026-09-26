from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'
s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos=s.find(scan)
if pos<0: raise SystemExit('scan entry missing')

extern='extern NSArray *HFA5MDispatcherAllEvidence(void);'
if extern in s and 'HFA5MDispatcherEvidenceReadiness' not in s:
    s=s.replace(extern,extern+'\nextern NSDictionary *HFA5MDispatcherEvidenceReadiness(void);',1)

if 'HFAV038EvidenceSnapshot' not in s:
    helpers=r'''
static NSDictionary *HFAV038EvidenceSnapshot(void){
    NSArray *runtime=@[];NSDictionary *disp=@{};NSUInteger attempts=0;
    for(NSUInteger i=0;i<6;i++){attempts=i+1;runtime=HFAV036UnifiedRuntimeEvidence(HFA5MDispatcherAllEvidence()?:@[]);disp=HFA5MDispatcherEvidenceReadiness()?:@{};if(runtime.count)break;if(i+1<6)[NSThread sleepForTimeInterval:0.05];}
    return @{@"status":runtime.count?@"ready":@"pending",@"attempts":@(attempts),@"features":runtime?:@[],@"dispatcher":disp?:@{}};
}
static NSString *HFAV038FeatureTargetClass(NSDictionary *f){
    NSDictionary *re=[f[@"runtimeEvidence"] isKindOfClass:NSDictionary.class]?f[@"runtimeEvidence"]:nil;NSString *c=[re[@"targetClass"] isKindOfClass:NSString.class]?re[@"targetClass"]:nil;if(c.length)return c;
    for(NSDictionary *a in [f[@"actions"] isKindOfClass:NSArray.class]?f[@"actions"]:@[]){NSString *tc=[a[@"targetClass"] isKindOfClass:NSString.class]?a[@"targetClass"]:nil;if(tc.length)return tc;}return nil;
}
static NSArray *HFAV038DownstreamSemanticEvidence(NSDictionary *f,const char *selectedImage,HFAV02Layout l){
    if(!f||!selectedImage||!*selectedImage)return @[];NSString *selected=[NSString stringWithUTF8String:selectedImage]?:@"";NSMutableArray *candidates=[NSMutableArray array];
    for(NSDictionary *bridge in [f[@"observerBridges"] isKindOfClass:NSArray.class]?f[@"observerBridges"]:@[]){NSDictionary *reg=[bridge[@"observerRegistration"] isKindOfClass:NSDictionary.class]?bridge[@"observerRegistration"]:nil;NSDictionary *cb=[reg[@"callback"] isKindOfClass:NSDictionary.class]?reg[@"callback"]:nil;if(cb)[candidates addObject:@{@"origin":@"notification-observer",@"address":cb}];}
    for(NSDictionary *b in [f[@"dictionaryBlocks"] isKindOfClass:NSArray.class]?f[@"dictionaryBlocks"]:@[])[candidates addObject:@{@"origin":@"feature-block",@"address":b}];
    NSMutableArray *out=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(NSDictionary *c in candidates){if(out.count>=8)break;NSDictionary *a=[c[@"address"] isKindOfClass:NSDictionary.class]?c[@"address"]:nil;NSString *im=[a[@"image"] isKindOfClass:NSString.class]?a[@"image"]:nil;if(im.length&&![im isEqual:selected])continue;BOOL ok=NO;uint64_t r=HFAV032HexValue(a[@"rva"],&ok);if(!ok||!r||[seen containsObject:@(r)])continue;[seen addObject:@(r)];NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(l.base+(uintptr_t)r,0,0)?:@{};}@catch(NSException *e){ev=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime"};}NSMutableDictionary *x=[@{@"origin":c[@"origin"]?:@"downstream",@"rva":[NSString stringWithFormat:@"0x%llX",r],@"semanticEvidence":ev} mutableCopy];if(a[@"selector"])x[@"selector"]=a[@"selector"];[out addObject:x];}
    return out;
}
static NSDictionary *HFAV038ClassStateIndex(NSString *className,HFAV02Layout l){
    if(!className.length)return @{};static NSMutableDictionary *cache;static dispatch_once_t once;dispatch_once(&once,^{cache=[NSMutableDictionary dictionary];});NSString *ck=[NSString stringWithFormat:@"%llX|%@",(unsigned long long)l.base,className];@synchronized(cache){NSDictionary *hit=cache[ck];if(hit)return hit;}
    Class cls=objc_getClass(className.UTF8String);if(!cls)return @{};NSMutableArray *methods=[NSMutableArray array];
    for(int pass=0;pass<2;pass++){Class owner=pass?object_getClass(cls):cls;unsigned count=0;Method *ml=class_copyMethodList(owner,&count);for(unsigned i=0;ml&&i<count&&methods.count<96;i++){IMP imp=method_getImplementation(ml[i]);Dl_info di={0};if(!imp||!dladdr((void*)imp,&di)||!di.dli_fbase||(uintptr_t)di.dli_fbase!=l.base)continue;[methods addObject:@{@"address":@((unsigned long long)(uintptr_t)imp),@"selector":NSStringFromSelector(method_getName(ml[i]))?:@"?"}];}free(ml);if(methods.count>=96)break;}
    [methods sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){unsigned long long x=[a[@"address"] unsignedLongLongValue],y=[b[@"address"] unsignedLongLongValue];return x<y?NSOrderedAscending:(x>y?NSOrderedDescending:NSOrderedSame);}];NSMutableDictionary *idx=[NSMutableDictionary dictionary];CFAbsoluteTime started=CFAbsoluteTimeGetCurrent();
    for(NSUInteger i=0;i<methods.count;i++){if(CFAbsoluteTimeGetCurrent()-started>0.18)break;uintptr_t a=(uintptr_t)[methods[i][@"address"] unsignedLongLongValue],end=0;if(i+1<methods.count){uintptr_t n=(uintptr_t)[methods[i+1][@"address"] unsignedLongLongValue];if(n>a)end=n;}NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(a,0,end)?:@{};}@catch(NSException *e){continue;}for(NSDictionary *sa in [ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[]){if(![sa[@"exact"] boolValue])continue;NSNumber *n=[sa[@"runtimeAddress"] isKindOfClass:NSNumber.class]?sa[@"runtimeAddress"]:nil;if(!n)continue;NSMutableArray *bucket=idx[n];if(!bucket){bucket=[NSMutableArray array];idx[n]=bucket;}NSMutableDictionary *x=[sa mutableCopy];x[@"selector"]=methods[i][@"selector"]?:@"?";x[@"methodRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-l.base)];x[@"origin"]=@"target-class-consumer";[bucket addObject:x];}}
    NSDictionary *out=[idx copy];@synchronized(cache){cache[ck]=out;}return out;
}
static NSArray *HFAV038DownstreamStateBindings(NSArray *runtime,NSDictionary *sem,NSArray *helperEvidence,const char *selectedImage,HFAV02Layout l){
    NSMutableDictionary *backend=[NSMutableDictionary dictionary];HFAV037CollectStateIndex(backend,sem,@"backend");for(NSDictionary *h in helperEvidence?:@[]){NSDictionary *ev=[h[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?h[@"semanticEvidence"]:@{};HFAV037CollectStateIndex(backend,ev,@"helper");}if(!backend.count)return @[];NSMutableArray *out=[NSMutableArray array];
    for(NSDictionary *f in runtime?:@[]){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSMutableDictionary *cons=[NSMutableDictionary dictionary];
        for(NSDictionary *ds in HFAV038DownstreamSemanticEvidence(f,selectedImage,l)){NSDictionary *ev=[ds[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?ds[@"semanticEvidence"]:@{};HFAV037CollectStateIndex(cons,ev,ds[@"origin"]?:@"downstream");}
        NSDictionary *classIdx=HFAV038ClassStateIndex(HFAV038FeatureTargetClass(f),l);for(NSNumber *n in classIdx){NSMutableArray *bucket=cons[n];if(!bucket){bucket=[NSMutableArray array];cons[n]=bucket;}[bucket addObjectsFromArray:classIdx[n]];}
        NSNumber *match=nil;NSDictionary *be=nil,*ce=nil;NSString *relation=nil;for(NSNumber *n in cons){NSArray *ba=backend[n],*ca=cons[n];if(!ba.count||!ca.count)continue;NSDictionary *bw=HFAV037FirstAccess(ba,@"write"),*br=HFAV037FirstAccess(ba,@"read"),*cr=HFAV037FirstAccess(ca,@"read"),*cw=HFAV037FirstAccess(ca,@"write");if(bw&&cr){match=n;be=bw;ce=cr;relation=@"receiver-consumer";break;}if((bw||br)&&(cw||cr)&&(bw||cw)){match=n;be=bw?:br;ce=cw?:cr;relation=@"downstream-shared-state";break;}}
        if(!match)continue;NSMutableDictionary *b=[@{@"identifier":identifier,@"confidence":@"strong",@"evidence":relation?:@"downstream-state",@"matchedRuntimeAddress":match,@"backendAccess":be?:@{},@"consumerAccess":ce?:@{}} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])b[@"title"]=f[@"title"];if([f[@"type"] isKindOfClass:NSString.class])b[@"controlType"]=f[@"type"];if([be[@"sourceRVA"] isKindOfClass:NSString.class])b[@"matchedSourceRVA"]=be[@"sourceRVA"];if([ce[@"sourceRVA"] isKindOfClass:NSString.class])b[@"consumerSourceRVA"]=ce[@"sourceRVA"];if([ce[@"selector"] isKindOfClass:NSString.class])b[@"consumerSelector"]=ce[@"selector"];[out addObject:b];}
    return out;
}
static NSArray *HFAV038BranchOutcomeBindings(NSArray *bindings){NSMutableArray *out=[NSMutableArray array];for(NSDictionary *x in bindings?:@[]){NSMutableDictionary *b=[x mutableCopy];NSDictionary *bb=[b[@"branchBinding"] isKindOfClass:NSDictionary.class]?b[@"branchBinding"]:nil;if(bb&&[[bb[@"kind"] description] isEqual:@"conditional-return-path"]){BOOL tr=[bb[@"targetReachesReturn"] boolValue],fr=[bb[@"fallthroughReachesReturn"] boolValue];NSMutableDictionary *o=[NSMutableDictionary dictionary];if(tr!=fr){o[@"returningEdge"]=tr?@"target":@"fallthrough";o[@"nonReturningEdge"]=tr?@"fallthrough":@"target";o[@"confidence"]=@"strong";}else{o[@"returningEdge"]=@"unresolved";o[@"confidence"]=@"partial";}o[@"evidence"]=@"cfg-return-reachability";b[@"branchOutcome"]=o;}[out addObject:b];}return out;}
'''
    s=s[:pos]+helpers+s[pos:]

old='NSArray *runtime=HFAV036UnifiedRuntimeEvidence(HFA5MDispatcherAllEvidence()?:@[]);HFAV02Log([NSString stringWithFormat:@"[V037-EVIDENCE] unified=%lu",(unsigned long)runtime.count]);'
if old not in s: raise SystemExit('v038 evidence anchor missing')
new='NSDictionary *evidence38=HFAV038EvidenceSnapshot();NSArray *runtime=[evidence38[@"features"] isKindOfClass:NSArray.class]?evidence38[@"features"]:@[];NSString *readiness38=[evidence38[@"status"] isKindOfClass:NSString.class]?evidence38[@"status"]:@"pending";HFAV02Log([NSString stringWithFormat:@"[V038-EVIDENCE] status=%@ attempts=%@ unified=%lu",readiness38,evidence38[@"attempts"]?:@0,(unsigned long)runtime.count]);if(!runtime.count)HFAV02Log(@"[V038-EVIDENCE-PENDING] no-runtime-feature-evidence-after-bounded-retry");'
s=s.replace(old,new,1)

old_chain='NSArray *helper36=HFAV036ExpandHelperEvidence(sev,l);if(helper36.count){bb[@"helperEvidence"]=helper36;HFAV02Log([NSString stringWithFormat:@"[V037-HELPER] backend=%@ helpers=%lu",bb[@"backendId"]?:@0,(unsigned long)helper36.count]);}NSArray *direct36=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);NSArray *shared36=HFAV036SharedStateBindings(runtime,sev,helper36,image,l);NSArray *state37=HFAV037StateConsumerBindings(runtime,sev,helper36,image,l);NSArray *merged37=HFAV036MergeBindings(HFAV036MergeBindings(direct36,shared36),state37);NSArray *legacyBranch37=HFAV036BranchBindings(merged37,sev);NSArray *fb=HFAV037SemanticNodeBindings(legacyBranch37,sev);if(shared36.count)HFAV02Log([NSString stringWithFormat:@"[V037-SHARED-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)shared36.count]);if(state37.count)HFAV02Log([NSString stringWithFormat:@"[V037-STATE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)state37.count]);NSUInteger nodeBound=0;for(NSDictionary *fx in fb)if([fx[@"branchBinding"] isKindOfClass:NSDictionary.class])nodeBound++;if(nodeBound)HFAV02Log([NSString stringWithFormat:@"[V037-NODE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)nodeBound]);'
if old_chain not in s: raise SystemExit('v038 binding anchor missing')
new_chain='NSArray *helper36=HFAV036ExpandHelperEvidence(sev,l);if(helper36.count){bb[@"helperEvidence"]=helper36;HFAV02Log([NSString stringWithFormat:@"[V038-HELPER] backend=%@ helpers=%lu",bb[@"backendId"]?:@0,(unsigned long)helper36.count]);}NSArray *direct36=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);NSArray *shared36=HFAV036SharedStateBindings(runtime,sev,helper36,image,l);NSArray *state37=HFAV037StateConsumerBindings(runtime,sev,helper36,image,l);NSArray *downstream38=HFAV038DownstreamStateBindings(runtime,sev,helper36,image,l);NSArray *merged38=HFAV036MergeBindings(HFAV036MergeBindings(HFAV036MergeBindings(direct36,shared36),state37),downstream38);NSArray *legacyBranch38=HFAV036BranchBindings(merged38,sev);NSArray *fb=HFAV038BranchOutcomeBindings(HFAV037SemanticNodeBindings(legacyBranch38,sev));if(shared36.count)HFAV02Log([NSString stringWithFormat:@"[V038-SHARED-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)shared36.count]);if(state37.count)HFAV02Log([NSString stringWithFormat:@"[V038-STATE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)state37.count]);if(downstream38.count){bb[@"downstreamBindings"]=downstream38;HFAV02Log([NSString stringWithFormat:@"[V038-DOWNSTREAM-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)downstream38.count]);}NSUInteger nodeBound=0,outcomeBound=0;for(NSDictionary *fx in fb){if([fx[@"branchBinding"] isKindOfClass:NSDictionary.class])nodeBound++;if([fx[@"branchOutcome"] isKindOfClass:NSDictionary.class])outcomeBound++;}if(nodeBound)HFAV02Log([NSString stringWithFormat:@"[V038-NODE-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)nodeBound]);if(outcomeBound)HFAV02Log([NSString stringWithFormat:@"[V038-BRANCH-OUTCOME] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)outcomeBound]);'
s=s.replace(old_chain,new_chain,1)

root='@"orphanPatchDescriptors":orphans,@"targetConflicts":conflicts35,@"legacyRuntimeEvidence":runtime'
if root not in s: raise SystemExit('v038 root anchor missing')
s=s.replace(root,root+',@"evidenceReadiness":evidence38',1)
s=s.replace('com.hfa.runtime-analyzer/v0.3.7','com.hfa.runtime-analyzer/v0.3.8',1).replace('[V037-','[V038-').replace('HFAEnableIL2CPPEnrichmentV037','HFAEnableIL2CPPEnrichmentV038')
out='NSString *p37=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v037.json");'
if out not in s: raise SystemExit('v038 output anchor missing')
s=s.replace(out,'NSString *p38=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v038.json");'+out,1)
write='[json writeToFile:p37 atomically:YES];[json writeToFile:p36 atomically:YES];'
if write not in s: raise SystemExit('v038 write anchor missing')
s=s.replace(write,'[json writeToFile:p38 atomically:YES];'+write,1)
SRC.write_text(s)

SEM.write_text(SEM.read_text().replace('HFAMap_RuntimeAnalyzer_v037_stage.log','HFAMap_RuntimeAnalyzer_v038_stage.log').replace('V037-','V038-'))
UI.write_text(UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.7 ControlFlowConsumerBinding','HFAMap RuntimeAnalyzer v0.3.8 DownstreamConsumerResolver',2).replace('com.hfa.runtime-analyzer.v037','com.hfa.runtime-analyzer.v038'))

ss=SRC.read_text()
for x in ['HFAV038EvidenceSnapshot','HFAV038DownstreamSemanticEvidence','HFAV038ClassStateIndex','HFAV038DownstreamStateBindings','receiver-consumer','downstream-shared-state','[V038-DOWNSTREAM-BIND]','[V038-EVIDENCE-PENDING]','branchOutcome','HFAMap_RuntimeAnalyzer_v038.json','com.hfa.runtime-analyzer/v0.3.8','HFAEnableIL2CPPEnrichmentV038']:
    if x not in ss: raise SystemExit('missing '+x)
print('v0.3.8 downstream runtime consumer binding applied')
