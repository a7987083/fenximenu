from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'
s=SRC.read_text()
scan_token='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
if scan_token not in s: raise SystemExit('v039 scan anchor missing')

if 'HFAV039ImageExactStateIndex' not in s:
    helper=r'''
static NSDictionary *HFAV039ImageExactStateIndex(const char *selectedImage,HFAV02Layout l){
    if(!selectedImage||!*selectedImage)return @{};static NSMutableDictionary *cache;static dispatch_once_t once;dispatch_once(&once,^{cache=[NSMutableDictionary dictionary];});NSString *ck=[NSString stringWithFormat:@"%llX|%s",(unsigned long long)l.base,selectedImage];@synchronized(cache){NSDictionary *hit=cache[ck];if(hit)return hit;}
    Class classes[768]={0};unsigned cc=HFAAppLocalCopyClassesForImage(selectedImage,classes,768);NSMutableArray *methods=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(unsigned ci=0;ci<cc&&ci<768;ci++){Class cls=classes[ci];if(!cls)continue;for(int pass=0;pass<2;pass++){Class owner=pass?object_getClass(cls):cls;if(!owner)continue;unsigned count=0;Method *ml=class_copyMethodList(owner,&count);for(unsigned mi=0;ml&&mi<count&&methods.count<1024;mi++){uintptr_t a=(uintptr_t)method_getImplementation(ml[mi]);Dl_info di={0};if(!a||!dladdr((void*)a,&di)||!di.dli_fbase||(uintptr_t)di.dli_fbase!=l.base)continue;NSNumber *key=@((unsigned long long)a);if([seen containsObject:key])continue;[seen addObject:key];[methods addObject:@{@"address":key,@"selector":NSStringFromSelector(method_getName(ml[mi]))?:@"?",@"class":[NSString stringWithUTF8String:class_getName(cls)?:"?"]?:@"?"}];}free(ml);if(methods.count>=1024)break;}if(methods.count>=1024)break;}
    [methods sortUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){unsigned long long x=[a[@"address"] unsignedLongLongValue],y=[b[@"address"] unsignedLongLongValue];return x<y?NSOrderedAscending:(x>y?NSOrderedDescending:NSOrderedSame);}];NSMutableDictionary *idx=[NSMutableDictionary dictionary];NSUInteger scanned=0;BOOL budget=NO;CFAbsoluteTime started=CFAbsoluteTimeGetCurrent();
    for(NSUInteger i=0;i<methods.count;i++){if(scanned>=512||CFAbsoluteTimeGetCurrent()-started>0.35){budget=YES;break;}uintptr_t a=(uintptr_t)[methods[i][@"address"] unsignedLongLongValue],end=0;if(i+1<methods.count){uintptr_t n=(uintptr_t)[methods[i+1][@"address"] unsignedLongLongValue];if(n>a&&n-a<=0x4000)end=n;}NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(a,0,end)?:@{};}@catch(NSException *ex){scanned++;continue;}scanned++;
        for(NSDictionary *sa in [ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[]){if(![sa[@"exact"] boolValue])continue;NSNumber *n=[sa[@"runtimeAddress"] isKindOfClass:NSNumber.class]?sa[@"runtimeAddress"]:nil;if(!n)continue;NSMutableArray *bucket=idx[n];if(!bucket){bucket=[NSMutableArray array];idx[n]=bucket;}NSMutableDictionary *x=[sa mutableCopy];x[@"origin"]=@"image-exact-state-xref";x[@"selector"]=methods[i][@"selector"]?:@"?";x[@"class"]=methods[i][@"class"]?:@"?";x[@"methodRVA"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)(a-l.base)];x[@"semanticType"]=ev[@"semanticType"]?:@"unknown-runtime";[bucket addObject:x];}
    }
    NSDictionary *out=@{@"index":[idx copy],@"methodCount":@(methods.count),@"scannedMethods":@(scanned),@"budgetExceeded":@(budget)};@synchronized(cache){cache[ck]=out;}return out;
}
static NSMutableDictionary *HFAV039BackendStateIndex(NSDictionary *sem,NSArray *helperEvidence){NSMutableDictionary *backend=[NSMutableDictionary dictionary];HFAV037CollectStateIndex(backend,sem,@"backend");for(NSDictionary *h in helperEvidence?:@[]){NSDictionary *ev=[h[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?h[@"semanticEvidence"]:@{};HFAV037CollectStateIndex(backend,ev,@"helper");}return backend;}
static NSArray *HFAV039StateXrefCandidates(NSDictionary *sem,NSArray *helperEvidence,const char *selectedImage,HFAV02Layout l,NSDictionary **metaOut){NSMutableDictionary *backend=HFAV039BackendStateIndex(sem,helperEvidence);if(!backend.count){if(metaOut)*metaOut=@{};return @[];}NSDictionary *all=HFAV039ImageExactStateIndex(selectedImage,l);NSDictionary *idx=[all[@"index"] isKindOfClass:NSDictionary.class]?all[@"index"]:@{};NSMutableArray *out=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(NSNumber *n in backend){NSArray *ba=backend[n],*ca=[idx[n] isKindOfClass:NSArray.class]?idx[n]:@[];if(!ca.count)continue;NSDictionary *bw=HFAV037FirstAccess(ba,@"write"),*br=HFAV037FirstAccess(ba,@"read");for(NSDictionary *ce in ca){NSDictionary *be=nil;NSString *rel=nil;NSString *access=[ce[@"access"] description];if(bw&&[access isEqual:@"read"]){be=bw;rel=@"receiver-consumer-candidate";}else if((bw||br)&&([access isEqual:@"write"]||bw)){be=bw?:br;rel=@"exact-shared-state-candidate";}if(!be||!rel)continue;NSString *key=[NSString stringWithFormat:@"%@|%@|%@",n,ce[@"methodRVA"]?:@"?",rel];if([seen containsObject:key])continue;[seen addObject:key];NSMutableDictionary *x=[@{@"matchedRuntimeAddress":n,@"relation":rel,@"confidence":@"candidate",@"backendAccess":be,@"consumerAccess":ce} mutableCopy];if(ce[@"class"])x[@"consumerClass"]=ce[@"class"];if(ce[@"selector"])x[@"consumerSelector"]=ce[@"selector"];if(ce[@"methodRVA"])x[@"consumerMethodRVA"]=ce[@"methodRVA"];[out addObject:x];if(out.count>=48)break;}if(out.count>=48)break;}
    if(metaOut)*metaOut=@{@"methodCount":all[@"methodCount"]?:@0,@"scannedMethods":all[@"scannedMethods"]?:@0,@"budgetExceeded":all[@"budgetExceeded"]?:@NO,@"candidateCount":@(out.count)};return out;
}
static void HFAV039CollectTaggedStates(NSMutableDictionary *dst,NSDictionary *ev,NSString *origin,NSString *selector){if(!dst||![ev isKindOfClass:NSDictionary.class])return;for(NSDictionary *sa in [ev[@"stateAccesses"] isKindOfClass:NSArray.class]?ev[@"stateAccesses"]:@[]){if(![sa[@"exact"] boolValue])continue;NSNumber *n=[sa[@"runtimeAddress"] isKindOfClass:NSNumber.class]?sa[@"runtimeAddress"]:nil;if(!n)continue;NSMutableArray *bucket=dst[n];if(!bucket){bucket=[NSMutableArray array];dst[n]=bucket;}NSMutableDictionary *x=[sa mutableCopy];x[@"origin"]=origin?:@"downstream";if(selector.length)x[@"selector"]=selector;[bucket addObject:x];}}
static NSDictionary *HFAV039SemanticAtRVA(NSString *rva,HFAV02Layout l){BOOL ok=NO;uint64_t r=HFAV032HexValue(rva,&ok);if(!ok||!r)return @{};static NSMutableDictionary *cache;static dispatch_once_t once;dispatch_once(&once,^{cache=[NSMutableDictionary dictionary];});NSNumber *key=@((unsigned long long)(l.base+(uintptr_t)r));@synchronized(cache){NSDictionary *hit=cache[key];if(hit)return hit;}NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(l.base+(uintptr_t)r,0,0)?:@{};}@catch(NSException *ex){ev=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime"};}@synchronized(cache){cache[key]=ev;}return ev;}
static NSArray *HFAV039DownstreamHelperBindings(NSArray *runtime,NSDictionary *sem,NSArray *helperEvidence,const char *selectedImage,HFAV02Layout l){NSMutableDictionary *backend=HFAV039BackendStateIndex(sem,helperEvidence);if(!backend.count)return @[];NSMutableArray *out=[NSMutableArray array];
    for(NSDictionary *f in runtime?:@[]){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSMutableDictionary *cons=[NSMutableDictionary dictionary];NSArray *down=HFAV038DownstreamSemanticEvidence(f,selectedImage,l);for(NSDictionary *ds in down){NSDictionary *ev=[ds[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?ds[@"semanticEvidence"]:@{};NSString *sel=[ds[@"selector"] isKindOfClass:NSString.class]?ds[@"selector"]:nil;HFAV039CollectTaggedStates(cons,ev,ds[@"origin"]?:@"downstream",sel);NSMutableSet *seen=[NSMutableSet set];for(NSDictionary *hc in [ev[@"helperCalls"] isKindOfClass:NSArray.class]?ev[@"helperCalls"]:@[]){if(seen.count>=6)break;NSString *rv=[hc[@"targetRVA"] isKindOfClass:NSString.class]?hc[@"targetRVA"]:nil;if(!rv.length||[seen containsObject:rv])continue;[seen addObject:rv];NSDictionary *hev=HFAV039SemanticAtRVA(rv,l);HFAV039CollectTaggedStates(cons,hev,@"downstream-helper",sel);}}
        NSNumber *match=nil;NSDictionary *be=nil,*ce=nil;NSString *relation=nil;for(NSNumber *n in cons){NSArray *ba=backend[n],*ca=cons[n];if(!ba.count||!ca.count)continue;NSDictionary *bw=HFAV037FirstAccess(ba,@"write"),*br=HFAV037FirstAccess(ba,@"read"),*cr=HFAV037FirstAccess(ca,@"read"),*cw=HFAV037FirstAccess(ca,@"write");if(bw&&cr){match=n;be=bw;ce=cr;relation=@"notification-helper-receiver-consumer";break;}if((bw||br)&&(cw||cr)&&(bw||cw)){match=n;be=bw?:br;ce=cw?:cr;relation=@"notification-helper-shared-state";break;}}
        if(!match)continue;NSMutableDictionary *b=[@{@"identifier":identifier,@"confidence":@"strong",@"evidence":relation?:@"notification-helper-state",@"matchedRuntimeAddress":match,@"backendAccess":be?:@{},@"consumerAccess":ce?:@{}} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])b[@"title"]=f[@"title"];if([f[@"type"] isKindOfClass:NSString.class])b[@"controlType"]=f[@"type"];if([be[@"sourceRVA"] isKindOfClass:NSString.class])b[@"matchedSourceRVA"]=be[@"sourceRVA"];if([ce[@"sourceRVA"] isKindOfClass:NSString.class])b[@"consumerSourceRVA"]=ce[@"sourceRVA"];if([ce[@"selector"] isKindOfClass:NSString.class])b[@"consumerSelector"]=ce[@"selector"];[out addObject:b];}
    return out;
}
'''
    pos=s.find(scan_token)
    if pos<0: raise SystemExit('v039 actual scan entry missing')
    s=s[:pos]+helper+'\n'+s[pos:]

old='NSArray *downstream38=HFAV038DownstreamStateBindings(runtime,sev,helper36,image,l);NSArray *merged38=HFAV036MergeBindings(HFAV036MergeBindings(HFAV036MergeBindings(direct36,shared36),state37),downstream38);NSArray *legacyBranch38=HFAV036BranchBindings(merged38,sev);NSArray *fb=HFAV038BranchOutcomeBindings(HFAV037SemanticNodeBindings(legacyBranch38,sev));'
if old not in s: raise SystemExit('v039 binding anchor missing')
new='NSArray *downstream38=HFAV038DownstreamStateBindings(runtime,sev,helper36,image,l);NSArray *downstream39=HFAV039DownstreamHelperBindings(runtime,sev,helper36,image,l);NSDictionary *xrefMeta39=nil;NSArray *xref39=HFAV039StateXrefCandidates(sev,helper36,image,l,&xrefMeta39);if(xref39.count)bb[@"stateXrefConsumers"]=xref39;if(xrefMeta39.count)bb[@"stateXrefMeta"]=xrefMeta39;NSArray *merged39=HFAV036MergeBindings(HFAV036MergeBindings(HFAV036MergeBindings(HFAV036MergeBindings(direct36,shared36),state37),downstream38),downstream39);NSArray *legacyBranch38=HFAV036BranchBindings(merged39,sev);NSArray *fb=HFAV038BranchOutcomeBindings(HFAV037SemanticNodeBindings(legacyBranch38,sev));'
s=s.replace(old,new,1)

oldlog='if(downstream38.count){bb[@"downstreamBindings"]=downstream38;HFAV02Log([NSString stringWithFormat:@"[V038-DOWNSTREAM-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)downstream38.count]);}NSUInteger nodeBound=0,outcomeBound=0;'
if oldlog not in s: raise SystemExit('v039 downstream log anchor missing')
newlog='if(downstream38.count){bb[@"downstreamBindings"]=downstream38;HFAV02Log([NSString stringWithFormat:@"[V039-DOWNSTREAM-BIND] backend=%@ directFeatures=%lu",bb[@"backendId"]?:@0,(unsigned long)downstream38.count]);}if(downstream39.count){bb[@"downstreamHelperBindings"]=downstream39;HFAV02Log([NSString stringWithFormat:@"[V039-DOWNSTREAM-HELPER-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)downstream39.count]);}if(xrefMeta39.count)HFAV02Log([NSString stringWithFormat:@"[V039-STATE-XREF] backend=%@ methods=%@ candidates=%@ budget=%@",bb[@"backendId"]?:@0,xrefMeta39[@"scannedMethods"]?:@0,xrefMeta39[@"candidateCount"]?:@0,[xrefMeta39[@"budgetExceeded"] boolValue]?@"exceeded":@"ok"]);NSUInteger nodeBound=0,outcomeBound=0;'
s=s.replace(oldlog,newlog,1)

s=s.replace('com.hfa.runtime-analyzer/v0.3.8','com.hfa.runtime-analyzer/v0.3.9',1)
s=s.replace('HFAEnableIL2CPPEnrichmentV038','HFAEnableIL2CPPEnrichmentV039')
out='NSString *p38=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v038.json");'
if out not in s: raise SystemExit('v039 output anchor missing')
s=s.replace(out,'NSString *p39=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v039.json");'+out,1)
write='[json writeToFile:p38 atomically:YES];[json writeToFile:p37 atomically:YES];'
if write not in s: raise SystemExit('v039 write anchor missing')
s=s.replace(write,'[json writeToFile:p39 atomically:YES];'+write,1)
SRC.write_text(s)

sem=SEM.read_text().replace('HFAMap_RuntimeAnalyzer_v038_stage.log','HFAMap_RuntimeAnalyzer_v039_stage.log')
SEM.write_text(sem)
ui=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.8 DownstreamConsumerResolver','HFAMap RuntimeAnalyzer v0.3.9 ExactStateXrefConsumerResolver',2).replace('com.hfa.runtime-analyzer.v038','com.hfa.runtime-analyzer.v039')
UI.write_text(ui)

ss=SRC.read_text()
for required in ['HFAV039ImageExactStateIndex','HFAV039StateXrefCandidates','HFAV039DownstreamHelperBindings','image-exact-state-xref','receiver-consumer-candidate','notification-helper-receiver-consumer','[V039-STATE-XREF]','[V039-DOWNSTREAM-HELPER-BIND]','HFAMap_RuntimeAnalyzer_v039.json','com.hfa.runtime-analyzer/v0.3.9','HFAEnableIL2CPPEnrichmentV039']:
    if required not in ss: raise SystemExit('missing '+required)
for forbidden in ['0x2D98AC8','0x2D9887C','0x2E25904']:
    if forbidden in ss: raise SystemExit('fixed RVA leaked into v039 runtime layer')
print('v0.3.9 exact-state xref and downstream helper consumer resolver applied')
