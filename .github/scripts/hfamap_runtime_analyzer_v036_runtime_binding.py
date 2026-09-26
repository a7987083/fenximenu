from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
SEM=ROOT/'src'/'HFARuntimeSemanticAnalyzer.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'

sem=SEM.read_text()
mat='''    NSMutableDictionary *e=[@{@"runtimeAddress":@((unsigned long long)value),@"source":kind?:@"unknown"} mutableCopy];\n    if(value>=image.base)e[@"rva"]=HFASemRVA(value,image);'''
if mat not in sem: raise SystemExit('materialized-address anchor missing')
sem=sem.replace(mat,'''    NSMutableDictionary *e=[@{@"runtimeAddress":@((unsigned long long)value),@"source":kind?:@"unknown"} mutableCopy];\n    e[@"writable"]=@(HFASemWritable(value,image));\n    if(value>=image.base)e[@"rva"]=HFASemRVA(value,image);''',1)
sem=sem.replace('HFAMap_RuntimeAnalyzer_v035_stage.log','HFAMap_RuntimeAnalyzer_v036_stage.log')
sem=sem.replace('V035-','V036-')
SEM.write_text(sem)

s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
pos=s.find(scan)
if pos<0: raise SystemExit('scan entry missing')
if 'HFAV036UnifiedRuntimeEvidence' not in s:
    helpers=r'''
static NSString *HFAV036OutputDirectory(void){
    NSString *p=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v035.json");
    return p.length?[p stringByDeletingLastPathComponent]:@"";
}
static NSDictionary *HFAV036LatestAnalysis(void){
    NSString *dir=HFAV036OutputDirectory();if(!dir.length)return @{};NSFileManager *fm=[NSFileManager defaultManager];NSError *err=nil;NSArray *names=[fm contentsOfDirectoryAtPath:dir error:&err];if(!names.count)return @{};
    NSString *best=nil;NSDate *bestDate=nil;for(NSString *n in names){if(![n hasSuffix:@".hfamap.analysis.json"])continue;NSString *p=[dir stringByAppendingPathComponent:n];NSDictionary *a=[fm attributesOfItemAtPath:p error:nil];NSDate *d=a[NSFileModificationDate];if(!best||!bestDate||[d compare:bestDate]==NSOrderedDescending){best=p;bestDate=d;}}
    if(!best.length)return @{};NSData *data=[NSData dataWithContentsOfFile:best];if(!data.length)return @{};id obj=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];return [obj isKindOfClass:NSDictionary.class]?obj:@{};
}
static NSArray *HFAV036UnifiedRuntimeEvidence(NSArray *seed){
    NSMutableDictionary *by=[NSMutableDictionary dictionary];
    for(NSDictionary *x in seed?:@[]){NSString *identifier=[x[@"identifier"] isKindOfClass:NSString.class]?x[@"identifier"]:nil;if(!identifier.length)continue;by[identifier]=[x mutableCopy];}
    NSDictionary *analysis=HFAV036LatestAnalysis();NSArray *features=[analysis[@"features"] isKindOfClass:NSArray.class]?analysis[@"features"]:@[];
    for(NSDictionary *f in features){NSString *identifier=[f[@"id"] isKindOfClass:NSString.class]?f[@"id"]:([f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil);if(!identifier.length)continue;NSMutableDictionary *r=by[identifier]?:[NSMutableDictionary dictionary];r[@"identifier"]=identifier;if([f[@"title"] isKindOfClass:NSString.class])r[@"title"]=f[@"title"];NSDictionary *ctl=[f[@"control"] isKindOfClass:NSDictionary.class]?f[@"control"]:nil;if([ctl[@"kind"] isKindOfClass:NSString.class])r[@"type"]=ctl[@"kind"];if([f[@"menuImage"] isKindOfClass:NSString.class])r[@"menuImage"]=f[@"menuImage"];if([f[@"runtimeEvidence"] isKindOfClass:NSDictionary.class])r[@"runtimeEvidence"]=f[@"runtimeEvidence"];r[@"evidenceSource"]=@"unified-feature-catalog";by[identifier]=r;}
    return by.allValues?:@[];
}
static uintptr_t HFAV036FeatureImplementation(NSDictionary *f,const char *selectedImage,HFAV02Layout l){
    NSString *selected=selectedImage?[NSString stringWithUTF8String:selectedImage]:@"";NSDictionary *re=[f[@"runtimeEvidence"] isKindOfClass:NSDictionary.class]?f[@"runtimeEvidence"]:nil;NSDictionary *im=[re[@"implementation"] isKindOfClass:NSDictionary.class]?re[@"implementation"]:nil;NSString *image=[im[@"image"] isKindOfClass:NSString.class]?im[@"image"]:nil;BOOL ok=NO;uint64_t r=HFAV032HexValue(im[@"rva"],&ok);if(ok&&r&&(!image.length||[image isEqual:selected]))return l.base+(uintptr_t)r;
    NSArray *actions=[f[@"actions"] isKindOfClass:NSArray.class]?f[@"actions"]:@[];for(NSDictionary *ae in actions){NSDictionary *a=[ae[@"action"] isKindOfClass:NSDictionary.class]?ae[@"action"]:nil;NSString *ai=[a[@"image"] isKindOfClass:NSString.class]?a[@"image"]:nil;BOOL aok=NO;uint64_t ar=HFAV032HexValue(a[@"rva"],&aok);if(aok&&ar&&(!ai.length||[ai isEqual:selected]))return l.base+(uintptr_t)ar;}return 0;
}
static void HFAV036AddStateAddresses(NSMutableDictionary *dst,NSDictionary *sem,HFAV02Layout l){
    for(NSDictionary *e in [sem[@"materializedAddresses"] isKindOfClass:NSArray.class]?sem[@"materializedAddresses"]:@[]){NSNumber *n=[e[@"runtimeAddress"] isKindOfClass:NSNumber.class]?e[@"runtimeAddress"]:nil;if(!n||![e[@"writable"] boolValue])continue;dst[n]=e;}
    for(NSDictionary *c in [sem[@"receiverCaptures"] isKindOfClass:NSArray.class]?sem[@"receiverCaptures"]:@[]){BOOL ok=NO;uint64_t r=HFAV032HexValue(c[@"storeRVA"],&ok);if(ok){NSNumber *n=@((unsigned long long)(l.base+(uintptr_t)r));NSMutableDictionary *e=[c mutableCopy];e[@"runtimeAddress"]=n;dst[n]=e;}}
}
static NSArray *HFAV036ExpandHelperEvidence(NSDictionary *sem,HFAV02Layout l){
    NSString *type=[sem[@"semanticType"] isKindOfClass:NSString.class]?sem[@"semanticType"]:@"";BOOL wants=[type containsString:@"receiver-capture-with-helper"]||[type isEqual:@"runtime-state"];if(!wants)return @[];NSArray *calls=[sem[@"helperCalls"] isKindOfClass:NSArray.class]?sem[@"helperCalls"]:@[];NSMutableArray *out=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(NSDictionary *c in calls){if(out.count>=4)break;NSString *rv=[c[@"targetRVA"] isKindOfClass:NSString.class]?c[@"targetRVA"]:nil;if(!rv.length||[seen containsObject:rv])continue;BOOL ok=NO;uint64_t r=HFAV032HexValue(rv,&ok);if(!ok||!r)continue;[seen addObject:rv];NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(l.base+(uintptr_t)r,0,0)?:@{};}@catch(NSException *ex){ev=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime"};}[out addObject:@{@"targetRVA":rv,@"semanticEvidence":ev}];}
    return out;
}
static NSDictionary *HFAV036ActionSemantic(NSDictionary *f,const char *selectedImage,HFAV02Layout l){
    uintptr_t a=HFAV036FeatureImplementation(f,selectedImage,l);if(!a)return @{};static NSMutableDictionary *cache;static dispatch_once_t once;dispatch_once(&once,^{cache=[NSMutableDictionary dictionary];});NSNumber *key=@((unsigned long long)a);@synchronized(cache){NSDictionary *hit=cache[key];if(hit)return hit;}NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(a,0,0)?:@{};}@catch(NSException *ex){ev=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime"};}@synchronized(cache){cache[key]=ev;}return ev;
}
static NSArray *HFAV036SharedStateBindings(NSArray *runtime,NSDictionary *sem,NSArray *helperEvidence,const char *selectedImage,HFAV02Layout l){
    NSMutableDictionary *backend=[NSMutableDictionary dictionary];HFAV036AddStateAddresses(backend,sem,l);for(NSDictionary *h in helperEvidence){NSDictionary *ev=[h[@"semanticEvidence"] isKindOfClass:NSDictionary.class]?h[@"semanticEvidence"]:@{};HFAV036AddStateAddresses(backend,ev,l);}if(!backend.count)return @[];
    NSMutableArray *out=[NSMutableArray array];for(NSDictionary *f in runtime){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:nil;if(!identifier.length)continue;NSDictionary *aev=HFAV036ActionSemantic(f,selectedImage,l);NSMutableDictionary *ast=[NSMutableDictionary dictionary];HFAV036AddStateAddresses(ast,aev,l);NSNumber *shared=nil;for(NSNumber *n in ast)if(backend[n]){shared=n;break;}if(!shared)continue;NSDictionary *be=backend[shared];NSMutableDictionary *b=[@{@"identifier":identifier,@"confidence":@"strong",@"evidence":@"shared-writable-state",@"matchedRuntimeAddress":shared} mutableCopy];if([f[@"title"] isKindOfClass:NSString.class])b[@"title"]=f[@"title"];if([f[@"type"] isKindOfClass:NSString.class])b[@"controlType"]=f[@"type"];if([be[@"sourceRVA"] isKindOfClass:NSString.class])b[@"matchedSourceRVA"]=be[@"sourceRVA"];[out addObject:b];}return out;
}
static NSArray *HFAV036MergeBindings(NSArray *a,NSArray *b){NSMutableDictionary *m=[NSMutableDictionary dictionary];for(NSDictionary *x in a?:@[]){NSString *i=[x[@"identifier"] isKindOfClass:NSString.class]?x[@"identifier"]:nil;if(i.length)m[i]=[x mutableCopy];}for(NSDictionary *x in b?:@[]){NSString *i=[x[@"identifier"] isKindOfClass:NSString.class]?x[@"identifier"]:nil;if(!i.length)continue;NSMutableDictionary *e=m[i];if(!e)m[i]=[x mutableCopy];else{if(!e[@"matchedSourceRVA"]&&x[@"matchedSourceRVA"])e[@"matchedSourceRVA"]=x[@"matchedSourceRVA"];if(!e[@"matchedRuntimeAddress"]&&x[@"matchedRuntimeAddress"])e[@"matchedRuntimeAddress"]=x[@"matchedRuntimeAddress"];if([e[@"evidence"] isEqual:@"cfstring-reference"]==NO)e[@"evidence"]=x[@"evidence"]?:e[@"evidence"];}}return m.allValues?:@[];}
static NSArray *HFAV036BranchBindings(NSArray *bindings,NSDictionary *sem){
    NSArray *ops=[sem[@"operations"] isKindOfClass:NSArray.class]?sem[@"operations"]:@[];NSArray *mat=[sem[@"materializedAddresses"] isKindOfClass:NSArray.class]?sem[@"materializedAddresses"]:@[];NSMutableArray *work=[NSMutableArray array];for(NSDictionary *x in bindings){NSMutableDictionary *b=[x mutableCopy];NSString *src=[b[@"matchedSourceRVA"] isKindOfClass:NSString.class]?b[@"matchedSourceRVA"]:nil;if(!src.length&&[b[@"matchedRuntimeAddress"] isKindOfClass:NSNumber.class]){NSNumber *n=b[@"matchedRuntimeAddress"];for(NSDictionary *e in mat)if([e[@"runtimeAddress"] isEqual:n]&&[e[@"sourceRVA"] isKindOfClass:NSString.class]){src=e[@"sourceRVA"];b[@"matchedSourceRVA"]=src;break;}}[work addObject:b];}
    NSMutableSet *used=[NSMutableSet set];for(NSMutableDictionary *b in work){BOOL sok=NO;uint64_t sr=HFAV032HexValue(b[@"matchedSourceRVA"],&sok);if(!sok)continue;NSDictionary *best=nil;uint64_t bestD=UINT64_MAX;for(NSDictionary *op in ops){NSString *name=[op[@"op"] isKindOfClass:NSString.class]?op[@"op"]:@"";if([name isEqual:@"CALL_ORIGINAL"]||[name isEqual:@"TAILCALL_ORIGINAL"])continue;BOOL ook=NO;uint64_t orva=HFAV032HexValue(op[@"rva"],&ook);if(!ook||orva<sr||orva-sr>0x90)continue;NSString *key=[NSString stringWithFormat:@"%@|%@",name,op[@"rva"]?:@""];if([used containsObject:key])continue;if(orva-sr<bestD){best=op;bestD=orva-sr;}}if(best){NSString *key=[NSString stringWithFormat:@"%@|%@",best[@"op"]?:@"?",best[@"rva"]?:@""];[used addObject:key];b[@"branchBinding"]=@{@"op":best[@"op"]?:@"?",@"opRVA":best[@"rva"]?:@"",@"sourceRVA":b[@"matchedSourceRVA"]?:@"",@"distance":@(bestD),@"confidence":bestD<=0x50?@"strong":@"medium"};}}
    return work;
}

'''
    s=s[:pos]+helpers+s[pos:]

runtime='NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];'
if runtime not in s: raise SystemExit('runtime evidence anchor missing')
s=s.replace(runtime,'NSArray *runtime=HFAV036UnifiedRuntimeEvidence(HFA5MDispatcherAllEvidence()?:@[]);HFAV02Log([NSString stringWithFormat:@"[V036-EVIDENCE] unified=%lu",(unsigned long)runtime.count]);',1)

old='NSArray *fb=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);'
if old not in s: raise SystemExit('feature-binding call anchor missing')
new='''NSArray *helper36=HFAV036ExpandHelperEvidence(sev,l);if(helper36.count){bb[@"helperEvidence"]=helper36;HFAV02Log([NSString stringWithFormat:@"[V036-HELPER] backend=%@ helpers=%lu",bb[@"backendId"]?:@0,(unsigned long)helper36.count]);}NSArray *direct36=HFASemanticFeatureBindings(runtime,sev,l.base+(uintptr_t)off);NSArray *shared36=HFAV036SharedStateBindings(runtime,sev,helper36,image,l);NSArray *fb=HFAV036BranchBindings(HFAV036MergeBindings(direct36,shared36),sev);if(shared36.count)HFAV02Log([NSString stringWithFormat:@"[V036-SHARED-BIND] backend=%@ features=%lu",bb[@"backendId"]?:@0,(unsigned long)shared36.count]);'''
s=s.replace(old,new,1)

# Promote version markers while retaining all v0.3.5 compatibility outputs.
s=s.replace('com.hfa.runtime-analyzer/v0.3.5','com.hfa.runtime-analyzer/v0.3.6',1)
s=s.replace('[V035-','[V036-')
s=s.replace('HFAEnableIL2CPPEnrichmentV035','HFAEnableIL2CPPEnrichmentV036')
out='NSString *p35=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v035.json");'
if out not in s: raise SystemExit('v036 output anchor missing')
s=s.replace(out,'NSString *p36=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v036.json");'+out,1)
write='[json writeToFile:p35 atomically:YES];[json writeToFile:p342 atomically:YES];'
if write not in s: raise SystemExit('v036 write anchor missing')
s=s.replace(write,'[json writeToFile:p36 atomically:YES];'+write,1)
SRC.write_text(s)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.5 SemanticCoverageBinding','HFAMap RuntimeAnalyzer v0.3.6 RuntimeSemanticCompletion',2).replace('com.hfa.runtime-analyzer.v035','com.hfa.runtime-analyzer.v036')
UI.write_text(u)

s=SRC.read_text();sem=SEM.read_text()
for x in ['HFAV036UnifiedRuntimeEvidence','HFAV036SharedStateBindings','HFAV036ExpandHelperEvidence','HFAV036BranchBindings','[V036-EVIDENCE]','[V036-SHARED-BIND]','[V036-HELPER]','HFAMap_RuntimeAnalyzer_v036.json','com.hfa.runtime-analyzer/v0.3.6','HFAEnableIL2CPPEnrichmentV036']:
    if x not in s: raise SystemExit('missing '+x)
if '@"writable"' not in sem: raise SystemExit('materialized writable classification missing')
for forbidden in ['RandomDice','SPGainMulti','WayOfKings','RogueLegend','MeChat','Duck Survival']:
    if forbidden in s or forbidden in sem: raise SystemExit('game-specific token leaked into v036 generic layer: '+forbidden)
print('v0.3.6 runtime hook evidence/binding completion applied')
