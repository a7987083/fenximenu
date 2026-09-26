from pathlib import Path

ROOT=Path('hfamap')
SRC=ROOT/'src'/'HFAMapRuntimeAnalyzerV02.m'
UI=ROOT/'src'/'HFAMapCyberUI.m'

s=SRC.read_text()
scan='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
i=s.find(scan)
if i<0:raise SystemExit('scan entry missing')
if 'HFAV035DescriptorlessActionBackends' not in s:
    helpers=r'''
static NSArray *HFAV035DescriptorlessActionBackends(NSArray *runtime,const char *selectedImage,HFAV02Layout l){
    if(!runtime.count||!selectedImage||!*selectedImage)return @[];NSString *selected=[NSString stringWithUTF8String:selectedImage]?:@"";NSMutableDictionary *groups=[NSMutableDictionary dictionary];
    for(NSDictionary *f in runtime){NSString *identifier=[f[@"identifier"] isKindOfClass:NSString.class]?f[@"identifier"]:@"";NSString *title=[f[@"title"] isKindOfClass:NSString.class]?f[@"title"]:@"";NSString *type=[f[@"type"] isKindOfClass:NSString.class]?f[@"type"]:@"";NSArray *actions=[f[@"actions"] isKindOfClass:NSArray.class]?f[@"actions"]:@[];
        for(NSDictionary *ae in actions){NSDictionary *a=[ae[@"action"] isKindOfClass:NSDictionary.class]?ae[@"action"]:nil;if(!a)continue;NSString *im=[a[@"image"] isKindOfClass:NSString.class]?a[@"image"]:@"";if(![im isEqual:selected])continue;BOOL ok=NO;uint64_t r=HFAV032HexValue(a[@"rva"],&ok);if(!ok)continue;NSString *k=[NSString stringWithFormat:@"%llX",(unsigned long long)r];NSMutableDictionary *g=groups[k];if(!g){g=[@{@"rva":@(r),@"image":im,@"features":[NSMutableArray array]} mutableCopy];groups[k]=g;}NSMutableArray *fs=g[@"features"];BOOL dup=NO;for(NSDictionary *x in fs)if([x[@"identifier"] isEqual:identifier]){dup=YES;break;}if(dup)continue;NSMutableDictionary *b=[@{@"identifier":identifier,@"title":title,@"controlType":type,@"confidence":@"strong",@"evidence":@"runtime-action-implementation"} mutableCopy];if([a[@"selector"] isKindOfClass:NSString.class])b[@"selector"]=a[@"selector"];if([ae[@"targetClass"] isKindOfClass:NSString.class])b[@"targetClass"]=ae[@"targetClass"];[fs addObject:b];}}
    }
    NSArray *ordered=[[groups allValues] sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a,NSDictionary *b){unsigned long long x=[a[@"rva"] unsignedLongLongValue],y=[b[@"rva"] unsignedLongLongValue];return x<y?NSOrderedAscending:(x>y?NSOrderedDescending:NSOrderedSame);}];NSMutableArray *out=[NSMutableArray array];
    for(NSUInteger n=0;n<ordered.count;n++){NSDictionary *g=ordered[n];uint64_t r=[g[@"rva"] unsignedLongLongValue];uintptr_t addr=l.base+(uintptr_t)r,hardEnd=0;if(n+1<ordered.count){uint64_t nr=[ordered[n+1][@"rva"] unsignedLongLongValue];if(nr>r)hardEnd=l.base+(uintptr_t)nr;}NSDictionary *ev=@{};@try{ev=HFASemanticAnalyzeReplacementBounded(addr,0,hardEnd)?:@{};}@catch(NSException *e){ev=@{@"status":@"objc-exception",@"semanticType":@"unknown-runtime"};}NSString *st=[ev[@"semanticType"] isKindOfClass:NSString.class]?ev[@"semanticType"]:@"unknown-runtime";if([st isEqual:@"unknown-runtime"])st=@"descriptor-less-action";[out addObject:[@{@"backendType":@"descriptor-less-action",@"semanticType":st,@"actionRVA":[NSString stringWithFormat:@"0x%llX",r],@"replacementRVA":[NSString stringWithFormat:@"0x%llX",r],@"targetImage":g[@"image"]?:@"?",@"featureBindings":g[@"features"]?:@[],@"semanticEvidence":ev,@"canonicalEligible":@NO,@"canonicalReason":@"runtime-action-not-static-bytes"} mutableCopy]];}
    return out;
}
static NSArray *HFAV035TargetConflicts(NSArray *backends){NSMutableDictionary *m=[NSMutableDictionary dictionary];for(NSDictionary *b in backends){NSString *r=[b[@"targetRVA"] isKindOfClass:NSString.class]?b[@"targetRVA"]:nil;NSString *im=[b[@"targetImage"] isKindOfClass:NSString.class]?b[@"targetImage"]:nil;if(!r.length||!im.length)continue;NSString *k=[NSString stringWithFormat:@"%@|%@",im,r];NSMutableArray *a=m[k];if(!a){a=[NSMutableArray array];m[k]=a;}[a addObject:b[@"backendId"]?:@0];}NSMutableArray *out=[NSMutableArray array];for(NSString *k in m){NSArray *ids=m[k];if(ids.count<2)continue;NSArray *p=[k componentsSeparatedByString:@"|"];[out addObject:@{@"targetImage":p.firstObject?:@"?",@"targetRVA":p.count>1?p[1]:@"?",@"backendIds":ids,@"status":@"duplicate-target-requires-explicit-resolution"}];}return out;}

'''
    s=s[:i]+helpers+s[i:]

anchor='NSUInteger bindingCount35=0;'
if anchor not in s:raise SystemExit('feature binding stage missing')
s=s.replace(anchor,'NSUInteger bindingCount35=0,actionCount35=0;',1)
loop='for(NSMutableDictionary *bb in backends)'
pos=s.find(loop,s.find('NSArray *runtime=HFA5MDispatcherAllEvidence()?:@[];'))
if pos<0:raise SystemExit('binding loop missing')
insert='''if(backends.count==0&&runtime.count){NSArray *ab=HFAV035DescriptorlessActionBackends(runtime,image,l);actionCount35=ab.count;unsigned aid=1;for(NSMutableDictionary *x in ab){x[@"backendId"]=@(aid++);[backends addObject:x];HFAV02Log([NSString stringWithFormat:@"[V035-ACTION-BACKEND] id=%@ rva=%@ features=%lu semantic=%@",x[@"backendId"],x[@"actionRVA"],(unsigned long)[x[@"featureBindings"] count],x[@"semanticType"]]);}}\n    '''
s=s[:pos]+insert+s[pos:]
# Existing action backends already have exact action-based feature bindings; the generic string binder skips them naturally.
needle='NSArray *conflicts35=HFAV035TargetConflicts(backends);'
# feature-binding script does not create this marker; append after its loop by using the next root construction anchor.
rootpos=s.find('NSDictionary *root=@{')
if rootpos<0:raise SystemExit('root anchor missing')
s=s[:rootpos]+'NSArray *conflicts35=HFAV035TargetConflicts(backends);\n    '+s[rootpos:]

summary='@"orphanPatches":@(orphans.count),@"featureBindings":@(bindingCount35)'
if summary not in s:raise SystemExit('summary binding anchor missing')
s=s.replace(summary,summary+',@"descriptorlessAction":@(actionCount35),@"targetConflicts":@(conflicts35.count)',1)
root='@"orphanPatchDescriptors":orphans,@"legacyRuntimeEvidence":runtime'
if root not in s:raise SystemExit('root evidence anchor missing')
s=s.replace(root,'@"orphanPatchDescriptors":orphans,@"targetConflicts":conflicts35,@"legacyRuntimeEvidence":runtime',1)

s=s.replace('com.hfa.runtime-analyzer/v0.3.4.2','com.hfa.runtime-analyzer/v0.3.5',1)
s=s.replace('[V0342-','[V035-')
s=s.replace('HFAEnableIL2CPPEnrichmentV0342','HFAEnableIL2CPPEnrichmentV035')
out='NSString *p342=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v0342.json");'
if out not in s:raise SystemExit('v035 output anchor missing')
s=s.replace(out,'NSString *p35=HFAOutputPath(@"HFAMap_RuntimeAnalyzer_v035.json");'+out,1)
write='[json writeToFile:p342 atomically:YES];[json writeToFile:p341 atomically:YES];'
if write not in s:raise SystemExit('v035 write anchor missing')
s=s.replace(write,'[json writeToFile:p35 atomically:YES];'+write,1)
SRC.write_text(s)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.4.2 CFGReachability','HFAMap RuntimeAnalyzer v0.3.5 SemanticCoverageBinding',2).replace('com.hfa.runtime-analyzer.v0342','com.hfa.runtime-analyzer.v035')
UI.write_text(u)

s=SRC.read_text()
for x in ['HFAV035DescriptorlessActionBackends','HFAV035TargetConflicts','[V035-ACTION-BACKEND]','descriptorlessAction','targetConflicts','HFAMap_RuntimeAnalyzer_v035.json','com.hfa.runtime-analyzer/v0.3.5','HFAEnableIL2CPPEnrichmentV035']:
    if x not in s:raise SystemExit('missing '+x)
if 'disabled-by-default' not in s:raise SystemExit('IL2CPP enrichment must stay opt-in')
print('v0.3.5 descriptor-less action fallback + conflict audit applied')
