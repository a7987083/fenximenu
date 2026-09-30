from pathlib import Path

HDR=Path('hfamap/src/HFAMapIL2CPPRuntimeResolver.h')
IMPL=Path('hfamap/src/HFAMapIL2CPPRuntimeResolver.m')
TRUTH=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')

h=HDR.read_text()
needle='FOUNDATION_EXPORT NSDictionary * _Nullable HFAIL2CPPResolveNativeAddress(const void *address);\n'
if needle not in h: raise SystemExit('IL2CPP header native resolver anchor missing')
if 'HFAIL2CPPResolveContainingAddress' not in h:
    h=h.replace(needle,needle+'FOUNDATION_EXPORT NSDictionary * _Nullable HFAIL2CPPResolveContainingAddress(const void *address);\n',1)
HDR.write_text(h)

m=IMPL.read_text()
if 'gContainCache' not in m:
    anchor='static NSMutableDictionary *gCache;\n'
    if anchor not in m: raise SystemExit('IL2CPP cache declaration anchor missing')
    m=m.replace(anchor,anchor+'static NSMutableDictionary *gContainCache;\nstatic NSUInteger gContainResolveCount;\nstatic NSUInteger gContainHitCount;\nstatic NSUInteger gContainCandidateCount;\nstatic NSUInteger gContainBudgetMissCount;\n',1)

old='''if(!gCache)gCache=[[NSMutableDictionary alloc]init]; else [gCache removeAllObjects];'''
new='''if(!gCache)gCache=[[NSMutableDictionary alloc]init]; else [gCache removeAllObjects];\n        if(!gContainCache)gContainCache=[[NSMutableDictionary alloc]init]; else [gContainCache removeAllObjects];'''
if old not in m: raise SystemExit('IL2CPP refresh cache anchor missing')
m=m.replace(old,new,1)

old='''return @{ @"available":@(gReady), @"unityPath":gUnityPath?:@"", @"unityBase":[NSString stringWithFormat:@"0x%llX",(unsigned long long)gUnityBase], @"methodPointerAPI":@(gMethodGetPointer!=NULL), @"lastError":gLastError?:@"", @"resolveCount":@(gResolveCount), @"hitCount":@(gHitCount), @"budgetMissCount":@(gBudgetMissCount) };'''
new='''return @{ @"available":@(gReady), @"unityPath":gUnityPath?:@"", @"unityBase":[NSString stringWithFormat:@"0x%llX",(unsigned long long)gUnityBase], @"methodPointerAPI":@(gMethodGetPointer!=NULL), @"lastError":gLastError?:@"", @"resolveCount":@(gResolveCount), @"hitCount":@(gHitCount), @"budgetMissCount":@(gBudgetMissCount), @"containmentResolveCount":@(gContainResolveCount), @"containmentHitCount":@(gContainHitCount), @"containmentCandidateCount":@(gContainCandidateCount), @"containmentBudgetMissCount":@(gContainBudgetMissCount) };'''
if old not in m: raise SystemExit('IL2CPP status anchor missing')
m=m.replace(old,new,1)

if 'NSDictionary *HFAIL2CPPResolveContainingAddress' not in m:
    m += r'''

NSDictionary *HFAIL2CPPResolveContainingAddress(const void *address){
    HFAEnsureReady(); uintptr_t target=(uintptr_t)address; if(!gReady||!HFAExecutableUnityAddress(target))return nil;
    NSString *key=[NSString stringWithFormat:@"%llX",(unsigned long long)target];
    @synchronized(gContainCache){ id cached=[gContainCache objectForKey:key]; if(cached)return cached==[NSNull null]?nil:cached; }
    gContainResolveCount++;
    CFAbsoluteTime started=CFAbsoluteTimeGetCurrent(); const CFTimeInterval budget=0.75; NSUInteger visited=0;
    uintptr_t best=0,next=UINTPTR_MAX; NSString *bestAssembly=nil,*bestNS=nil,*bestClass=nil,*bestMethod=nil,*bestSource=nil; NSInteger bestArgc=-1; const void *bestMethodInfo=NULL;
    void *domain=gDomainGet(); if(!domain)return nil; size_t ac=0; const void **assemblies=gDomainGetAssemblies(domain,&ac); if(!assemblies)return nil;
    for(size_t a=0;a<ac;a++){
        const void *image=gAssemblyGetImage(assemblies[a]); if(!image)continue; NSString *assembly=HFAString(gImageGetName(image)); size_t cc=gImageGetClassCount(image);
        for(size_t c=0;c<cc;c++){
            if((visited&0x3FF)==0 && CFAbsoluteTimeGetCurrent()-started>budget){
                gContainBudgetMissCount++; NSDictionary *miss=@{ @"attempted":@YES,@"resolved":@NO,@"candidateOnly":@YES,@"resolutionMode":@"containment",@"reason":@"budget",@"visitedMethods":@(visited) };
                @synchronized(gContainCache){[gContainCache setObject:miss forKey:key];}
                HFALog("[V031315-IL2CPP-CONTAINMENT] address=0x%llX resolved=0 reason=budget methods=%lu\n",(unsigned long long)target,(unsigned long)visited); return miss;
            }
            void *klass=gImageGetClass(image,c); if(!klass)continue; NSString *cn=HFAString(gClassGetName(klass)),*ns=HFAString(gClassGetNamespace(klass)); void *it=NULL; const void *method=NULL;
            while((method=gClassGetMethods(klass,&it))!=NULL){
                visited++; NSString *src=nil; uintptr_t p=HFAMethodPointer(method,&src); if(!p)continue;
                if(p<=target && p>=best){
                    if(p>best || !bestMethodInfo){ best=p; bestAssembly=assembly; bestNS=ns; bestClass=cn; bestMethod=HFAString(gMethodGetName(method)); bestArgc=gMethodGetParamCount?(NSInteger)gMethodGetParamCount(method):-1; bestSource=src; bestMethodInfo=method; }
                } else if(p>target && p<next) next=p;
            }
        }
    }
    if(!best){ @synchronized(gContainCache){[gContainCache setObject:[NSNull null] forKey:key];} HFALog("[V031315-IL2CPP-CONTAINMENT] address=0x%llX resolved=0 reason=no-lower-method methods=%lu\n",(unsigned long long)target,(unsigned long)visited); return nil; }
    uint64_t delta=(uint64_t)(target-best); BOOL bounded=(next!=UINTPTR_MAX && target<next); uint64_t span=bounded?(uint64_t)(next-best):0;
    const uint64_t hardLimit=0x10000; BOOL accepted=bounded && delta<=hardLimit; NSString *confidence=@"candidate";
    if(accepted){ if(delta<=0x800)confidence=@"high"; else if(delta<=0x4000)confidence=@"medium"; else confidence=@"guarded"; }
    NSString *classPath=bestNS.length?[NSString stringWithFormat:@"%@.%@",bestNS,bestClass]:bestClass; uint64_t methodRVA=gUnityBase&&best>=gUnityBase?(uint64_t)(best-gUnityBase):0;
    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:@{ @"attempted":@YES,@"resolved":@(accepted),@"candidateOnly":@(!accepted),@"resolutionMode":@"containment",@"exactPointerMatch":@NO,@"containmentMatch":@(accepted),@"assembly":bestAssembly?:@"",@"namespace":bestNS?:@"",@"class":bestClass?:@"",@"method":bestMethod?:@"",@"argumentCount":@(bestArgc),@"methodInfo":[NSString stringWithFormat:@"0x%llX",(unsigned long long)(uintptr_t)bestMethodInfo],@"methodPointer":[NSString stringWithFormat:@"0x%llX",(unsigned long long)best],@"methodStart":[NSString stringWithFormat:@"0x%llX",(unsigned long long)best],@"methodStartRVA":[NSString stringWithFormat:@"0x%llX",(unsigned long long)methodRVA],@"offsetInMethod":[NSString stringWithFormat:@"0x%llX",(unsigned long long)delta],@"offsetInMethodValue":@(delta),@"boundedByNextMethod":@(bounded),@"confidence":confidence,@"pointerSource":bestSource?:@"unavailable",@"canonical":[NSString stringWithFormat:@"%@!%@::%@/%ld",bestAssembly?:@"?",classPath?:@"?",bestMethod?:@"?",(long)bestArgc],@"visitedMethods":@(visited) }];
    if(bounded){ out[@"nextMethodStart"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)next]; out[@"methodSpanUpperBound"]=[NSString stringWithFormat:@"0x%llX",(unsigned long long)span]; }
    if(accepted)gContainHitCount++; else gContainCandidateCount++;
    @synchronized(gContainCache){[gContainCache setObject:out forKey:key];}
    HFALog("[V031315-IL2CPP-CONTAINMENT] address=0x%llX resolved=%u methodStart=0x%llX delta=0x%llX bounded=%u next=0x%llX confidence=%s canonical=%s\n",(unsigned long long)target,accepted?1:0,(unsigned long long)best,(unsigned long long)delta,bounded?1:0,(unsigned long long)(bounded?next:0),[confidence UTF8String]?:"?",[[out objectForKey:@"canonical"] UTF8String]?:"?");
    return out;
}
'''
IMPL.write_text(m)

s=TRUTH.read_text()
old='''static NSDictionary *HFATIL2CPPSemantic(uintptr_t address){\n    if(!address)return @{ @"attempted":@NO,@"resolved":@NO };\n    NSDictionary *hit=HFAIL2CPPResolveNativeAddress((const void *)address);\n    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:hit?:@{}];\n    out[@"attempted"]=@YES;out[@"resolved"]=@([hit[@"resolved"] boolValue]);\n    return out;\n}\n'''
new='''static NSDictionary *HFATIL2CPPSemantic(uintptr_t address){\n    if(!address)return @{ @"attempted":@NO,@"resolved":@NO };\n    NSDictionary *hit=HFAIL2CPPResolveNativeAddress((const void *)address);\n    if([hit[@"resolved"] boolValue]){NSMutableDictionary *exact=[NSMutableDictionary dictionaryWithDictionary:hit];exact[@"attempted"]=@YES;exact[@"resolved"]=@YES;exact[@"resolutionMode"]=@"exact";exact[@"candidateOnly"]=@NO;return exact;}\n    NSDictionary *contain=HFAIL2CPPResolveContainingAddress((const void *)address);\n    if(contain){NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:contain];out[@"attempted"]=@YES;return out;}\n    return @{ @"attempted":@YES,@"resolved":@NO,@"candidateOnly":@YES,@"resolutionMode":@"none" };\n}\n'''
if old not in s: raise SystemExit('v031314 semantic helper anchor missing')
s=s.replace(old,new,1)
s=s.replace('com.hfa.runtime-modification-truth/v0.3.13.14','com.hfa.runtime-modification-truth/v0.3.13.15')
s=s.replace('[V031314-IL2CPP-TARGET]','[V031315-IL2CPP-TARGET]')
TRUTH.write_text(s)

t=TRACE.read_text()
t=t.replace('HFAMap_RuntimeModificationTruth_v031314.json','HFAMap_RuntimeModificationTruth_v031315.json')
t=t.replace('[V031314-TRUTH-FILE]','[V031315-TRUTH-FILE]')
t=t.replace('[V031314-TRUTH-SUMMARY]','[V031315-TRUTH-SUMMARY]')
t=t.replace('[V031314-MOD-SEMANTIC]','[V031315-MOD-SEMANTIC]')
# Enrich semantic log records with containment-specific fields while preserving compatibility.
t=t.replace('resolved=%u canonical=%s\\n",[[h[@"backendId"] description] UTF8String]?:"?",[[h[@"targetImage"] description] UTF8String]?:"?",[[h[@"targetRVA"] description] UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[[sem[@"canonical"] description] UTF8String]?:"")',
'''resolved=%u mode=%s offsetInMethod=%s confidence=%s canonical=%s\\n",[[h[@"backendId"] description] UTF8String]?:"?",[[h[@"targetImage"] description] UTF8String]?:"?",[[h[@"targetRVA"] description] UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[[sem[@"resolutionMode"] description] UTF8String]?:"?",[[sem[@"offsetInMethod"] description] UTF8String]?:"0x0",[[sem[@"confidence"] description] UTF8String]?:"exact",[[sem[@"canonical"] description] UTF8String]?:"")''')
t=t.replace('resolved=%u canonical=%s\\n",[[p[@"analyzerBackendId"] description] UTF8String]?:"?",[[p[@"targetImage"] description] UTF8String]?:"?",[[p[@"targetRVA"] description] UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[[sem[@"canonical"] description] UTF8String]?:"")',
'''resolved=%u mode=%s offsetInMethod=%s confidence=%s canonical=%s\\n",[[p[@"analyzerBackendId"] description] UTF8String]?:"?",[[p[@"targetImage"] description] UTF8String]?:"?",[[p[@"targetRVA"] description] UTF8String]?:"?",[sem[@"resolved"] boolValue]?1:0,[[sem[@"resolutionMode"] description] UTF8String]?:"?",[[sem[@"offsetInMethod"] description] UTF8String]?:"0x0",[[sem[@"confidence"] description] UTF8String]?:"exact",[[sem[@"canonical"] description] UTF8String]?:"")''')
TRACE.write_text(t)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.14 ModificationSemanticResolver','HFAMap RuntimeAnalyzer v0.3.13.15 MethodContainmentResolver')
UI.write_text(u)

for token in ['HFAIL2CPPResolveContainingAddress','containmentResolveCount','[V031315-IL2CPP-CONTAINMENT]','offsetInMethod','boundedByNextMethod','candidateOnly','confidence']:
    if token not in HDR.read_text()+IMPL.read_text(): raise SystemExit('v031315 resolver token missing '+token)
for token in ['HFAIL2CPPResolveContainingAddress','[V031315-IL2CPP-TARGET]','v0.3.13.15']:
    if token not in TRUTH.read_text(): raise SystemExit('v031315 truth token missing '+token)
for token in ['[V031315-TRUTH-SUMMARY]','[V031315-MOD-SEMANTIC]','[V031315-TRUTH-FILE]','HFAMap_RuntimeModificationTruth_v031315.json']:
    if token not in TRACE.read_text(): raise SystemExit('v031315 trace token missing '+token)
if 'v0.3.13.15 MethodContainmentResolver' not in UI.read_text(): raise SystemExit('v031315 UI marker missing')
print('v0.3.13.15 method containment resolver applied')
