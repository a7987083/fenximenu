from pathlib import Path
import re

GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')
CROSS=Path('hfamap/src/HFAMapCrossImageResolver.m')
IL2CPP=Path('hfamap/src/HFAMapIL2CPPRuntimeResolver.m')
TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
TRUTH=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
UI=Path('hfamap/src/HFAMapCyberUI.m')


def function_span(text, signature):
    start=text.find(signature)
    if start<0: raise SystemExit('missing function: '+signature)
    brace=text.find('{',start)
    if brace<0: raise SystemExit('missing brace: '+signature)
    depth=0; instr=False; esc=False
    for i in range(brace,len(text)):
        ch=text[i]
        if instr:
            if esc: esc=False
            elif ch=='\\': esc=True
            elif ch=='"': instr=False
            continue
        if ch=='"': instr=True; continue
        if ch=='{': depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return start,i+1
    raise SystemExit('unterminated function: '+signature)

old='[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"]'
new='[NSHomeDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"Documents/HFAMap_%@_Learn.log",([[NSBundle mainBundle] bundleIdentifier]?:@"unknown")]]'
replaced=0
for p in Path('hfamap/src').glob('*.m'):
    s=p.read_text(); n=s.count(old)
    if n:
        s=s.replace(old,new); p.write_text(s); replaced+=n
if replaced<1: raise SystemExit('bundle-ID Learn.log path anchor missing')

c=CROSS.read_text()
anchor='static uint64_t gCrossBLRResolvedCount;\n'
if 'gCrossTargetCache' not in c:
    if anchor not in c: raise SystemExit('cross counter anchor missing')
    c=c.replace(anchor,anchor+'static NSMutableDictionary *gCrossTargetCache;\nstatic NSMutableDictionary *gCrossBLRCache;\nstatic uint64_t gCrossTargetCacheHitCount;\nstatic uint64_t gCrossBLRCacheHitCount;\nstatic uint64_t gCrossUniqueResolveCount;\nstatic uint64_t gCrossBLRUniqueResolveCount;\n',1)
needle='''NSDictionary *HFACrossImageResolveTarget(const void *target) {\n    gCrossResolveCount++;\n    uintptr_t original=(uintptr_t)target,cur=original;if(!cur)return nil;'''
repl='''NSDictionary *HFACrossImageResolveTarget(const void *target) {\n    gCrossResolveCount++;\n    uintptr_t original=(uintptr_t)target,cur=original;if(!cur)return nil;\n    if(!gCrossTargetCache)gCrossTargetCache=[[NSMutableDictionary alloc]init];\n    NSString *cacheKey=[NSString stringWithFormat:@"%llX",(unsigned long long)original];\n    @synchronized(gCrossTargetCache){id cached=[gCrossTargetCache objectForKey:cacheKey];if(cached){gCrossTargetCacheHitCount++;return cached==[NSNull null]?nil:cached;}}\n    gCrossUniqueResolveCount++;'''
if needle not in c: raise SystemExit('cross target entry anchor missing')
c=c.replace(needle,repl,1)
needle='''    if(cur==original||!hops.count)return nil;\n    gCrossResolvedCount++;\n    NSDictionary *oi=HFAXAddressInfo(original),*fi=HFAXAddressInfo(cur);\n    return @{ @"resolved":@YES,@"original":oi?:@{},@"final":fi?:@{},@"finalAddressValue":@(cur),@"hops":hops,@"hopCount":@(hops.count),@"crossImage":@(![[oi objectForKey:@"image"] isEqual:[fi objectForKey:@"image"]]) };\n}'''
repl='''    if(cur==original||!hops.count){@synchronized(gCrossTargetCache){[gCrossTargetCache setObject:[NSNull null] forKey:cacheKey];}return nil;}\n    gCrossResolvedCount++;\n    NSDictionary *oi=HFAXAddressInfo(original),*fi=HFAXAddressInfo(cur);\n    NSDictionary *result=@{ @"resolved":@YES,@"original":oi?:@{},@"final":fi?:@{},@"finalAddressValue":@(cur),@"hops":hops,@"hopCount":@(hops.count),@"crossImage":@(![[oi objectForKey:@"image"] isEqual:[fi objectForKey:@"image"]]) };\n    @synchronized(gCrossTargetCache){[gCrossTargetCache setObject:result forKey:cacheKey];}\n    return result;\n}'''
if needle not in c: raise SystemExit('cross target exit anchor missing')
c=c.replace(needle,repl,1)
needle='''NSDictionary *HFACrossImageResolveBLRCallsite(const void *functionStart,unsigned callsiteOffset,unsigned targetRegister) {\n    gCrossBLRResolveCount++;uintptr_t start=(uintptr_t)functionStart;if(!start||targetRegister>31)return nil;\n    NSDictionary *p=HFAXResolveBLRPattern(start,callsiteOffset,targetRegister);if(!p)return nil;'''
repl='''NSDictionary *HFACrossImageResolveBLRCallsite(const void *functionStart,unsigned callsiteOffset,unsigned targetRegister) {\n    gCrossBLRResolveCount++;uintptr_t start=(uintptr_t)functionStart;if(!start||targetRegister>31)return nil;\n    if(!gCrossBLRCache)gCrossBLRCache=[[NSMutableDictionary alloc]init];\n    NSString *cacheKey=[NSString stringWithFormat:@"%llX:%X:%u",(unsigned long long)start,callsiteOffset,targetRegister];\n    @synchronized(gCrossBLRCache){id cached=[gCrossBLRCache objectForKey:cacheKey];if(cached){gCrossBLRCacheHitCount++;return cached==[NSNull null]?nil:cached;}}\n    gCrossBLRUniqueResolveCount++;\n    NSDictionary *p=HFAXResolveBLRPattern(start,callsiteOffset,targetRegister);if(!p){@synchronized(gCrossBLRCache){[gCrossBLRCache setObject:[NSNull null] forKey:cacheKey];}return nil;}'''
if needle not in c: raise SystemExit('cross BLR entry anchor missing')
c=c.replace(needle,repl,1)
needle='''    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:p];out[@"resolved"]=@YES;out[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",callsiteOffset];out[@"targetRegister"]=@(targetRegister);out[@"rawTarget"]=HFAXAddressInfo(raw);out[@"final"]=HFAXAddressInfo(final);out[@"finalAddressValue"]=@(final);if(chain)out[@"trampoline"]=chain;\n    return out;\n}'''
repl='''    NSMutableDictionary *out=[NSMutableDictionary dictionaryWithDictionary:p];out[@"resolved"]=@YES;out[@"callsiteRVA"]=[NSString stringWithFormat:@"0x%X",callsiteOffset];out[@"targetRegister"]=@(targetRegister);out[@"rawTarget"]=HFAXAddressInfo(raw);out[@"final"]=HFAXAddressInfo(final);out[@"finalAddressValue"]=@(final);if(chain)out[@"trampoline"]=chain;\n    @synchronized(gCrossBLRCache){[gCrossBLRCache setObject:out forKey:cacheKey];}\n    return out;\n}'''
if needle not in c: raise SystemExit('cross BLR exit anchor missing')
c=c.replace(needle,repl,1)
needle='''return @{ @"resolveCount":@(gCrossResolveCount),@"resolvedCount":@(gCrossResolvedCount),@"blrResolveCount":@(gCrossBLRResolveCount),@"blrResolvedCount":@(gCrossBLRResolvedCount),@"analysisOnly":@YES };'''
repl='''return @{ @"resolveCount":@(gCrossResolveCount),@"uniqueResolveCount":@(gCrossUniqueResolveCount),@"cacheHitCount":@(gCrossTargetCacheHitCount),@"resolvedCount":@(gCrossResolvedCount),@"blrResolveCount":@(gCrossBLRResolveCount),@"blrUniqueResolveCount":@(gCrossBLRUniqueResolveCount),@"blrCacheHitCount":@(gCrossBLRCacheHitCount),@"blrResolvedCount":@(gCrossBLRResolvedCount),@"analysisOnly":@YES };'''
if needle not in c: raise SystemExit('cross status anchor missing')
c=c.replace(needle,repl,1); CROSS.write_text(c)

g=GENERIC.read_text()
if 'gHFA031318CrossLogSeen' not in g:
    globals_anchor='static unsigned gScanGeneration;\n'
    helper='''static NSMutableSet *gHFA031318CrossLogSeen;\nstatic BOOL HFA031318CrossLogOnce(uintptr_t address){\n    if(!address)return NO;if(!gHFA031318CrossLogSeen)gHFA031318CrossLogSeen=[[NSMutableSet alloc]init];\n    NSString *k=[NSString stringWithFormat:@"%llX",(unsigned long long)address];\n    @synchronized(gHFA031318CrossLogSeen){if([gHFA031318CrossLogSeen containsObject:k])return NO;[gHFA031318CrossLogSeen addObject:k];return YES;}\n}\n'''
    if globals_anchor not in g: raise SystemExit('generic globals anchor missing')
    g=g.replace(globals_anchor,globals_anchor+helper,1)
logneedle='HFAGenericLog("[V031312-CROSSIMAGE] from=%s+%s to=%s+%s hops=%lu crossed=%u\\n",'
if logneedle in g and 'HFA031318CrossLogOnce((uintptr_t)address)' not in g:
    g=g.replace(logneedle,'if(HFA031318CrossLogOnce((uintptr_t)address))HFAGenericLog("[V031312-CROSSIMAGE] from=%s+%s to=%s+%s hops=%lu crossed=%u\\n",',1)
a,b=function_span(g,'static NSDictionary *HFA03138SenderIdentifierDataflow(Method method, NSDictionary *discriminator)')
fn=g[a:b]
fn=fn.replace('if(size==3){uint8_t nd=(uint8_t)MIN((unsigned)derivedDepth[rn]+1u,15u);','if(size==3&&derivedDepth[rn]<6){uint8_t nd=(uint8_t)MIN((unsigned)derivedDepth[rn]+1u,6u);')
fn=fn.replace('if(hasTaintedArg){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,15u);tainted[0]=YES;','if(hasTaintedArg&&argDepth<6){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,6u);tainted[0]=YES;')
if '15u);tainted[0]=YES;' in fn:
    fn=fn.replace('if(hasTaintedArg){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,15u);tainted[0]=YES;','if(hasTaintedArg&&argDepth<6){uint8_t nd=(uint8_t)MIN((unsigned)argDepth+1u,6u);tainted[0]=YES;')
loop='for(unsigned off=0;off+4<=scanLimit;off+=4){'
if loop not in fn: raise SystemExit('dataflow loop anchor missing')
pre='BOOL hfa031318BudgetExceeded=NO;CFAbsoluteTime hfa031318Started=CFAbsoluteTimeGetCurrent();const CFTimeInterval hfa031318Budget=0.75;const uint8_t hfa031318DepthCap=6;'
fn=fn.replace(loop,pre+'\n    '+loop+'if((off&0x3FFu)==0&&CFAbsoluteTimeGetCurrent()-hfa031318Started>hfa031318Budget){hfa031318BudgetExceeded=YES;HFAGenericLog("[V031318-BUDGET] stage=sender-dataflow off=0x%X budgetMs=750 action=fail-soft\\n",off);break;}',1)
ret='@"objectReturnAware":@YES}'
if ret not in fn: raise SystemExit('dataflow return metadata anchor missing')
fn=fn.replace(ret,'@"objectReturnAware":@YES,@"budgetExceeded":@(hfa031318BudgetExceeded),@"budgetMs":@750,@"depthCap":@(hfa031318DepthCap)}',1)
g=g[:a]+fn+g[b:]; GENERIC.write_text(g)

u=UI.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.17 NativeEntrySemanticResolver','HFAMap RuntimeAnalyzer v0.3.13.18 AnalysisBudgetAndDedup'); UI.write_text(u)
for token in ['gCrossTargetCache','uniqueResolveCount','cacheHitCount','gCrossBLRCache','blrCacheHitCount']:
    if token not in CROSS.read_text(): raise SystemExit('cross token missing '+token)
for token in ['[V031318-BUDGET]','hfa031318DepthCap','HFA031318CrossLogOnce','@"budgetExceeded"']:
    if token not in GENERIC.read_text(): raise SystemExit('generic token missing '+token)
if 'HFAMap RuntimeAnalyzer v0.3.13.18 AnalysisBudgetAndDedup' not in UI.read_text(): raise SystemExit('v031318 UI marker missing')
for p in [GENERIC,CROSS,IL2CPP,TRACE,TRUTH]:
    if 'Documents/HFAMap_Learn.log' in p.read_text(): raise SystemExit('legacy Learn.log path remains in '+str(p))
print(f'v0.3.13.18 analysis budget/dedup applied; bundleLogPathReplacements={replaced}')
