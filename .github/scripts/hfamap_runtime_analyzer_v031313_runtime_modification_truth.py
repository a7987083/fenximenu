from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
MAKEFILE=Path('hfamap/Makefile')
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

s=TRACE.read_text()
if '#import "HFAMapRuntimeModificationTruth.h"' not in s:
    first=s.find('#import ')
    if first<0: raise SystemExit('trace import anchor missing')
    line_end=s.find('\n',first)
    s=s[:line_end+1]+'#import "HFAMapRuntimeModificationTruth.h"\n'+s[line_end+1:]

a,b=function_span(s,'static void HFA0312WriteAudit(NSArray *ledger,NSArray *featureDispositions,NSArray *conflicts,NSArray *features,NSDictionary *targets,NSString *packageStatus,NSString *rootPath,NSString *mirrorPath)')
fn=s[a:b]
anchor='NSError *err=nil;'
if anchor not in fn: raise SystemExit('audit NSError anchor missing')
inject=r'''NSDictionary *runtimeTruth=HFARuntimeModificationTruthBuild(ledger?:@[],dir);
    if([runtimeTruth isKindOfClass:[NSDictionary class]]){
        NSMutableDictionary *truthRoot=[root mutableCopy];truthRoot[@"runtimeModificationTruth"]=runtimeTruth;root=truthRoot;
        NSString *truthPath=[dir stringByAppendingPathComponent:@"HFAMap_RuntimeModificationTruth_v031313.json"];
        NSError *truthErr=nil;NSData *truthJSON=[NSJSONSerialization dataWithJSONObject:runtimeTruth options:NSJSONWritingPrettyPrinted error:&truthErr];
        if(truthJSON&&[truthJSON writeToFile:truthPath options:NSDataWritingAtomic error:&truthErr])HFALog("[V031313-TRUTH-FILE] path=%s menu=%u startup=%u effective=%u\\n",truthPath.UTF8String,[runtimeTruth[@"menuFeatureCount"] unsignedIntValue],[runtimeTruth[@"startupFeatureCount"] unsignedIntValue],[runtimeTruth[@"effectiveFeatureCount"] unsignedIntValue]);
        else HFALog("[V031313-TRUTH-FILE] status=fail reason=%s\\n",truthErr.localizedDescription.UTF8String?:"json");
    }
    '''
fn=fn.replace(anchor,inject+anchor,1)
s=s[:a]+fn+s[b:]
TRACE.write_text(s)

m=MAKEFILE.read_text()
needle='src/HFAMapCrossImageResolver.m'
if 'src/HFAMapRuntimeModificationTruth.m' not in m:
    if needle not in m: raise SystemExit('Makefile cross-image anchor missing')
    m=m.replace(needle,'src/HFAMapRuntimeModificationTruth.m '+needle,1)
MAKEFILE.write_text(m)

u=UI.read_text()
u=u.replace('HFAMap RuntimeAnalyzer v0.3.13.12 CrossImageCallResolver','HFAMap RuntimeAnalyzer v0.3.13.13 RuntimeModificationTruthResolver')
UI.write_text(u)

for token in ['[V031313-TRUTH-FILE]','HFARuntimeModificationTruthBuild','runtimeModificationTruth']:
    if token not in TRACE.read_text(): raise SystemExit('missing trace token '+token)
if 'src/HFAMapRuntimeModificationTruth.m' not in MAKEFILE.read_text(): raise SystemExit('truth source missing from Makefile')
if 'v0.3.13.13 RuntimeModificationTruthResolver' not in UI.read_text(): raise SystemExit('UI marker missing')
print('v0.3.13.13 runtime modification truth integration applied')
