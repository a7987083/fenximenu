from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
V02=Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
trace=TRACE.read_text(); v=V02.read_text()


def function_span(text,name):
    needle=name+'('
    pos=0
    while True:
        i=text.find(needle,pos)
        if i<0: raise SystemExit(f'missing function {name}')
        start=text.rfind('\n',0,i)+1
        brace=text.find('{',i); semi=text.find(';',i)
        if brace>=0 and (semi<0 or brace<semi):
            depth=0; instr=False; esc=False
            for j in range(brace,len(text)):
                ch=text[j]
                if instr:
                    if esc: esc=False
                    elif ch=='\\': esc=True
                    elif ch=='"': instr=False
                    continue
                if ch=='"': instr=True; continue
                if ch=='{': depth+=1
                elif ch=='}':
                    depth-=1
                    if depth==0:return start,j+1
        pos=i+len(needle)

if 'HFAAnalyzerV02BeginExportEpoch' in v:
    raise SystemExit('v03131 epoch guard already present')
a,b=function_span(v,'HFAAnalyzerV02ScanSelectedImage')
orig=v[a:b]
old_sig='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
if old_sig not in orig: raise SystemExit('v03131 analyzer signature changed')
impl=orig.replace(old_sig,'static unsigned HFAAnalyzerV02ScanSelectedImageImpl(void)',1)
wrapped=r'''static unsigned gHFAV03131ExportEpoch=0;
static unsigned gHFAV03131AnalyzerEpoch=UINT_MAX;
static unsigned gHFAV03131AnalyzerResult=0;

void HFAAnalyzerV02BeginExportEpoch(void){
    gHFAV03131ExportEpoch++;
    if(gHFAV03131ExportEpoch==UINT_MAX)gHFAV03131ExportEpoch=1;
    HFAV02Log([NSString stringWithFormat:@"[V03131-ANALYZER-GUARD] action=begin epoch=%u",gHFAV03131ExportEpoch]);
}

'''+impl+r'''

unsigned HFAAnalyzerV02ScanSelectedImage(void){
    if(gHFAV03131AnalyzerEpoch==gHFAV03131ExportEpoch){
        HFAV02Log([NSString stringWithFormat:@"[V03131-ANALYZER-GUARD] action=reuse epoch=%u result=%u",gHFAV03131ExportEpoch,gHFAV03131AnalyzerResult]);
        return gHFAV03131AnalyzerResult;
    }
    gHFAV03131AnalyzerEpoch=gHFAV03131ExportEpoch;
    HFAV02Log([NSString stringWithFormat:@"[V03131-ANALYZER-GUARD] action=run epoch=%u",gHFAV03131ExportEpoch]);
    gHFAV03131AnalyzerResult=HFAAnalyzerV02ScanSelectedImageImpl();
    return gHFAV03131AnalyzerResult;
}'''
v=v[:a]+wrapped+v[b:]
V02.write_text(v)

if 'extern void HFAAnalyzerV02BeginExportEpoch(void);' not in trace:
    anchor='extern unsigned HFAAnalyzerV02ScanSelectedImage(void);'
    if anchor not in trace: raise SystemExit('v03131 analyzer extern anchor missing')
    trace=trace.replace(anchor,anchor+'\nextern void HFAAnalyzerV02BeginExportEpoch(void);',1)
prepass='unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();'
if prepass not in trace: raise SystemExit('v03131 prepass anchor missing')
trace=trace.replace(prepass,'HFAAnalyzerV02BeginExportEpoch();unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();',1)
TRACE.write_text(trace)

out=V02.read_text(); tout=TRACE.read_text()
for req in ['HFAAnalyzerV02ScanSelectedImageImpl','HFAAnalyzerV02BeginExportEpoch','[V03131-ANALYZER-GUARD] action=run','[V03131-ANALYZER-GUARD] action=reuse']:
    if req not in out: raise SystemExit('v03131 epoch guard missing '+req)
if 'HFAAnalyzerV02BeginExportEpoch();unsigned analyzerNative=HFAAnalyzerV02ScanSelectedImage();' not in tout:
    raise SystemExit('v03131 epoch reset not attached to canonical prepass')
print('v0.3.13.1 per-export analyzer epoch guard applied')
