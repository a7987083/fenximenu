#!/usr/bin/env python3
import argparse, json, re, subprocess, sys
from pathlib import Path

CROSS_RE=re.compile(r'\[V031312-CROSSIMAGE\]\s+from=([^\s]+)\s+to=([^\s]+)')
RET_RE=re.compile(r'\[V031310-RETURN\].*?depth=(\d+)')
DER_RE=re.compile(r'\[V031310-DERIVED\].*?depth=(\d+)')
BOOT_RE=re.compile(r'\[V0342-BOOT-01\]')
END_MARKERS=('FAMILY-RESOLVE-END','FAMILY-EXECUTE-END','FULL-SCAN-END','V031313-TRUTH-SUMMARY')

def analyze_text(text):
    lines=text.splitlines(); cross=[]; depths=[]; max_off=0
    for line in lines:
        m=CROSS_RE.search(line)
        if m: cross.append((m.group(1),m.group(2)))
        m=RET_RE.search(line) or DER_RE.search(line)
        if m: depths.append(int(m.group(1)))
        for x in re.findall(r'\boff=0x([0-9A-Fa-f]+)',line): max_off=max(max_off,int(x,16))
    unique=list(dict.fromkeys(cross)); depth_over=sum(1 for d in depths if d>6); second_boot=max(0,len(BOOT_RE.findall(text))-1); ends={k:text.count(k) for k in END_MARKERS}
    return {'lineCount':len(lines),'crossCalls':len(cross),'crossUniquePairs':len(unique),'crossCacheHitsSimulated':max(0,len(cross)-len(unique)),'crossReductionPercent':round((1-len(unique)/len(cross))*100,2) if cross else 0,'taintEvents':len(depths),'depthOver6DroppedSimulated':depth_over,'maxObservedDepth':max(depths) if depths else 0,'maxObservedOffset':hex(max_off),'restartEvidence':second_boot,'completionMarkers':ends,'wouldFailSoft':second_boot>0 and not any(ends.values())}

def inspect_binary(path):
    p=Path(path)
    if not p.exists(): return {'present':False}
    out={'present':True,'size':p.stat().st_size,'path':str(p)}
    try: out['file']=subprocess.run(['file',str(p)],capture_output=True,text=True,check=False).stdout.strip()
    except Exception as e: out['fileError']=str(e)
    data=p.read_bytes()[:4]; out['magic']=data.hex(); out['machO64']=data in (bytes.fromhex('cffaedfe'),bytes.fromhex('feedfacf'))
    return out

def self_test():
    sample='''[V0342-BOOT-01]\n[V031312-CROSSIMAGE] from=A+0x10 to=B+0x20 hops=1 crossed=1\n[V031312-CROSSIMAGE] from=A+0x10 to=B+0x20 hops=1 crossed=1\n[V031310-RETURN] type=BL off=0x100 depth=7\n[V0342-BOOT-01]\n'''
    r=analyze_text(sample); assert r['crossCalls']==2 and r['crossUniquePairs']==1 and r['depthOver6DroppedSimulated']==1 and r['restartEvidence']==1
    print(json.dumps(r,indent=2)); return 0

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('logs',nargs='*'); ap.add_argument('--binary'); ap.add_argument('--self-test',action='store_true'); args=ap.parse_args()
    if args.self_test:return self_test()
    if not args.logs:ap.error('provide one or more HFAMap Learn.log files')
    report={'schema':'com.hfa.v031318-replay/v1','policy':{'depthCap':6,'crossImageMemoize':True,'failSoftBudgetMs':750},'logs':{}}
    for s in args.logs:
        p=Path(s); report['logs'][p.name]=analyze_text(p.read_text(errors='replace'))
    if args.binary: report['binary']=inspect_binary(args.binary)
    print(json.dumps(report,indent=2,ensure_ascii=False)); return 0
if __name__=='__main__':sys.exit(main())
