from pathlib import Path
import re

P=Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s=P.read_text()
start=s.find('static NSDictionary *HFAV038EvidenceSnapshot')
scan_token='unsigned HFAAnalyzerV02ScanSelectedImage(void)'
if start<0 or scan_token not in s: raise SystemExit('v038 compile-fix anchors missing')

# The first v0.3.8 generator captured scan position before adding an extern at
# the file prefix. If that stale offset placed the helper block inside the
# preceding branchBinding token, move the complete helper region to the actual
# scan entry and repair only that token boundary.
def fn_end(text,name,start_at=0):
    i=text.find(name,start_at)
    if i<0: raise SystemExit(name+' missing')
    b=text.find('{',i);depth=0;ins=False;esc=False
    for j in range(b,len(text)):
        ch=text[j]
        if ins:
            if esc:esc=False
            elif ch=='\\':esc=True
            elif ch=='"':ins=False
            continue
        if ch=='"':ins=True;continue
        if ch=='{':depth+=1
        elif ch=='}':
            depth-=1
            if depth==0:return j+1
    raise SystemExit(name+' unterminated')

end=fn_end(s,'static NSArray *HFAV038BranchOutcomeBindings',start)
helper=s[start:end]
s=s[:start]+s[end:]
s,n=re.subn(r'branchBindi\s*ng','branchBinding',s,count=1)
if n!=1 and 'branchBinding' not in s: raise SystemExit('branchBinding repair failed')
scan=s.find(scan_token)
if scan<0: raise SystemExit('actual scan entry missing after repair')
s=s[:scan]+helper+'\n'+s[scan:]
if s.count('static NSDictionary *HFAV038EvidenceSnapshot')!=1: raise SystemExit('v038 helper duplication')
if re.search(r'branchBindi\s+ng',s): raise SystemExit('split branchBinding remains')
P.write_text(s)
print('v0.3.8 generated helper insertion repaired after prefix mutation')
