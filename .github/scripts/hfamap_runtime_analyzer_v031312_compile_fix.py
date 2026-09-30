from pathlib import Path

P=Path('hfamap/src/HFAMapCrossImageResolver.m')
s=P.read_text()
sig='static BOOL HFAXDecodeADR(uint32_t ins,uintptr_t pc,unsigned *rdOut,uintptr_t *valueOut)'
start=s.find(sig)
if start<0:
    raise SystemExit('HFAXDecodeADR anchor missing')
brace=s.find('{',start)
if brace<0:
    raise SystemExit('HFAXDecodeADR brace missing')
depth=0
end=None
for i in range(brace,len(s)):
    if s[i]=='{': depth+=1
    elif s[i]=='}':
        depth-=1
        if depth==0:
            end=i+1
            break
if end is None:
    raise SystemExit('HFAXDecodeADR unterminated')
s=s[:start]+s[end:]
P.write_text(s)
print('v0.3.13.12 compile fix: removed unused ADR decoder')
