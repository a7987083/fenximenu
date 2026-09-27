from pathlib import Path

P=Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s=P.read_text()
fixes={
    'static NSArray *HFAV039StateXrefCandidates(':'static __attribute__((unused)) NSArray *HFAV039StateXrefCandidates(',
    'static NSDictionary *HFAV0310ConsumerGraph(':'static __attribute__((unused)) NSDictionary *HFAV0310ConsumerGraph(',
}
for old,new in fixes.items():
    if new in s: continue
    if old not in s: raise SystemExit('v0311 compile-fix anchor missing: '+old)
    s=s.replace(old,new,1)
P.write_text(s)
print('v0.3.11 superseded helper compile markers applied')
