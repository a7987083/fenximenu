from pathlib import Path

runtime=Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s=runtime.read_text()
fixes={
    'static NSArray *HFAV039StateXrefCandidates(':'static __attribute__((unused)) NSArray *HFAV039StateXrefCandidates(',
    'static NSDictionary *HFAV0310ConsumerGraph(':'static __attribute__((unused)) NSDictionary *HFAV0310ConsumerGraph(',
}
for old,new in fixes.items():
    if new in s: continue
    if old not in s: raise SystemExit('v0311 compile-fix anchor missing: '+old)
    s=s.replace(old,new,1)
runtime.write_text(s)

dispatch=Path('hfamap/src/HFAMap5MDispatcherResolver.m')
d=dispatch.read_text()
old='static NSDictionary *HFA0310ResolveNearbyBlockInvoke('
new='static __attribute__((unused)) NSDictionary *HFA0310ResolveNearbyBlockInvoke('
if new not in d:
    if old not in d: raise SystemExit('v0311 dispatcher compile-fix anchor missing')
    d=d.replace(old,new,1)
dispatch.write_text(d)
print('v0.3.11 superseded helper compile markers applied')
