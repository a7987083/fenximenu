from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
GENERIC=Path('hfamap/src/HFAMapGenericMenuResolver.m')

s=TRACE.read_text()
old='static int HFAFeatureLabelNumeric(const char *s)'
new='static __attribute__((unused)) int HFAFeatureLabelNumeric(const char *s)'
if old in s:
    s=s.replace(old,new,1)
TRACE.write_text(s)

g=GENERIC.read_text()
proto='static NSString *HFASafeStringGetter(id object, const char *selectorName);\n'
anchor='static BOOL HFA03135StringIsNumeric(NSString *s)'
if anchor in g and proto not in g[:g.find(anchor)+1]:
    g=g.replace(anchor,proto+anchor,1)
GENERIC.write_text(g)
print('v0.3.13.5 compile fix applied')
