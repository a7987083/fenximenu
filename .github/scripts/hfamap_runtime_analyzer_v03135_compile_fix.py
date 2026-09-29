from pathlib import Path

TRACE=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=TRACE.read_text()
old='static int HFAFeatureLabelNumeric(const char *s)'
new='static __attribute__((unused)) int HFAFeatureLabelNumeric(const char *s)'
if old in s:
    s=s.replace(old,new,1)
TRACE.write_text(s)
print('v0.3.13.5 compile fix applied')
