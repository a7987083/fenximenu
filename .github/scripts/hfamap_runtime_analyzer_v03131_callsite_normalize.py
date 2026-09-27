from pathlib import Path
import re

P=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=P.read_text()
pat=re.compile(r'HFAAnalyzerV02ScanSelectedImage\s*\(\s*\)')
matches=list(pat.finditer(s))
if len(matches)!=2:
    for i,m in enumerate(matches):
        a=max(0,m.start()-180);b=min(len(s),m.end()+220)
        print(f'CALLSITE[{i}] >>>{s[a:b]}<<<')
    raise SystemExit(f'v03131 expected exactly two pre-hotfix analyzer calls, got {len(matches)}')
# Normalize the later call expression regardless of whitespace added by earlier generators.
second=matches[1]
s=s[:second.start()]+'HFAAnalyzerV02ScanSelectedImage()'+s[second.end():]
# Normalize the legacy ownership-finalize assignment/log when present. This does
# not change behavior; it only makes the subsequent hotfix independent of prior
# formatting/minification.
s,n1=re.subn(r'unsigned\s+v02Native\s*=\s*HFAAnalyzerV02ScanSelectedImage\s*\(\s*\)\s*;',
             'unsigned v02Native=HFAAnalyzerV02ScanSelectedImage();',s,count=1)
s,n2=re.subn(r'HFALog\("\[V02-OWNERSHIP-FINALIZE\][^;]*;',
             'HFALog("[V02-OWNERSHIP-FINALIZE] nativeCandidates=%u\\n",v02Native);',s,count=1)
if n1!=1 or n2!=1:
    for i,m in enumerate(pat.finditer(s)):
        a=max(0,m.start()-180);b=min(len(s),m.end()+220)
        print(f'NORMALIZED-CALLSITE[{i}] >>>{s[a:b]}<<<')
    raise SystemExit(f'v03131 legacy callsite normalize failed assignment={n1} log={n2}')
P.write_text(s)
print('v0.3.13.1 legacy analyzer callsite normalized')
