from pathlib import Path
import re

P=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=P.read_text()
call='HFAAnalyzerV02ScanSelectedImage();'
pos=[m.start() for m in re.finditer(re.escape(call),s)]
if len(pos)!=2:
    raise SystemExit(f'v03131 expected exactly two pre-hotfix analyzer calls, got {len(pos)}')
# Normalize only the legacy v0.2 ownership-finalize assignment and log so the
# hotfix remains independent of whitespace/minification changes in earlier generators.
s,n1=re.subn(r'unsigned\s+v02Native\s*=\s*HFAAnalyzerV02ScanSelectedImage\(\);',
             'unsigned v02Native=HFAAnalyzerV02ScanSelectedImage();',s,count=1)
s,n2=re.subn(r'HFALog\("\[V02-OWNERSHIP-FINALIZE\][^;]*;',
             'HFALog("[V02-OWNERSHIP-FINALIZE] nativeCandidates=%u\\n",v02Native);',s,count=1)
if n1!=1 or n2!=1:
    raise SystemExit(f'v03131 legacy callsite normalize failed assignment={n1} log={n2}')
P.write_text(s)
print('v0.3.13.1 legacy analyzer callsite normalized')
