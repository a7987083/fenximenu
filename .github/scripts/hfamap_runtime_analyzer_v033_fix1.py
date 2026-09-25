from pathlib import Path
import re

SRC = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s = SRC.read_text()

# v0.3.2 generator history can leave either v0.3.2 or v0.3.2.2 in the root
# schema. Normalize only the RuntimeAnalyzer root and require exactly one hit.
pat = re.compile(r'@"schema"\s*:\s*@"com\.hfa\.runtime-analyzer/v0\.3\.2(?:\.2)?"')
replacement = '@"schema":@"com.hfa.runtime-analyzer/v0.3.3",@"structuralParity":@YES,@"decryptSource":decryptSource'
s, count = pat.subn(replacement, s, count=1)
if count != 1:
    raise SystemExit(f'v033 schema normalization expected 1 hit, got {count}')
if 'HFAV033StaticDecryptFingerprint' not in s or 'decryptStatus' not in s:
    raise SystemExit('v033 structural parity implementation missing before schema fix')
if '@"structuralParity":@YES' not in s:
    raise SystemExit('v033 structural parity marker missing after schema fix')
SRC.write_text(s)
print('v0.3.3 fix1: runtime analyzer schema normalized')
