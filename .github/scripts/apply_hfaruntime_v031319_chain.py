from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
S=ROOT/'.github'/'scripts'
subprocess.check_call(['python3',str(S/'apply_hfaruntime_v031318_chain.py')],cwd=ROOT)

src=ROOT/'hfamap'/'src'/'HFAMapRuntimeTargetDecrypt.m'
hdr=ROOT/'hfamap'/'src'/'HFAMapRuntimeTargetDecrypt.h'
if not src.exists() or not hdr.exists():
    raise SystemExit('v031319 runtime-target source files missing')

make=ROOT/'hfamap'/'Makefile'
m=make.read_text()
if 'src/HFAMapRuntimeTargetDecrypt.m' not in m:
    line=next((x for x in m.splitlines() if x.startswith('HFAMapUniversal_FILES =')),None)
    if not line: raise SystemExit('Makefile source-list anchor missing')
    m=m.replace(line,line+' src/HFAMapRuntimeTargetDecrypt.m',1)
make.write_text(m)

generic=ROOT/'hfamap'/'src'/'HFAMapGenericMenuResolver.m'
g=generic.read_text()
if 'HFARuntimeTargetDecryptScan' not in g:
    marker='void HFAGenericMenuRescan(void) {'
    if marker not in g: raise SystemExit('generic rescan anchor missing')
    g=g.replace(marker,'extern void HFARuntimeTargetDecryptScan(void);\n\n'+marker,1)
    old='''        HFAArchitectureScan();\n        HFAClassRegistryScan();\n        HFAGenericLog("[GENERIC-SCAN-END] generation=%u\\n", gScanGeneration);'''
    new='''        HFAArchitectureScan();\n        HFAClassRegistryScan();\n        HFARuntimeTargetDecryptScan();\n        HFAGenericLog("[GENERIC-SCAN-END] generation=%u\\n", gScanGeneration);'''
    if old not in g: raise SystemExit('generic scan-body anchor missing')
    g=g.replace(old,new,1)
generic.write_text(g)

ui=ROOT/'hfamap'/'src'/'HFAMapCyberUI.m'
u=ui.read_text().replace('HFAMap RuntimeAnalyzer v0.3.13.18 AnalysisBudgetAndDedup','HFAMap RuntimeAnalyzer v0.3.13.19 RuntimeTargetDecrypt')
ui.write_text(u)

for token in ['runtime-target-backend','scratchCopyDecrypt','runtime-decrypted-unique-exec-range','D105C3FF']:
    if token not in src.read_text(): raise SystemExit('v031319 source token missing '+token)
if 'HFARuntimeTargetDecryptScan();' not in generic.read_text(): raise SystemExit('v031319 scan integration missing')
if 'src/HFAMapRuntimeTargetDecrypt.m' not in make.read_text(): raise SystemExit('v031319 Makefile integration missing')
if 'v0.3.13.19 RuntimeTargetDecrypt' not in ui.read_text(): raise SystemExit('v031319 UI marker missing')
print('v0.3.13.19 generator chain complete')