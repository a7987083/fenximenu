from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
MAKE=ROOT/'hfamap'/'Makefile'
UI=ROOT/'hfamap'/'src'/'HFAMapCyberUI.m'

m=MAKE.read_text()
src='src/HFAMapC4M0ConfigOwnerResolver.m'
if src not in m:
    needle='HFAMapUniversal_FILES = '
    i=m.find(needle)
    if i<0: raise SystemExit('Makefile source anchor missing')
    e=m.find('\n',i)
    m=m[:e]+' '+src+m[e:]
MAKE.write_text(m)

u=UI.read_text()
old='HFAMap RuntimeAnalyzer v0.3.13.18 AnalysisBudgetAndDedup'
if old in u:u=u.replace(old,'HFAMap RuntimeAnalyzer v0.3.13.19 C4M0ConfigOwnerResolver')
elif 'v0.3.13.19 C4M0ConfigOwnerResolver' not in u:raise SystemExit('UI marker anchor missing')
UI.write_text(u)

resolver=(ROOT/'hfamap'/'src'/'HFAMapC4M0ConfigOwnerResolver.m').read_text()
for token in ['loadConfig:','loadPolicies','com.hfa.c4m0-config-owner/v0.3.13.19','readOnly','invoked']:
    if token not in resolver:raise SystemExit('resolver token missing '+token)
print('v0.3.13.19 C4M0 config owner resolver applied')
