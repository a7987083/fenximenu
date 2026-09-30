from pathlib import Path

P=Path('hfamap/src/HFAMapRuntimeModificationTruth.m')
s=P.read_text()
proto='static NSDictionary *HFATIL2CPPSemantic(uintptr_t address);\n\n'
anchor='static uintptr_t HFATBranch26Target(uintptr_t pc,uint32_t insn){\n'
if proto not in s:
    if anchor not in s: raise SystemExit('v031317 branch helper anchor missing')
    s=s.replace(anchor,proto+anchor,1)
P.write_text(s)
if proto not in P.read_text(): raise SystemExit('v031317 semantic prototype insertion failed')
print('v0.3.13.17 compile fix applied')
