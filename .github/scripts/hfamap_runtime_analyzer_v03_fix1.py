from pathlib import Path

p = Path('hfamap/src/HFAMapRuntimeAnalyzerV02.m')
s = p.read_text()

s = s.replace('_dyld_image_vmaddr_slide(', '_dyld_get_image_vmaddr_slide(')

anchor = 'static BOOL HFAV03ADR(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *addr){'
proto = '''static BOOL HFAV02ADRP(uint32_t w,uintptr_t pc,unsigned *rd,uintptr_t *page);\nstatic BOOL HFAV02ADD(uint32_t w,unsigned *rd,unsigned *rn,uint64_t *imm);\n\n'''
if proto.strip() not in s:
    if anchor not in s:
        raise SystemExit('HFAV03ADR anchor missing')
    s = s.replace(anchor, proto + anchor, 1)

p.write_text(s)
print('v0.3 fix1: decoder prototypes + dyld API corrected')
