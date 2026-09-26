from pathlib import Path

p = Path('hfamap/src/HFARuntimeSemanticAnalyzer.m')
s = p.read_text()

if '#import <mach/mach_vm.h>' not in s:
    s = s.replace('#import <mach/mach.h>\n', '#import <mach/mach.h>\n#import <mach/mach_vm.h>\n', 1)

unused = '            uintptr_t rs = x.base + (uintptr_t)g->vmaddr;\n'
if unused in s:
    s = s.replace(unused, '', 1)

if '#import <mach/mach_vm.h>' not in s:
    raise SystemExit('v034 mach_vm compatibility include missing')
if unused in s:
    raise SystemExit('v034 unused rs compile regression')

p.write_text(s)
print('v0.3.4 semantic compile compatibility fix applied')
