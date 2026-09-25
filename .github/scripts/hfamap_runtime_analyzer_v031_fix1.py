from pathlib import Path
p = Path('hfamap/src/HFAMapManualCapture.m')
s = p.read_text()
anchor = '#import <mach/mach.h>\n'
inc = '#import <mach/mach_vm.h>\n'
if inc not in s:
    if anchor not in s:
        raise SystemExit('mach include anchor missing')
    s = s.replace(anchor, anchor + inc, 1)
p.write_text(s)
print('v0.3.1 fix1: mach_vm header added')
