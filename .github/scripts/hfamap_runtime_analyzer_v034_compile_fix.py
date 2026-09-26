from pathlib import Path
import re

p = Path('hfamap/src/HFARuntimeSemanticAnalyzer.m')
s = p.read_text()

# iPhoneOS SDK deliberately rejects <mach/mach_vm.h>. Use public
# vm_read_overwrite for bounded readability probes and Mach-O initprot for
# writable classification instead of mach_vm_region.
s = s.replace('#import <mach/mach_vm.h>\n', '')
if '// #import <mach/mach_vm.h> unsupported on iPhoneOS' not in s:
    s = s.replace('#import <mach/mach.h>\n', '#import <mach/mach.h>\n// #import <mach/mach_vm.h> unsupported on iPhoneOS; vm_read_overwrite is used.\n', 1)

readable = r'''static BOOL HFASemReadable(uintptr_t address, size_t size) {
    if (!address || !size || address + size < address || size > 32) return NO;
    uint8_t scratch[32] = {0};
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)scratch,
                                         &got);
    return kr == KERN_SUCCESS && got == (vm_size_t)size;
}'''
s, n = re.subn(r'static BOOL HFASemReadable\(uintptr_t address, size_t size\) \{.*?\n\}', readable, s, count=1, flags=re.S)
if n != 1:
    raise SystemExit('v034 HFASemReadable replacement failed')

writable = r'''static BOOL HFASemWritable(uintptr_t address, HFASemImage image) {
    if (!address || !image.header) return NO;
    const uint8_t *c = (const uint8_t *)(image.header + 1);
    for (uint32_t i = 0; i < image.header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)c;
        if (lc->cmdsize < sizeof(*lc)) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *g = (const struct segment_command_64 *)c;
            uintptr_t start = (uintptr_t)((intptr_t)g->vmaddr + image.slide);
            uintptr_t end = start + (uintptr_t)g->vmsize;
            if (address >= start && address < end) return (g->initprot & VM_PROT_WRITE) != 0;
        }
        c += lc->cmdsize;
    }
    return NO;
}'''
s, n = re.subn(r'static BOOL HFASemWritable\(uintptr_t address, HFASemImage image\) \{.*?\n\}', writable, s, count=1, flags=re.S)
if n != 1:
    raise SystemExit('v034 HFASemWritable replacement failed')

unused = '            uintptr_t rs = x.base + (uintptr_t)g->vmaddr;\n'
s = s.replace(unused, '', 1)

if 'mach_vm_region(' in s:
    raise SystemExit('v034 unsupported mach_vm_region remains')
if 'vm_read_overwrite(' not in s:
    raise SystemExit('v034 vm_read_overwrite probe missing')
if unused in s:
    raise SystemExit('v034 unused rs compile regression')

p.write_text(s)
print('v0.3.4 iOS-safe VM compatibility fix applied')
