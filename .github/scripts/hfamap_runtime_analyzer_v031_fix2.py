from pathlib import Path

p = Path('hfamap/src/HFAMapManualCapture.m')
s = p.read_text()

s = s.replace('#import <mach/mach_vm.h>\n', '')
s = s.replace('#import <mach/vm_region.h>\n', '')

start = s.find('static BOOL HFACaptureVMInfo(')
end = s.find('static NSString *HFACaptureHexAt(', start)
if start < 0 or end < 0:
    raise SystemExit('VM helper span missing')

replacement = r'''static BOOL HFACaptureSegmentAllows(uintptr_t address, size_t size, vm_prot_t required) {
    if (!address || !size) return NO;
    uintptr_t last = address + size - 1;
    if (last < address) return NO;
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h || h->magic != MH_MAGIC_64) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *cursor = (const uint8_t *)(h + 1);
        for (uint32_t c = 0; c < h->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)cursor;
            if (!lc->cmdsize) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
                uintptr_t a = (uintptr_t)slide + (uintptr_t)seg->vmaddr;
                uintptr_t e = a + (uintptr_t)seg->vmsize;
                if (e > a && address >= a && last < e && (seg->initprot & required) == required)
                    return YES;
            }
            cursor += lc->cmdsize;
        }
    }
    return NO;
}

static BOOL HFACaptureReadable(uintptr_t address, size_t size) {
    return HFACaptureSegmentAllows(address, size, VM_PROT_READ);
}

static BOOL HFACaptureWritable(uintptr_t address, size_t size) {
    return HFACaptureSegmentAllows(address, size, VM_PROT_READ | VM_PROT_WRITE);
}

'''
s = s[:start] + replacement + s[end:]

old = '''static BOOL HFACapturePointerLike(uint64_t value) {
    if (value < 0x10000ull) return NO;
    return HFACaptureReadable((uintptr_t)value, 1);
}'''
new = '''static BOOL HFACapturePointerLike(uint64_t value) {
    if (value < 0x10000ull) return NO;
#if __LP64__
    if (value >= 0x0000800000000000ull) return NO;
#endif
    return (value & 0x7ull) == 0;
}'''
if old not in s:
    raise SystemExit('pointer helper missing')
s = s.replace(old, new, 1)

p.write_text(s)
print('v0.3.1 fix2: Mach-O segment guards installed')
