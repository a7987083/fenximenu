from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")
generic_path = Path("hfamap/src/HFAMapGenericMenuResolver.m")
profiler_path = Path("hfamap/src/HFAMapJailpatchRuntimeProfiler.m")
selector_path = Path("hfamap/src/HFAMapJailpatchSelectorResolver.m")

s = patch_path.read_text()
l = legacy_path.read_text()
g = generic_path.read_text()
p = profiler_path.read_text()
r = selector_path.read_text()


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


def replace_exact(text, old, new, expected, label):
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} matches, got {count}")
    return text.replace(old, new)


# v1.9.33 OriginalByteResolver
# Device evidence from v1.9.32 confirms the 5 MB runtime-record resolver end to end:
# semantic menu discovery is stable, decrypt fingerprint resolution returns rc=0,
# and all eight observed descriptors produce valid FULL-MAPPING records. Package
# export still kept only one mapping because the legacy exporter had exactly one
# original-byte source: vm_read_overwrite(slide + Mach-O vmaddr). Seven mappings
# failed that read and were conservatively omitted.
#
# Keep that safety property. A patch is still exportable only when original bytes
# are known. Add generic fallbacks instead of weakening the schema:
#   1. vm_read_overwrite from live memory
#   2. bounded direct memcpy when the page is readable
#   3. on-disk Mach-O segment translation when the requested file range is not
#      covered by an active FairPlay encryption range
# If live memory already equals the enabled bytes, prefer a trustworthy on-disk
# original when available. No sample address/image/feature is hardcoded.

s = replace_once(
    s,
    '[HFALearn v1.9.32 CrashSafeFullScan] loaded',
    '[HFALearn v1.9.33 OriginalByteResolver] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.32 CrashSafeFullScan] loaded',
    '[HFALearn UI v1.9.33 OriginalByteResolver] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=semantic-feature-array jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=semantic-feature-array jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    'update mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.32 CrashSafeFullScan',
    'HFAMap v1.9.33 OriginalByteResolver',
    2,
    'update generic resolver markers',
)
g = replace_once(g, '@"1.9.32"', '@"1.9.33"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.32 CrashSafeFullScan";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.33 OriginalByteResolver";',
    'update profiler version marker',
)
p = replace_once(p, '@"1.9.32"', '@"1.9.33"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.32 CrashSafeFullScan";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.33 OriginalByteResolver";',
    'update selector version marker',
)
r = replace_once(r, '@"1.9.32"', '@"1.9.33"', 'update selector json version')

l = replace_once(
    l,
    'HFAMap v1.9.32 Crash-Safe Scan',
    'HFAMap v1.9.33 Original Resolver',
    'update panel title',
)
l = replace_once(
    l,
    'Crash-safe semantic scan + generic secret decrypt enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'Crash-safe scan + generic decrypt + multi-source original-byte resolver.\\nOpen the menu, scan, then exercise visible controls.',
    'update panel help',
)

old_reader = r'''static NSData *HFAReadOriginalBytes(uint32_t imageIndex, uint64_t rva, NSUInteger length) {
    if (!length || UINT64_MAX - (uint64_t)_dyld_get_image_vmaddr_slide(imageIndex) < rva) return nil;
    vm_address_t address = (vm_address_t)(_dyld_get_image_vmaddr_slide(imageIndex) + rva);
    NSMutableData *data = [NSMutableData dataWithLength:length];
    vm_size_t read = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), address, length,
                                         (vm_address_t)data.mutableBytes, &read);
    return kr == KERN_SUCCESS && read == length ? data : nil;
}
'''
new_reader = r'''static NSData *HFAReadOriginalBytesFromFile(uint32_t imageIndex, uint64_t vmaddr,
                                                   NSUInteger length, int *cryptidOut) {
    if (cryptidOut) *cryptidOut = -1;
    if (!length) return nil;
    const char *path = _dyld_get_image_name(imageIndex);
    if (!path || !*path) return nil;
    NSData *imageData = [NSData dataWithContentsOfFile:
        [NSString stringWithUTF8String:path]];
    if (!imageData || imageData.length < sizeof(struct mach_header_64)) return nil;

    const uint8_t *bytes = (const uint8_t *)imageData.bytes;
    size_t fileLength = imageData.length;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64 ||
        sizeof(*mh) + (size_t)mh->sizeofcmds > fileLength) return nil;

    uint32_t cryptoff = 0, cryptsize = 0, cryptid = 0;
    const uint8_t *cursor = bytes + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((size_t)(cursor - bytes) + sizeof(struct load_command) > fileLength)
            return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize || (size_t)(cursor - bytes) + lc->cmdsize > fileLength)
            return nil;
        if (lc->cmd == LC_ENCRYPTION_INFO_64 &&
            lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            const struct encryption_info_command_64 *ec =
                (const struct encryption_info_command_64 *)cursor;
            cryptoff = ec->cryptoff;
            cryptsize = ec->cryptsize;
            cryptid = ec->cryptid;
        }
        cursor += lc->cmdsize;
    }
    if (cryptidOut) *cryptidOut = (int)cryptid;

    cursor = bytes + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmd == LC_SEGMENT_64 &&
            lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            if (vmaddr >= seg->vmaddr) {
                uint64_t delta = vmaddr - seg->vmaddr;
                if (delta <= seg->filesize &&
                    (uint64_t)length <= seg->filesize - delta &&
                    UINT64_MAX - seg->fileoff >= delta) {
                    uint64_t fileOffset = seg->fileoff + delta;
                    if (UINT64_MAX - fileOffset >= (uint64_t)length &&
                        fileOffset + (uint64_t)length <= fileLength) {
                        uint64_t fileEnd = fileOffset + (uint64_t)length;
                        uint64_t cryptEnd = (uint64_t)cryptoff + (uint64_t)cryptsize;
                        int encryptedOverlap = cryptid && cryptsize &&
                            fileEnd > (uint64_t)cryptoff && fileOffset < cryptEnd;
                        if (encryptedOverlap) return nil;
                        return [imageData subdataWithRange:
                            NSMakeRange((NSUInteger)fileOffset, length)];
                    }
                }
            }
        }
        if (!lc->cmdsize) break;
        cursor += lc->cmdsize;
    }
    return nil;
}

static NSData *HFAReadOriginalBytes(uint32_t imageIndex, uint64_t vmaddr,
                                    NSUInteger length, const char **sourceOut,
                                    int *cryptidOut) {
    if (sourceOut) *sourceOut = "unavailable";
    if (cryptidOut) *cryptidOut = -1;
    if (!length) return nil;

    intptr_t slide = _dyld_get_image_vmaddr_slide(imageIndex);
    uintptr_t address = (uintptr_t)((intptr_t)vmaddr + slide);
    if (address < (uintptr_t)length) return nil;

    NSMutableData *data = [NSMutableData dataWithLength:length];
    vm_size_t read = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         length, (vm_address_t)data.mutableBytes,
                                         &read);
    if (kr == KERN_SUCCESS && read == length) {
        if (sourceOut) *sourceOut = "vm-read";
        return data;
    }

    if (HFAReadable(address, length)) {
        memcpy(data.mutableBytes, (const void *)address, length);
        if (sourceOut) *sourceOut = "memcpy";
        return data;
    }

    int cryptid = -1;
    NSData *fileData = HFAReadOriginalBytesFromFile(imageIndex, vmaddr, length,
                                                    &cryptid);
    if (cryptidOut) *cryptidOut = cryptid;
    if (fileData.length == length) {
        if (sourceOut) *sourceOut = "mach-o-file";
        return fileData;
    }
    return nil;
}
'''
s = replace_once(s, old_reader, new_reader, 'replace single-source original reader')

old_call = r'''                NSData *original = imageIndex >= 0 ? HFAReadOriginalBytes((uint32_t)imageIndex, rva, enabled.length) : nil;
                if (definition && enabled.length && original.length == enabled.length) {
                    if ([original isEqualToData:enabled]) {
                        HFALog("[PACKAGE-SKIP] title=\"%s\" reason=patch-already-enabled\n", title);
                    } else {
'''
new_call = r'''                const char *originalSource = "unavailable";
                int originalCryptid = -1;
                NSData *original = imageIndex >= 0 ?
                    HFAReadOriginalBytes((uint32_t)imageIndex, rva, enabled.length,
                                         &originalSource, &originalCryptid) : nil;
                if (definition && enabled.length && original.length == enabled.length &&
                    [original isEqualToData:enabled] && imageIndex >= 0) {
                    int fileCryptid = -1;
                    NSData *fileOriginal = HFAReadOriginalBytesFromFile(
                        (uint32_t)imageIndex, rva, enabled.length, &fileCryptid);
                    if (fileOriginal.length == enabled.length &&
                        ![fileOriginal isEqualToData:enabled]) {
                        original = fileOriginal;
                        originalSource = "mach-o-file-after-enabled-live";
                        originalCryptid = fileCryptid;
                    }
                }
                HFALog("[PACKAGE-ORIGINAL] title=\"%s\" module=%s offset=%s bytes=%u imageIndex=%d source=%s cryptid=%d status=%s\n",
                       title, descriptor->module[0] ? descriptor->module : "?",
                       normalizedOffset[0] ? normalizedOffset : "?",
                       (unsigned)enabled.length, imageIndex, originalSource,
                       originalCryptid,
                       original.length == enabled.length ? "ok" : "unavailable");
                if (definition && enabled.length && original.length == enabled.length) {
                    if ([original isEqualToData:enabled]) {
                        HFALog("[PACKAGE-SKIP] title=\"%s\" reason=patch-already-enabled source=%s\n",
                               title, originalSource);
                    } else {
'''
s = replace_once(s, old_call, new_call, 'instrument package original resolution')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
