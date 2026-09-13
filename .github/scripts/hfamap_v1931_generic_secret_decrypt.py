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


# v1.9.31 GenericSecretDecryptResolver
# - preserve the already runtime-confirmed 15 MB decrypt path as a fast path
# - if the legacy relative candidate does not fingerprint, resolve the decrypt routine
#   by scanning the current image's loaded Mach-O __TEXT,__text section
# - accept a scanned routine only when the stable ARM64 decrypt fingerprint is unique
# - never hardcode the observed 5 MB relative delta, image name, class name, or RVA

s = replace_once(
    s,
    '[HFALearn v1.9.30 JailpatchSelectorResolver] loaded',
    '[HFALearn v1.9.31 GenericSecretDecryptResolver] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.30 JailpatchSelectorResolver] loaded',
    '[HFALearn UI v1.9.31 GenericSecretDecryptResolver] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=selector-resolver export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=selector-resolver+generic-secret-decrypt export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    'update dual mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.30 JailpatchSelectorResolver',
    'HFAMap v1.9.31 GenericSecretDecryptResolver',
    2,
    'update generic resolver version markers',
)
g = replace_once(g, '@"1.9.30"', '@"1.9.31"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.30 JailpatchSelectorResolver";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.31 GenericSecretDecryptResolver";',
    'update profiler version',
)
p = replace_once(p, '@"1.9.30"', '@"1.9.31"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.30 JailpatchSelectorResolver";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.31 GenericSecretDecryptResolver";',
    'update selector resolver version',
)
r = replace_once(r, '@"1.9.30"', '@"1.9.31"', 'update selector resolver json version')

l = replace_once(
    l,
    'HFAMap v1.9.30 Jailpatch Resolver',
    'HFAMap v1.9.31 Generic Secret Resolver',
    'update panel title',
)
l = replace_once(
    l,
    'Legacy resolver + Jailpatch selector resolver enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'Legacy + Jailpatch selector resolver with generic secret decrypt enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'update panel help',
)

helper_anchor = '''static int HFADecryptWrapper(id wrapper, char *out, size_t outCap, const char *label) {\n'''
helper = r'''typedef struct {
    const void *imageBase;
    uintptr_t decryptAddress;
    unsigned matches;
    int mode;
} HFADecryptResolverCache;

static HFADecryptResolverCache gDecryptResolverCache[16];
static unsigned gDecryptResolverCacheCount;

static int HFADecryptFingerprint(uintptr_t address) {
    if (!address) return 0;
    uint32_t insn0 = 0, insn30 = 0, insn40 = 0;
    memcpy(&insn0, (const void *)address, 4);
    memcpy(&insn30, (const void *)(address + 0x30u), 4);
    memcpy(&insn40, (const void *)(address + 0x40u), 4);
    return insn0 == 0xD105C3FFu &&
           insn30 == 0xB9400408u &&
           insn40 == 0x53187D00u;
}

static int HFATextRangeForImage(const void *imageBase, uintptr_t *startOut,
                                uintptr_t *endOut) {
    if (!imageBase || !startOut || !endOut) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)imageBase;
    if (mh->magic != MH_MAGIC_64) return 0;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize || lc->cmdsize > 0x10000u) return 0;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            if (strncmp(seg->segname, "__TEXT", sizeof(seg->segname)) == 0) {
                uintptr_t slide = (uintptr_t)mh - (uintptr_t)seg->vmaddr;
                const struct section_64 *sec =
                    (const struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
                    if (strncmp(sec->sectname, "__text", sizeof(sec->sectname)) == 0 &&
                        strncmp(sec->segname, "__TEXT", sizeof(sec->segname)) == 0) {
                        uintptr_t start = slide + (uintptr_t)sec->addr;
                        uintptr_t end = start + (uintptr_t)sec->size;
                        if (end <= start || sec->size < 0x44u) return 0;
                        *startOut = start;
                        *endOut = end;
                        return 1;
                    }
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return 0;
}

static uintptr_t HFAResolveSecretDecrypt(IMP getter, Dl_info *getterInfoOut,
                                         unsigned *matchesOut,
                                         const char **modeOut) {
    if (matchesOut) *matchesOut = 0;
    if (modeOut) *modeOut = "none";
    if (!getter) return 0;
    Dl_info getterInfo = {0};
    if (!dladdr((const void *)getter, &getterInfo) ||
        !getterInfo.dli_fbase || !getterInfo.dli_fname) return 0;
    if (getterInfoOut) *getterInfoOut = getterInfo;

    uintptr_t legacyCandidate = (uintptr_t)getter + 0xD00u;
    Dl_info legacyInfo = {0};
    if (dladdr((const void *)legacyCandidate, &legacyInfo) &&
        legacyInfo.dli_fbase == getterInfo.dli_fbase &&
        HFADecryptFingerprint(legacyCandidate)) {
        if (matchesOut) *matchesOut = 1;
        if (modeOut) *modeOut = "legacy-relative";
        return legacyCandidate;
    }

    for (unsigned i = 0; i < gDecryptResolverCacheCount; i++) {
        HFADecryptResolverCache *cache = &gDecryptResolverCache[i];
        if (cache->imageBase != getterInfo.dli_fbase) continue;
        if (matchesOut) *matchesOut = cache->matches;
        if (modeOut) *modeOut = cache->mode == 2 ? "text-fingerprint" : "ambiguous";
        return cache->decryptAddress;
    }

    uintptr_t textStart = 0, textEnd = 0;
    if (!HFATextRangeForImage(getterInfo.dli_fbase, &textStart, &textEnd)) return 0;
    uintptr_t found = 0;
    unsigned matches = 0;
    uintptr_t last = textEnd - 0x44u;
    for (uintptr_t address = (textStart + 3u) & ~(uintptr_t)3u;
         address <= last; address += 4u) {
        if (!HFADecryptFingerprint(address)) continue;
        found = address;
        matches++;
        if (matches > 1u) found = 0;
    }

    if (gDecryptResolverCacheCount <
        sizeof(gDecryptResolverCache) / sizeof(gDecryptResolverCache[0])) {
        HFADecryptResolverCache *cache =
            &gDecryptResolverCache[gDecryptResolverCacheCount++];
        cache->imageBase = getterInfo.dli_fbase;
        cache->decryptAddress = matches == 1u ? found : 0;
        cache->matches = matches;
        cache->mode = matches == 1u ? 2 : 3;
    }
    if (matchesOut) *matchesOut = matches;
    if (modeOut) *modeOut = matches == 1u ? "text-fingerprint" : "ambiguous";
    return matches == 1u ? found : 0;
}

static int HFADecryptWrapper(id wrapper, char *out, size_t outCap, const char *label) {
'''
s = replace_once(s, helper_anchor, helper, 'insert generic secret decrypt resolver')

old_locator = r'''    IMP getter = method_getImplementation(getterMethod);
    uintptr_t decryptAddress = (uintptr_t)getter + 0xD00u;
    Dl_info getterInfo = {0}, decryptInfo = {0};
    if (!dladdr((void *)getter, &getterInfo) ||
        !dladdr((void *)decryptAddress, &decryptInfo) ||
        getterInfo.dli_fbase != decryptInfo.dli_fbase) return 0;
    uintptr_t getterRVA = (uintptr_t)getter - (uintptr_t)getterInfo.dli_fbase;
    uintptr_t decryptRVA = decryptAddress - (uintptr_t)decryptInfo.dli_fbase;

    uint32_t insn0 = 0, insn30 = 0, insn40 = 0;
    memcpy(&insn0, (void *)decryptAddress, 4);
    memcpy(&insn30, (void *)(decryptAddress + 0x30), 4);
    memcpy(&insn40, (void *)(decryptAddress + 0x40), 4);
    if (insn0 != 0xD105C3FFu || insn30 != 0xB9400408u || insn40 != 0x53187D00u) {
        HFALog("[MAP-DECRYPT-SKIP] field=%s image=%s getterRVA=%llX candidateRVA=%llX fingerprint=%08X/%08X/%08X\n",
               label, HFABase(getterInfo.dli_fname),
               (unsigned long long)getterRVA, (unsigned long long)decryptRVA,
               insn0, insn30, insn40);
        return 0;
    }
'''
new_locator = r'''    IMP getter = method_getImplementation(getterMethod);
    Dl_info getterInfo = {0}, decryptInfo = {0};
    unsigned decryptMatches = 0;
    const char *decryptMode = "none";
    uintptr_t decryptAddress = HFAResolveSecretDecrypt(
        getter, &getterInfo, &decryptMatches, &decryptMode);
    uintptr_t getterRVA = getterInfo.dli_fbase ?
        (uintptr_t)getter - (uintptr_t)getterInfo.dli_fbase : 0;
    if (!decryptAddress ||
        !dladdr((const void *)decryptAddress, &decryptInfo) ||
        decryptInfo.dli_fbase != getterInfo.dli_fbase) {
        HFALog("[MAP-DECRYPT-SKIP] field=%s image=%s getterRVA=%llX reason=resolver mode=%s matches=%u\n",
               label, getterInfo.dli_fname ? HFABase(getterInfo.dli_fname) : "?",
               (unsigned long long)getterRVA, decryptMode, decryptMatches);
        return 0;
    }
    uintptr_t decryptRVA = decryptAddress - (uintptr_t)decryptInfo.dli_fbase;
    HFALog("[MAP-DECRYPT-RESOLVE] field=%s image=%s getterRVA=%llX decryptRVA=%llX mode=%s matches=%u\n",
           label, HFABase(getterInfo.dli_fname),
           (unsigned long long)getterRVA, (unsigned long long)decryptRVA,
           decryptMode, decryptMatches);
'''
s = replace_once(s, old_locator, new_locator, 'replace fixed decrypt locator')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
