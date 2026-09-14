#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

// v1.9.37 narrow, fail-closed iGMM -> Feature v2 exporter.
// It does not hardcode a game UUID, image offset or feature address. The exporter
// accepts only the hook topology that can be proven from the diagnostic JSON and
// live registration/trampoline evidence:
//   two captureFieldPointer producers + one shared conditional damage pipeline.
// UI semantic roles are accepted only when the menu's own id/title identifies
// damage, defence/defense and god/invincible unambiguously. Other iGMM shapes
// remain diagnostic-only instead of receiving guessed executable semantics.

static NSString *HFAIG37Documents(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static void HFAIG37Log(NSString *format, ...) NS_FORMAT_FUNCTION(1,2);
static void HFAIG37Log(NSString *format, ...) {
    va_list ap;
    va_start(ap, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end(ap);
    NSString *path = [HFAIG37Documents() stringByAppendingPathComponent:@"HFAMap_FeatureV2.log"];
    NSString *full = [NSString stringWithFormat:@"%@ %@\n", [[NSDate date] descriptionWithLocale:@"en_US_POSIX"], line ?: @""];
    NSData *data = [full dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm fileExistsAtPath:path]) [fm createFileAtPath:path contents:nil attributes:nil];
    NSFileHandle *h = [NSFileHandle fileHandleForWritingAtPath:path];
    if (h) {
        @try { [h seekToEndOfFile]; [h writeData:data]; [h synchronizeFile]; } @catch (__unused id e) {}
        [h closeFile];
    }
}

static const char *HFAIG37Base(const char *path) {
    if (!path) return "?";
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int HFAIG37ImageIndex(NSString *name) {
    if (![name isKindOfClass:[NSString class]] || !name.length) return -1;
    const char *wanted = name.UTF8String;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *path = _dyld_get_image_name(i);
        if (path && strcmp(HFAIG37Base(path), wanted) == 0) return (int)i;
    }
    return -1;
}

static BOOL HFAIG37Readable(uintptr_t address, size_t size) {
    if (!address || !size) return NO;
    mach_vm_address_t region = (mach_vm_address_t)address;
    mach_vm_size_t regionSize = 0;
    vm_region_basic_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &regionSize,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    if (kr != KERN_SUCCESS || !(info.protection & VM_PROT_READ)) return NO;
    return address >= region && address + size >= address && address + size <= region + regionSize;
}

static NSString *HFAIG37Hex(uintptr_t address, size_t size) {
    if (!size || size > 32 || !HFAIG37Readable(address, size)) return nil;
    const uint8_t *p = (const uint8_t *)address;
    NSMutableString *s = [NSMutableString stringWithCapacity:size * 2];
    for (size_t i = 0; i < size; i++) [s appendFormat:@"%02X", p[i]];
    return s;
}

static BOOL HFAIG37ParseHex(NSString *text, uint64_t *out) {
    if (![text isKindOfClass:[NSString class]] || !text.length) return NO;
    const char *s = text.UTF8String;
    if (!s) return NO;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') return NO;
    if (out) *out = (uint64_t)v;
    return YES;
}

static int64_t HFAIG37SignExtend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static uintptr_t HFAIG37ADR(uintptr_t pc, uint32_t word) {
    if ((word & 0x9F000000u) != 0x10000000u) return 0;
    uint64_t immlo = (word >> 29) & 3u;
    uint64_t immhi = (word >> 5) & 0x7FFFFu;
    int64_t imm = HFAIG37SignExtend((immhi << 2) | immlo, 21);
    return (uintptr_t)((intptr_t)pc + imm);
}

static uintptr_t HFAIG37ADRP(uintptr_t pc, uint32_t word) {
    if ((word & 0x9F000000u) != 0x90000000u) return 0;
    uint64_t immlo = (word >> 29) & 3u;
    uint64_t immhi = (word >> 5) & 0x7FFFFu;
    int64_t pages = HFAIG37SignExtend((immhi << 2) | immlo, 21);
    return (pc & ~(uintptr_t)0xFFFu) + (uintptr_t)(pages << 12);
}

static BOOL HFAIG37ADDImmediate(uint32_t word, unsigned *rnOut, uintptr_t *immOut) {
    if ((word & 0x7F000000u) != 0x11000000u) return NO;
    unsigned rn = (word >> 5) & 31u;
    uintptr_t imm = (uintptr_t)((word >> 10) & 0xFFFu);
    if ((word >> 22) & 1u) imm <<= 12;
    if (rnOut) *rnOut = rn;
    if (immOut) *immOut = imm;
    return YES;
}

static BOOL HFAIG37PairAddress(uintptr_t start, size_t words, size_t index,
                               unsigned reg, uintptr_t *out) {
    if (index >= words) return NO;
    uintptr_t pc = start + index * 4;
    uint32_t first = 0;
    memcpy(&first, (const void *)pc, 4);
    uintptr_t page = HFAIG37ADRP(pc, first);
    if (!page || (first & 31u) != reg) return NO;
    for (size_t n = 1; n <= 4 && index + n < words; n++) {
        uint32_t add = 0;
        memcpy(&add, (const void *)(start + (index + n) * 4), 4);
        unsigned rn = 0;
        uintptr_t imm = 0;
        if (!HFAIG37ADDImmediate(add, &rn, &imm)) continue;
        if (rn != reg || (add & 31u) != reg) continue;
        if (out) *out = page + imm;
        return YES;
    }
    return NO;
}

static uintptr_t HFAIG37ROR64(uintptr_t value, unsigned amount) {
    amount &= 63u;
    return amount ? ((value >> amount) | (value << (64u - amount))) : value;
}

static uintptr_t HFAIG37EmulateTrampoline(uintptr_t entry) {
    if (!entry || !HFAIG37Readable(entry, 4)) return 0;
    uintptr_t regs[32] = {0};
    uint8_t valid[32] = {0};
    for (unsigned i = 0; i < 96; i++) {
        uintptr_t pc = entry + (uintptr_t)i * 4u;
        if (!HFAIG37Readable(pc, 4)) return 0;
        uint32_t w = 0;
        memcpy(&w, (const void *)pc, 4);
        uintptr_t page = HFAIG37ADRP(pc, w);
        if (page) { unsigned rd = w & 31u; regs[rd] = page; valid[rd] = 1; continue; }
        uintptr_t adr = HFAIG37ADR(pc, w);
        if (adr) { unsigned rd = w & 31u; regs[rd] = adr; valid[rd] = 1; continue; }
        if ((w & 0xFF000000u) == 0x91000000u || (w & 0xFF000000u) == 0xD1000000u) {
            unsigned rd = w & 31u, rn = (w >> 5) & 31u;
            uintptr_t imm = (uintptr_t)((w >> 10) & 0xFFFu);
            if ((w >> 22) & 1u) imm <<= 12;
            if (valid[rn]) { regs[rd] = ((w & 0xFF000000u) == 0x91000000u) ? regs[rn] + imm : regs[rn] - imm; valid[rd] = 1; }
            else valid[rd] = 0;
            continue;
        }
        if ((w & 0xFFC00000u) == 0xF9400000u) {
            unsigned rt = w & 31u, rn = (w >> 5) & 31u;
            uintptr_t imm = (uintptr_t)((w >> 10) & 0xFFFu) << 3;
            if (valid[rn] && HFAIG37Readable(regs[rn] + imm, sizeof(uintptr_t))) {
                uintptr_t value = 0; memcpy(&value, (const void *)(regs[rn] + imm), sizeof(value));
                regs[rt] = value; valid[rt] = 1;
            } else valid[rt] = 0;
            continue;
        }
        if ((w & 0xFFE00000u) == 0x93C00000u) {
            unsigned rd = w & 31u, rn = (w >> 5) & 31u, rm = (w >> 16) & 31u;
            unsigned amount = (w >> 10) & 0x3Fu;
            if (rn == rm && valid[rn]) { regs[rd] = HFAIG37ROR64(regs[rn], amount); valid[rd] = 1; }
            else valid[rd] = 0;
            continue;
        }
        if ((w & 0xFFFFFC1Fu) == 0xD61F0000u) {
            unsigned rn = (w >> 5) & 31u;
            if (!valid[rn] || !regs[rn]) return 0;
            uintptr_t target = regs[rn];
#if __has_feature(ptrauth_calls)
            target = (uintptr_t)ptrauth_strip((void *)target, ptrauth_key_function_pointer);
#endif
            return target;
        }
    }
    return 0;
}

static NSString *HFAIG37UUID(const struct mach_header_64 *h) {
    if (!h) return nil;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *end = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return nil;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uc = (const struct uuid_command *)cursor;
            NSMutableString *s = [NSMutableString stringWithCapacity:36];
            for (unsigned j = 0; j < 16; j++) {
                if (j == 4 || j == 6 || j == 8 || j == 10) [s appendString:@"-"];
                [s appendFormat:@"%02X", uc->uuid[j]];
            }
            return s;
        }
        cursor += lc->cmdsize;
    }
    return nil;
}

static NSDictionary *HFAIG37ImageIdentity(NSString *image) {
    int index = HFAIG37ImageIndex(image);
    if (index < 0) return nil;
    const struct mach_header *mh = _dyld_get_image_header((uint32_t)index);
    if (!mh || mh->magic != MH_MAGIC_64) return nil;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    uint64_t textVM = 0;
    int cryptid = -1;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *end = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) textVM = seg->vmaddr;
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            cryptid = (int)((const struct encryption_info_command_64 *)cursor)->cryptid;
        }
        cursor += lc->cmdsize;
    }
    cpu_subtype_t subtype = h->cpusubtype & ~CPU_SUBTYPE_MASK;
#ifdef CPU_SUBTYPE_ARM64E
    NSString *arch = subtype == CPU_SUBTYPE_ARM64E ? @"arm64e" : @"arm64";
#else
    NSString *arch = @"arm64";
#endif
    const char *path = _dyld_get_image_name((uint32_t)index);
    NSString *resolved = path ? [NSString stringWithUTF8String:HFAIG37Base(path)] : image;
    return @{ @"status": @"resolved", @"declaredImage": image, @"resolvedImage": resolved ?: image,
              @"uuid": HFAIG37UUID(h) ?: @"?", @"architecture": arch,
              @"cputype": @((int)h->cputype), @"cpusubtype": @((int)subtype),
              @"preferredTextVMAddr": [NSString stringWithFormat:@"0x%llX", (unsigned long long)textVM],
              @"cryptid": @(cryptid) };
}

static NSDictionary *HFAIG37AddressInfo(uintptr_t runtime) {
    if (!runtime) return nil;
#if __has_feature(ptrauth_calls)
    runtime = (uintptr_t)ptrauth_strip((void *)runtime, ptrauth_key_function_pointer);
#endif
    Dl_info info = {0};
    if (!dladdr((void *)runtime, &info) || !info.dli_fname) return nil;
    NSString *image = [NSString stringWithUTF8String:HFAIG37Base(info.dli_fname)] ?: @"?";
    int index = HFAIG37ImageIndex(image);
    if (index < 0) return nil;
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)index);
    uint64_t preferred = (uint64_t)((intptr_t)runtime - slide);
    return @{ @"image": image,
              @"offset": [NSString stringWithFormat:@"0x%llX", (unsigned long long)preferred] };
}

static BOOL HFAIG37IsB(uintptr_t address) {
    if (!HFAIG37Readable(address, 4)) return NO;
    uint32_t w = 0; memcpy(&w, (const void *)address, 4);
    return (w & 0x7C000000u) == 0x14000000u;
}

static uint64_t HFAIG37CaptureFieldOffset(uintptr_t handler) {
    if (!handler || !HFAIG37Readable(handler, 0x80)) return UINT64_MAX;
    for (unsigned i = 0; i < 32; i++) {
        uint32_t w = 0; memcpy(&w, (const void *)(handler + i * 4), 4);
        if ((w & 0xFFC00000u) != 0xF9400000u) continue;
        unsigned rn = (w >> 5) & 31u;
        unsigned rt = w & 31u;
        uint64_t imm = (uint64_t)((w >> 10) & 0xFFFu) << 3;
        if (rn == 0u && rt != 31u && imm > 0 && imm <= 0x400) return imm;
    }
    return UINT64_MAX;
}

static NSArray<NSDictionary *> *HFAIG37RelatedHooks(NSString *menuImage,
                                                     NSDictionary *mainImpl,
                                                     NSString **reasonOut) {
    NSDictionary *registration = [mainImpl[@"registration"] isKindOfClass:[NSDictionary class]] ? mainImpl[@"registration"] : nil;
    NSDictionary *site = [registration[@"site"] isKindOfClass:[NSDictionary class]] ? registration[@"site"] : nil;
    uint64_t sitePref = 0, mainPref = 0;
    if (!HFAIG37ParseHex(site[@"offset"], &sitePref) || !HFAIG37ParseHex(mainImpl[@"offset"], &mainPref)) {
        if (reasonOut) *reasonOut = @"registration-or-handler-offset-missing";
        return nil;
    }
    int menuIndex = HFAIG37ImageIndex(menuImage);
    if (menuIndex < 0) { if (reasonOut) *reasonOut = @"menu-image-unresolved"; return nil; }
    intptr_t menuSlide = _dyld_get_image_vmaddr_slide((uint32_t)menuIndex);
    uintptr_t mainHandler = (uintptr_t)((intptr_t)mainPref + menuSlide);
    uintptr_t center = (uintptr_t)((intptr_t)sitePref + menuSlide);
    uintptr_t scanStart = center > 0x180 ? center - 0x180 : center;
    size_t scanSize = 0x380;
    if (!HFAIG37Readable(scanStart, scanSize)) { if (reasonOut) *reasonOut = @"registration-neighborhood-unreadable"; return nil; }
    size_t words = scanSize / 4;
    NSMutableArray *hooks = [NSMutableArray array];
    NSMutableSet *handlers = [NSMutableSet set];

    for (size_t i = 0; i < words; i++) {
        uintptr_t pc = scanStart + i * 4;
        uint32_t w = 0; memcpy(&w, (const void *)pc, 4);
        if ((w & 31u) != 3u) continue;
        uintptr_t handler = HFAIG37ADR(pc, w);
        if (!handler || !HFAIG37Readable(handler, 4)) continue;
        NSString *handlerKey = [NSString stringWithFormat:@"%llX", (unsigned long long)handler];
        if ([handlers containsObject:handlerKey]) continue;

        uintptr_t slot = 0;
        for (size_t j = i + 1; j < words && j <= i + 10; j++) {
            uintptr_t candidate = 0;
            if (HFAIG37PairAddress(scanStart, words, j, 4, &candidate)) { slot = candidate; break; }
        }
        if (!slot || !HFAIG37Readable(slot, sizeof(uintptr_t))) continue;
        uintptr_t trampoline = 0; memcpy(&trampoline, (const void *)slot, sizeof(trampoline));
#if __has_feature(ptrauth_calls)
        trampoline = (uintptr_t)ptrauth_strip((void *)trampoline, ptrauth_key_function_pointer);
#endif
        if (!trampoline || !HFAIG37Readable(trampoline, 4)) continue;
        uintptr_t continuation = HFAIG37EmulateTrampoline(trampoline);
        if (!continuation || continuation < 4) continue;
        uintptr_t hookEntry = continuation - 4;
        if (!HFAIG37IsB(hookEntry)) continue;
        NSDictionary *targetInfo = HFAIG37AddressInfo(hookEntry);
        NSDictionary *contInfo = HFAIG37AddressInfo(continuation);
        NSDictionary *trampInfo = HFAIG37AddressInfo(trampoline);
        if (!targetInfo || !contInfo || !trampInfo) continue;
        NSString *original = HFAIG37Hex(trampoline, 4);
        NSString *preexisting = HFAIG37Hex(hookEntry, 4);
        if (!original.length || !preexisting.length || [original caseInsensitiveCompare:preexisting] == NSOrderedSame) continue;
        uint64_t handlerPreferred = (uint64_t)((intptr_t)handler - menuSlide);
        uint64_t slotPreferred = (uint64_t)((intptr_t)slot - menuSlide);
        BOOL isMain = handler == mainHandler;
        uint64_t field = isMain ? UINT64_MAX : HFAIG37CaptureFieldOffset(handler);
        if (!isMain && field == UINT64_MAX) continue;
        NSMutableDictionary *record = [@{
            @"isMain": @(isMain),
            @"handler": [NSString stringWithFormat:@"0x%llX", (unsigned long long)handlerPreferred],
            @"slot": [NSString stringWithFormat:@"0x%llX", (unsigned long long)slotPreferred],
            @"target": targetInfo[@"image"],
            @"offset": targetInfo[@"offset"],
            @"continuation": contInfo[@"offset"],
            @"trampolineImage": trampInfo[@"image"],
            @"trampoline": trampInfo[@"offset"],
            @"original": original,
            @"preexisting": preexisting
        } mutableCopy];
        if (!isMain) record[@"fieldOffset"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)field];
        [hooks addObject:record];
        [handlers addObject:handlerKey];
    }

    NSUInteger mainCount = 0, producerCount = 0;
    NSString *targetImage = nil;
    for (NSDictionary *h in hooks) {
        if ([h[@"isMain"] boolValue]) mainCount++; else producerCount++;
        NSString *image = h[@"target"];
        if (!targetImage) targetImage = image;
        else if (![targetImage isEqualToString:image]) {
            if (reasonOut) *reasonOut = @"related-hooks-cross-target-image";
            return nil;
        }
    }
    if (mainCount != 1 || producerCount != 2 || hooks.count != 3) {
        if (reasonOut) *reasonOut = [NSString stringWithFormat:@"unsupported-hook-topology main=%lu producers=%lu total=%lu",
                                    (unsigned long)mainCount, (unsigned long)producerCount, (unsigned long)hooks.count];
        return nil;
    }
    return hooks;
}

static NSString *HFAIG37SemanticText(NSDictionary *feature) {
    NSString *a = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : @"";
    NSString *b = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : @"";
    return [[NSString stringWithFormat:@"%@ %@", a, b] lowercaseString];
}

static BOOL HFAIG37ContainsAny(NSString *s, NSArray<NSString *> *tokens) {
    for (NSString *t in tokens) if ([s rangeOfString:t].location != NSNotFound) return YES;
    return NO;
}

static NSDictionary *HFAIG37NewestDiagnostic(NSString **pathOut) {
    NSString *docs = HFAIG37Documents();
    NSArray *names = [NSFileManager.defaultManager contentsOfDirectoryAtPath:docs error:nil] ?: @[];
    NSDictionary *best = nil;
    NSDate *bestDate = [NSDate distantPast];
    NSString *bestPath = nil;
    for (NSString *name in names) {
        if (![name hasSuffix:@".hfamap.igmm.json"]) continue;
        NSString *path = [docs stringByAppendingPathComponent:name];
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (!data) continue;
        NSDictionary *root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![root isKindOfClass:[NSDictionary class]] || ![root[@"schema"] isEqual:@"com.hfa.igmm.runtime/v1"]) continue;
        NSDictionary *pkg = root[@"package"];
        NSString *bundle = [pkg[@"bundleIdentifier"] isKindOfClass:[NSString class]] ? pkg[@"bundleIdentifier"] : @"";
        if (bundle.length && ![bundle isEqualToString:(NSBundle.mainBundle.bundleIdentifier ?: @"")]) continue;
        NSDate *date = [[NSFileManager.defaultManager attributesOfItemAtPath:path error:nil] fileModificationDate] ?: [NSDate distantPast];
        if ([date compare:bestDate] == NSOrderedDescending) { best = root; bestDate = date; bestPath = path; }
    }
    if (pathOut) *pathOut = bestPath;
    return best;
}

static NSString *HFAIG37SafeStem(void) {
    NSBundle *b = NSBundle.mainBundle;
    NSString *bundle = b.bundleIdentifier ?: @"unknown.game";
    NSString *shortV = [b objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *build = [b objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSString *raw = [NSString stringWithFormat:@"%@_%@_%@", bundle, shortV, build];
    return [[raw stringByReplacingOccurrencesOfString:@"/" withString:@"_"] stringByReplacingOccurrencesOfString:@" " withString:@"_"];
}

static BOOL HFAIG37WriteJSON(NSDictionary *root, NSString *path) {
    if (![NSJSONSerialization isValidJSONObject:root]) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    return data && [data writeToFile:path options:NSDataWritingAtomic error:nil];
}

BOOL HFAMapIGMMFeatureV2ExportLatest(void) {
    @autoreleasepool {
        NSString *diagPath = nil;
        NSDictionary *diag = HFAIG37NewestDiagnostic(&diagPath);
        if (!diag) { HFAIG37Log(@"[IGMM-V2] status=skip reason=no-current-diagnostic"); return NO; }
        NSArray *rawFeatures = [diag[@"features"] isKindOfClass:[NSArray class]] ? diag[@"features"] : nil;
        NSDictionary *menu = [diag[@"menu"] isKindOfClass:[NSDictionary class]] ? diag[@"menu"] : nil;
        NSString *menuImage = [menu[@"image"] isKindOfClass:[NSString class]] ? menu[@"image"] : nil;
        if (!rawFeatures.count || !menuImage.length) { HFAIG37Log(@"[IGMM-V2] status=fail reason=diagnostic-shape"); return NO; }

        NSDictionary *damage = nil, *defence = nil, *god = nil;
        NSMutableArray *buttons = [NSMutableArray array];
        NSMutableDictionary<NSString *, NSNumber *> *implCounts = [NSMutableDictionary dictionary];
        NSMutableDictionary<NSString *, NSDictionary *> *implByKey = [NSMutableDictionary dictionary];

        for (NSDictionary *f in rawFeatures) {
            if (![f isKindOfClass:[NSDictionary class]]) continue;
            NSString *type = [f[@"type"] isKindOfClass:[NSString class]] ? f[@"type"] : @"";
            NSString *semantic = HFAIG37SemanticText(f);
            if ([type isEqualToString:@"modtext"] && HFAIG37ContainsAny(semantic, @[@"damage", @"attack"])) damage = f;
            else if ([type isEqualToString:@"modtext"] && HFAIG37ContainsAny(semantic, @[@"defence", @"defense"])) defence = f;
            else if ([type isEqualToString:@"customSwitch"] && HFAIG37ContainsAny(semantic, @[@"god", @"invinc"])) god = f;
            else if ([type isEqualToString:@"button"]) [buttons addObject:f];

            NSDictionary *runtime = [f[@"runtime"] isKindOfClass:[NSDictionary class]] ? f[@"runtime"] : nil;
            NSDictionary *impl = [runtime[@"implementation"] isKindOfClass:[NSDictionary class]] ? runtime[@"implementation"] : nil;
            if ([impl[@"kind"] isEqual:@"nativeIdentifierHandler"] && [impl[@"offset"] isKindOfClass:[NSString class]]) {
                NSString *key = [NSString stringWithFormat:@"%@:%@", impl[@"image"] ?: menuImage, impl[@"offset"]];
                implCounts[key] = @([implCounts[key] unsignedIntegerValue] + 1);
                implByKey[key] = impl;
            }
        }
        if (!damage || !defence || !god) {
            HFAIG37Log(@"[IGMM-V2] status=fail reason=semantic-roles-unresolved damage=%d defence=%d god=%d", !!damage, !!defence, !!god);
            return NO;
        }

        NSString *mainKey = nil;
        NSUInteger bestCount = 0;
        for (NSString *key in implCounts) {
            NSUInteger count = [implCounts[key] unsignedIntegerValue];
            if (count > bestCount) { bestCount = count; mainKey = key; }
        }
        NSDictionary *mainImpl = mainKey ? implByKey[mainKey] : nil;
        if (!mainImpl || bestCount < 3 || ![mainImpl[@"trampoline"] isKindOfClass:[NSDictionary class]] ||
            ![mainImpl[@"registration"] isKindOfClass:[NSDictionary class]]) {
            HFAIG37Log(@"[IGMM-V2] status=fail reason=shared-main-handler-unproven count=%lu", (unsigned long)bestCount);
            return NO;
        }

        NSString *reason = nil;
        NSArray<NSDictionary *> *related = HFAIG37RelatedHooks(menuImage, mainImpl, &reason);
        if (!related) { HFAIG37Log(@"[IGMM-V2] status=fail reason=%@", reason ?: @"hook-chain"); return NO; }

        NSString *targetImage = related.firstObject[@"target"];
        if (!targetImage.length) { HFAIG37Log(@"[IGMM-V2] status=fail reason=target-image"); return NO; }
        NSMutableDictionary *targets = [NSMutableDictionary dictionary];
        targets[targetImage] = @{ @"image": targetImage };
        NSMutableDictionary *identityTargets = [NSMutableDictionary dictionary];
        NSDictionary *targetIdentity = HFAIG37ImageIdentity(targetImage);
        if (!targetIdentity) { HFAIG37Log(@"[IGMM-V2] status=fail reason=target-identity"); return NO; }
        identityTargets[targetImage] = targetIdentity;

        NSMutableArray *hooks = [NSMutableArray array];
        unsigned producerIndex = 0;
        for (NSDictionary *h in related) {
            NSMutableDictionary *hook = [@{
                @"target": h[@"target"], @"offset": h[@"offset"], @"original": h[@"original"],
                @"preexisting": h[@"preexisting"]
            } mutableCopy];
            NSMutableDictionary *evidence = [@{
                @"menuImage": menuImage, @"replacement": h[@"handler"], @"originalSlot": h[@"slot"],
                @"continuation": h[@"continuation"], @"trampolineImage": h[@"trampolineImage"],
                @"trampoline": h[@"trampoline"], @"source": @"live-registration+trampoline"
            } mutableCopy];
            hook[@"evidence"] = evidence;
            if ([h[@"isMain"] boolValue]) {
                hook[@"id"] = @"damage_consumer";
                hook[@"behavior"] = @{
                    @"kind": @"conditionalPipeline", @"subjectRegister": @"x0", @"valueRegister": @"x1",
                    @"protectedStore": @"protectedObjects",
                    @"rules": @[
                        @{ @"when": @{ @"all": @[@"subjectIsProtected", @{ @"state": @"godMode", @"equals": @YES }] },
                           @"do": @[@{ @"kind": @"return" }] },
                        @{ @"when": @{ @"all": @[@"subjectIsProtected", @{ @"state": @"defenceMultiplier", @"notEquals": @1 }] },
                           @"do": @[@{ @"kind": @"divideIntegerArgument", @"register": @"x1", @"state": @"defenceMultiplier" }] },
                        @{ @"when": @{ @"all": @[@"subjectIsNotProtected", @{ @"state": @"damageMultiplier", @"notEquals": @1 }] },
                           @"do": @[@{ @"kind": @"multiplyIntegerArgument", @"register": @"x1", @"state": @"damageMultiplier" }] }
                    ], @"fallback": @"callOriginal"
                };
            } else {
                hook[@"id"] = [NSString stringWithFormat:@"protected_producer_%u", producerIndex++];
                hook[@"behavior"] = @{ @"kind": @"captureFieldPointer", @"baseRegister": @"x0",
                                        @"fieldOffset": h[@"fieldOffset"], @"store": @"protectedObjects" };
            }
            [hooks addObject:hook];
        }

        NSDictionary *damageConfig = [damage[@"config"] isKindOfClass:[NSDictionary class]] ? damage[@"config"] : @{};
        NSDictionary *defenceConfig = [defence[@"config"] isKindOfClass:[NSDictionary class]] ? defence[@"config"] : @{};
        NSNumber *damageDefault = [damageConfig[@"defaultValue"] isKindOfClass:[NSNumber class]] ? damageConfig[@"defaultValue"] : @1;
        NSNumber *defenceDefault = [defenceConfig[@"defaultValue"] isKindOfClass:[NSNumber class]] ? defenceConfig[@"defaultValue"] : @1;
        NSString *damageID = [damage[@"id"] isKindOfClass:[NSString class]] ? damage[@"id"] : @"damage";
        NSString *defenceID = [defence[@"id"] isKindOfClass:[NSString class]] ? defence[@"id"] : @"defence";
        NSString *godID = [god[@"id"] isKindOfClass:[NSString class]] ? god[@"id"] : @"god_mode";
        NSString *damageTitle = [damage[@"title"] isKindOfClass:[NSString class]] ? damage[@"title"] : damageID;
        NSString *defenceTitle = [defence[@"title"] isKindOfClass:[NSString class]] ? defence[@"title"] : defenceID;
        NSString *godTitle = [god[@"title"] isKindOfClass:[NSString class]] ? god[@"title"] : godID;

        NSMutableArray *features = [NSMutableArray arrayWithArray:@[
            @{ @"id": damageID, @"title": damageTitle, @"group": @"Combat",
               @"control": @{ @"kind": @"number", @"valueType": @"float32", @"default": damageDefault },
               @"execution": @{ @"kind": @"runtimeState", @"graph": @"combat_runtime", @"binding": @"damageMultiplier" } },
            @{ @"id": defenceID, @"title": defenceTitle, @"group": @"Combat",
               @"control": @{ @"kind": @"number", @"valueType": @"float32", @"default": defenceDefault },
               @"execution": @{ @"kind": @"runtimeState", @"graph": @"combat_runtime", @"binding": @"defenceMultiplier" } },
            @{ @"id": godID, @"title": godTitle, @"group": @"Combat",
               @"control": @{ @"kind": @"toggle", @"default": @NO },
               @"execution": @{ @"kind": @"runtimeState", @"graph": @"combat_runtime", @"binding": @"godMode" } }
        ]];

        for (NSDictionary *button in buttons) {
            NSDictionary *runtime = [button[@"runtime"] isKindOfClass:[NSDictionary class]] ? button[@"runtime"] : nil;
            NSDictionary *impl = [runtime[@"implementation"] isKindOfClass:[NSDictionary class]] ? runtime[@"implementation"] : nil;
            NSDictionary *target = [impl[@"target"] isKindOfClass:[NSDictionary class]] ? impl[@"target"] : nil;
            NSString *image = [target[@"image"] isKindOfClass:[NSString class]] ? target[@"image"] : nil;
            NSString *offset = [target[@"offset"] isKindOfClass:[NSString class]] ? target[@"offset"] : nil;
            if (!image.length || !offset.length || ![target[@"addressResolved"] boolValue] || [target[@"candidates"] unsignedIntegerValue] != 1) {
                HFAIG37Log(@"[IGMM-V2] status=fail reason=button-target-unresolved title=%@", button[@"title"] ?: @"?");
                return NO;
            }
            int index = HFAIG37ImageIndex(image);
            uint64_t preferred = 0;
            if (index < 0 || !HFAIG37ParseHex(offset, &preferred)) return NO;
            uintptr_t runtimeAddress = (uintptr_t)((intptr_t)preferred + _dyld_get_image_vmaddr_slide((uint32_t)index));
            NSString *original = HFAIG37Hex(runtimeAddress, 4);
            NSDictionary *idn = HFAIG37ImageIdentity(image);
            if (!original.length || !idn) return NO;
            targets[image] = @{ @"image": image };
            identityTargets[image] = idn;
            NSString *fid = [button[@"id"] isKindOfClass:[NSString class]] ? button[@"id"] : [NSString stringWithFormat:@"button_%lu", (unsigned long)features.count];
            NSString *title = [button[@"title"] isKindOfClass:[NSString class]] ? button[@"title"] : fid;
            [features addObject:@{ @"id": fid, @"title": title, @"group": @"Other",
                                   @"control": @{ @"kind": @"button" },
                                   @"execution": @{ @"kind": @"nativeCall", @"target": image, @"offset": offset,
                                                    @"abi": @"void()", @"original": original } }];
        }

        NSBundle *bundle = NSBundle.mainBundle;
        NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
        NSString *shortV = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
        NSString *buildV = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
        NSString *architecture = targetIdentity[@"architecture"] ?: @"arm64";
        NSDictionary *packageMeta = @{ @"bundleIdentifier": bundleID, @"shortVersion": shortV,
                                       @"buildVersion": buildV, @"architectures": @[architecture] };
        NSDictionary *graph = @{
            @"bootstrap": @"once",
            @"state": @{ @"damageMultiplier": @{ @"type": @"float32", @"default": damageDefault },
                           @"defenceMultiplier": @{ @"type": @"float32", @"default": defenceDefault },
                           @"godMode": @{ @"type": @"bool", @"default": @NO } },
            @"stores": @{ @"protectedObjects": @{ @"kind": @"pointerSet", @"maxEntries": @16 } },
            @"hooks": hooks,
            @"evidence": @{ @"sourceDiagnostic": diagPath.lastPathComponent ?: @"",
                             @"resolver": @"igmm-protected-pipeline-v1", @"failClosed": @YES }
        };
        NSDictionary *root = @{ @"schema": @"com.hfa.feature/v2",
                                 @"name": [NSString stringWithFormat:@"%@ %@ auto-generated features", bundleID, shortV],
                                 @"offsetSemantics": @"preferred-mach-o-vmaddr",
                                 @"package": packageMeta, @"targets": targets,
                                 @"runtimeGraphs": @{ @"combat_runtime": graph }, @"features": features };
        NSDictionary *identityPackage = @{ @"bundleIdentifier": bundleID, @"shortVersion": shortV, @"buildVersion": buildV };
        NSDictionary *identity = @{ @"schema": @"com.hfa.patch.identity/v1",
                                     @"offsetSemantics": @"preferred-mach-o-vmaddr",
                                     @"package": identityPackage, @"targets": identityTargets };

        NSString *stem = [HFAIG37SafeStem() stringByAppendingString:@".hfafeature"];
        NSString *packageName = [stem stringByAppendingString:@".json"];
        NSString *identityName = [stem stringByAppendingString:@".identity.json"];
        NSString *packagePath = [HFAIG37Documents() stringByAppendingPathComponent:packageName];
        NSString *identityPath = [HFAIG37Documents() stringByAppendingPathComponent:identityName];
        if (!HFAIG37WriteJSON(root, packagePath) || !HFAIG37WriteJSON(identity, identityPath)) {
            HFAIG37Log(@"[IGMM-V2] status=fail reason=write");
            return NO;
        }
        HFAIG37Log(@"[IGMM-V2] status=pass package=%@ identity=%@ features=%lu hooks=%lu source=%@",
                   packageName, identityName, (unsigned long)features.count, (unsigned long)hooks.count,
                   diagPath.lastPathComponent ?: @"?");
        return YES;
    }
}
