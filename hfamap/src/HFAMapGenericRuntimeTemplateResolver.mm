#import "HFAMapGenericRuntimeTemplateResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <string.h>

namespace {

struct HFASection { uint64_t addr, size, off; std::string sect, seg; };
struct HFAImage {
    NSData *data;
    const uint8_t *bytes;
    uint64_t length;
    uint64_t textBase;
    std::vector<HFASection> text;
    std::vector<HFASection> dataSections;
    std::vector<uint64_t> starts;
};

struct HFAWrapper {
    uint64_t start = 0;
    uint64_t core = 0;
    uint32_t outputLength = 0;
    uint64_t outputVA = 0;
    uint64_t sourceVA = 0;
};

static bool HFAInside(uint64_t off, uint64_t size, uint64_t length) {
    return off <= length && size <= length - off;
}

static uint32_t HFAU32(const uint8_t *p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

static std::string HFAName(const char raw[16]) {
    size_t n = 0;
    while (n < 16 && raw[n]) ++n;
    return std::string(raw, raw + n);
}

static int64_t HFASign(uint64_t value, unsigned bits) {
    const uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static bool HFAParse(NSString *path, HFAImage &image) {
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!data.length || data.length < sizeof(struct mach_header_64)) return false;

    const uint8_t *bytes = (const uint8_t *)data.bytes;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64 ||
        mh->ncmds > 4096 || mh->sizeofcmds > 4U * 1024U * 1024U ||
        !HFAInside(sizeof(*mh), mh->sizeofcmds, data.length)) return false;

    uint32_t startsOff = 0, startsSize = 0;
    const uint8_t *cursor = bytes + sizeof(*mh), *end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) return false;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return false;

        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize)
                return false;
            if (HFAName(seg->segname) == "__TEXT") image.textBase = seg->vmaddr;

            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; ++s) {
                HFASection sec = {
                    sects[s].addr, sects[s].size, sects[s].offset,
                    HFAName(sects[s].sectname), HFAName(sects[s].segname)
                };
                if (sec.sect == "__text" && HFAInside(sec.off, sec.size, data.length))
                    image.text.push_back(sec);
                if ((sec.seg == "__DATA" || sec.seg == "__DATA_CONST" ||
                     sec.seg == "__AUTH" || sec.seg == "__AUTH_CONST" ||
                     sec.seg == "__TEXT") &&
                    HFAInside(sec.off, sec.size, data.length))
                    image.dataSections.push_back(sec);
            }
        } else if (lc->cmd == LC_FUNCTION_STARTS &&
                   lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)cursor;
            startsOff = cmd->dataoff;
            startsSize = cmd->datasize;
        }
        cursor += lc->cmdsize;
    }

    if (image.text.empty()) return false;

    if (startsSize && HFAInside(startsOff, startsSize, data.length)) {
        const uint8_t *p = bytes + startsOff, *limit = p + startsSize;
        uint64_t address = image.textBase;
        while (p < limit && image.starts.size() < 100000) {
            uint64_t delta = 0;
            unsigned shift = 0;
            bool done = false;
            while (p < limit && shift < 64) {
                uint8_t b = *p++;
                delta |= (uint64_t)(b & 0x7fU) << shift;
                if (!(b & 0x80U)) { done = true; break; }
                shift += 7;
            }
            if (!done || !delta || UINT64_MAX - address < delta) break;
            address += delta;
            image.starts.push_back(address);
        }
    }

    image.data = data;
    image.bytes = bytes;
    image.length = data.length;
    return true;
}

static bool HFAOffset(const HFAImage &image, uint64_t address,
                      uint64_t *out, const HFASection **sectionOut) {
    for (const HFASection &sec : image.text) {
        if (address < sec.addr || address - sec.addr >= sec.size) continue;
        uint64_t off = sec.off + (address - sec.addr);
        if (!HFAInside(off, 4, image.length)) return false;
        if (out) *out = off;
        if (sectionOut) *sectionOut = &sec;
        return true;
    }
    return false;
}

static uint64_t HFAFunctionEnd(const HFAImage &image, uint64_t address) {
    if (!image.starts.empty()) {
        auto upper = std::upper_bound(image.starts.begin(), image.starts.end(), address);
        if (upper != image.starts.end()) return *upper;
    }
    return address + 0x100;
}

static bool HFADecodeBL(uint32_t insn, uint64_t pc, uint64_t *targetOut) {
    if ((insn & 0xFC000000U) != 0x94000000U) return false;
    int64_t imm = HFASign(insn & 0x03FFFFFFU, 26) << 2;
    if (targetOut) *targetOut = (uint64_t)((int64_t)pc + imm);
    return true;
}

static bool HFADecodeADRP(uint32_t insn, uint64_t pc, uint64_t *pageOut, unsigned *regOut) {
    if ((insn & 0x9F000000U) != 0x90000000U) return false;
    uint64_t imm = (((uint64_t)insn >> 5U) & 0x7FFFFU) << 2U;
    imm |= ((uint64_t)insn >> 29U) & 3U;
    if (pageOut)
        *pageOut = (uint64_t)((int64_t)(pc & ~0xFFFULL) + (HFASign(imm, 21) << 12));
    if (regOut) *regOut = insn & 31U;
    return true;
}

static bool HFADecodeADD(uint32_t insn, unsigned rn, uint64_t base,
                         uint64_t *valueOut, unsigned *rdOut) {
    if ((insn & 0xFF000000U) != 0x91000000U) return false;
    if (((insn >> 5U) & 31U) != rn) return false;
    uint64_t imm = (insn >> 10U) & 0xFFFU;
    if ((insn >> 22U) & 1U) imm <<= 12;
    if (valueOut) *valueOut = base + imm;
    if (rdOut) *rdOut = insn & 31U;
    return true;
}

static bool HFADecodeMOVW2Imm(uint32_t insn, uint32_t *valueOut) {
    // MOVZ W2,#imm16
    if ((insn & 0xFFE0001FU) != 0x52800002U) return false;
    if (valueOut) *valueOut = (insn >> 5U) & 0xFFFFU;
    return true;
}

static bool HFADataAddress(const HFAImage &image, uint64_t address) {
    for (const HFASection &sec : image.dataSections) {
        if (address >= sec.addr && address - sec.addr < sec.size) return true;
    }
    return false;
}

static bool HFAResolveRegisterAddress(const HFAImage &image,
                                      const HFASection &sec,
                                      uint64_t windowStart,
                                      uint64_t callsite,
                                      unsigned wantedReg,
                                      uint64_t *valueOut) {
    uint64_t pages[32] = {};
    bool pageSet[32] = {};
    uint64_t values[32] = {};
    bool valueSet[32] = {};

    for (uint64_t pc = windowStart; pc < callsite; pc += 4) {
        uint64_t off = sec.off + (pc - sec.addr);
        if (!HFAInside(off, 4, image.length)) continue;
        uint32_t w = HFAU32(image.bytes + off);

        uint64_t page = 0;
        unsigned reg = 0;
        if (HFADecodeADRP(w, pc, &page, &reg)) {
            pages[reg] = page;
            pageSet[reg] = true;
            valueSet[reg] = false;
            continue;
        }

        for (unsigned rn = 0; rn < 32; ++rn) {
            if (!pageSet[rn]) continue;
            uint64_t value = 0;
            unsigned rd = 0;
            if (!HFADecodeADD(w, rn, pages[rn], &value, &rd)) continue;
            values[rd] = value;
            valueSet[rd] = true;
            break;
        }
    }

    if (!valueSet[wantedReg]) return false;
    if (valueOut) *valueOut = values[wantedReg];
    return true;
}

static std::vector<HFAWrapper> HFAFindWrappers(const HFAImage &image) {
    std::vector<HFAWrapper> raw;
    std::map<uint64_t, NSUInteger> coreCounts;

    for (uint64_t start : image.starts) {
        uint64_t end = HFAFunctionEnd(image, start);
        if (end <= start || end - start > 0x140) continue;

        uint64_t fileOff = 0;
        const HFASection *section = nullptr;
        if (!HFAOffset(image, start, &fileOff, &section)) continue;

        uint64_t core = 0;
        uint32_t length = 0;
        for (uint64_t pc = start; pc + 4 <= end; pc += 4) {
            uint64_t off = section->off + (pc - section->addr);
            if (!HFAInside(off, 4, image.length)) break;
            uint32_t w = HFAU32(image.bytes + off);

            uint64_t target = 0;
            if (HFADecodeBL(w, pc, &target)) core = target;

            uint32_t imm = 0;
            if (HFADecodeMOVW2Imm(w, &imm) && imm > 0 && imm <= 1024)
                length = imm;
        }

        if (!core || !length) continue;

        // Recover X0/X1 at the wrapper's decrypt-core callsite.
        for (uint64_t pc = start; pc + 4 <= end; pc += 4) {
            uint64_t off = section->off + (pc - section->addr);
            if (!HFAInside(off, 4, image.length)) break;
            uint64_t target = 0;
            if (!HFADecodeBL(HFAU32(image.bytes + off), pc, &target) || target != core)
                continue;

            uint64_t windowStart = pc >= 0x30 ? pc - 0x30 : start;
            if (windowStart < start) windowStart = start;

            uint64_t x0 = 0, x1 = 0;
            bool ok0 = HFAResolveRegisterAddress(image, *section, windowStart, pc, 0, &x0);
            bool ok1 = HFAResolveRegisterAddress(image, *section, windowStart, pc, 1, &x1);
            if (!ok0 || !ok1) continue;
            if (!HFADataAddress(image, x0) || !HFADataAddress(image, x1)) continue;

            raw.push_back({start, core, length, x0, x1});
            coreCounts[core]++;
            break;
        }
    }

    std::vector<HFAWrapper> filtered;
    for (const HFAWrapper &w : raw) {
        if (coreCounts[w.core] >= 2) filtered.push_back(w);
    }
    return filtered;
}

static const struct mach_header_64 *HFALoadedImage(NSString *name, NSString *path) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *loadedPath = [NSString stringWithUTF8String:raw] ?: @"";
        BOOL match = (name.length && [loadedPath.lastPathComponent isEqualToString:name]) ||
                     (path.length && [loadedPath isEqualToString:path]);
        if (!match) continue;
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (header && header->magic == MH_MAGIC_64) return header;
    }
    return nullptr;
}

static BOOL HFARead(uintptr_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)buffer,
                                         &copied);
    return kr == KERN_SUCCESS && copied == (vm_size_t)size;
}

static NSString *HFAPlaintext(const uint8_t *bytes, size_t capacity) {
    if (!bytes || !capacity) return nil;
    size_t len = 0;
    NSUInteger printable = 0;
    while (len < capacity && bytes[len]) {
        uint8_t c = bytes[len];
        BOOL ok = (c >= 0x20 && c <= 0x7E) || c == 0x0A || c == 0x0D || c == 0x09;
        if (!ok) return nil;
        ++printable;
        ++len;
    }
    if (!len || len >= capacity) return nil;
    if (printable * 100 / len < 95) return nil;
    return [[[NSString alloc] initWithBytes:bytes
                                    length:len
                                  encoding:NSUTF8StringEncoding] autorelease];
}

static NSInteger HFALuaScore(NSString *text) {
    if (!text.length) return 0;
    NSString *l = text.lowercaseString;
    NSInteger score = 0;
    for (NSString *token in @[@"function", @"local ", @"return ", @"true", @"false",
                               @"require", @"_g", @"(", @")", @"=", @".", @":"]) {
        if ([l containsString:token]) ++score;
    }
    return score;
}

} // namespace

NSDictionary *HFAMapResolveGenericRuntimeTemplates(NSDictionary *candidate,
                                                   NSTimeInterval deadline) {
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : nil;
    NSString *image = [candidate[@"image"] isKindOfClass:NSString.class] ?
                        candidate[@"image"] : path.lastPathComponent;

    HFAImage parsed = {};
    if (!path.length || !HFAParse(path, parsed)) {
        return @{@"schema": @"com.hfa.generic-runtime-template/v1",
                 @"status": @"parse-failed", @"records": @[],
                 @"analysisOnly": @YES, @"memoryWritten": @NO};
    }

    const struct mach_header_64 *loaded = HFALoadedImage(image, path);
    if (!loaded) {
        return @{@"schema": @"com.hfa.generic-runtime-template/v1",
                 @"status": @"menu-not-loaded", @"records": @[],
                 @"analysisOnly": @YES, @"memoryWritten": @NO};
    }

    std::vector<HFAWrapper> wrappers = HFAFindWrappers(parsed);
    NSMutableArray *records = [NSMutableArray array];
    NSUInteger resolved = 0;

    for (const HFAWrapper &w : wrappers) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        if (w.outputVA < parsed.textBase) continue;

        uintptr_t runtimeOutput =
            (uintptr_t)loaded + (uintptr_t)(w.outputVA - parsed.textBase);

        size_t want = (size_t)w.outputLength + 1;
        if (want > 4097) continue;

        std::vector<uint8_t> buffer(want, 0);
        BOOL readable = HFARead(runtimeOutput, buffer.data(), want);
        NSString *plain = readable ? HFAPlaintext(buffer.data(), want) : nil;

        NSMutableDictionary *record = [@{
            @"wrapperRVA": [NSString stringWithFormat:@"0x%llX",
                            (unsigned long long)w.start],
            @"coreRVA": [NSString stringWithFormat:@"0x%llX",
                         (unsigned long long)w.core],
            @"outputRVA": [NSString stringWithFormat:@"0x%llX",
                           (unsigned long long)w.outputVA],
            @"sourceRVA": [NSString stringWithFormat:@"0x%llX",
                           (unsigned long long)w.sourceVA],
            @"declaredLength": @(w.outputLength),
            @"runtimeOutputReadable": @(readable),
            @"unknownCodeInvoked": @NO,
            @"memoryWritten": @NO
        } mutableCopy];

        if (plain.length) {
            record[@"plaintext"] = plain;
            record[@"luaScore"] = @(HFALuaScore(plain));
            record[@"status"] = @"plaintext-recovered";
            ++resolved;
        } else {
            record[@"status"] = readable ? @"runtime-buffer-not-plaintext" :
                                           @"runtime-buffer-unreadable";
        }
        [records addObject:record];
        [record release];
    }

    NSDictionary *result = @{
        @"schema": @"com.hfa.generic-runtime-template/v1",
        @"status": NSDate.date.timeIntervalSince1970 > deadline ? @"timeout" : @"complete",
        @"menuImage": image ?: @"",
        @"wrapperCount": @(wrappers.size()),
        @"plaintextResolvedCount": @(resolved),
        @"records": records,
        @"analysisOnly": @YES,
        @"unknownCodeInvoked": @NO,
        @"memoryWritten": @NO,
        @"policy": @"generic-arm64-wrapper-core-discovery+read-only-natural-runtime-plaintext+fail-closed"
    };

    NSData *data = [NSJSONSerialization dataWithJSONObject:result
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:nil];
    [data writeToFile:[HFAOutputDirectoryPath()
        stringByAppendingPathComponent:HFAOutputFileName(@"RuntimeTemplates.json")]
               options:NSDataWritingAtomic
                 error:nil];

    HFADiagnosticsLog(@"generic-runtime-template", result[@"status"], @{
        @"wrapperCount": result[@"wrapperCount"] ?: @0,
        @"plaintextResolvedCount": result[@"plaintextResolvedCount"] ?: @0
    });

    return result;
}
