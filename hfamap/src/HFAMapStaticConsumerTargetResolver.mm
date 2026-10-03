#import "HFAMapStaticConsumerTargetResolver.h"

#import <mach-o/loader.h>
#import <mach/machine.h>
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

struct HFASection {
    uint64_t addr;
    uint64_t size;
    uint64_t off;
    std::string name;
};

struct HFAImage {
    NSData *data;
    const uint8_t *bytes;
    uint64_t length;
    uint64_t textBase;
    std::vector<HFASection> text;
    std::vector<HFASection> cstrings;
    std::vector<HFASection> cfstrings;
    std::vector<uint64_t> starts;
};

static bool HFAInside(uint64_t off, uint64_t size, uint64_t length) {
    return off <= length && size <= length - off;
}

static uint32_t HFAU32(const uint8_t *p) {
    uint32_t v = 0; memcpy(&v, p, sizeof(v)); return v;
}

static uint64_t HFAU64(const uint8_t *p) {
    uint64_t v = 0; memcpy(&v, p, sizeof(v)); return v;
}

static std::string HFAName(const char raw[16]) {
    size_t n = 0; while (n < 16 && raw[n]) ++n;
    return std::string(raw, raw + n);
}

static int64_t HFASign(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static bool HFAParse(NSString *path, HFAImage &image, NSString **reason) {
    NSDictionary *a = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    uint64_t size = [a[NSFileSize] unsignedLongLongValue];
    if (!size || size > 128ULL * 1024ULL * 1024ULL) {
        if (reason) *reason = @"menu-file-size-out-of-bounds"; return false;
    }
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (data.length != size || data.length < sizeof(struct mach_header_64)) {
        if (reason) *reason = @"menu-file-read-failed"; return false;
    }
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)bytes;
    if (mh->magic != MH_MAGIC_64 || mh->cputype != CPU_TYPE_ARM64 ||
        mh->ncmds > 4096 || mh->sizeofcmds > 4U * 1024U * 1024U ||
        !HFAInside(sizeof(*mh), mh->sizeofcmds, data.length)) {
        if (reason) *reason = @"unsupported-menu-mach-o"; return false;
    }

    uint32_t startsOff = 0, startsSize = 0;
    const uint8_t *cursor = bytes + sizeof(*mh);
    const uint8_t *end = cursor + mh->sizeofcmds;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (cursor + sizeof(struct load_command) > end) return false;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return false;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize) return false;
            if (HFAName(seg->segname) == "__TEXT") image.textBase = seg->vmaddr;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects; ++s) {
                if (!HFAInside(sects[s].offset, sects[s].size, data.length)) continue;
                HFASection sec = { sects[s].addr, sects[s].size, sects[s].offset, HFAName(sects[s].sectname) };
                if (sec.name == "__text") image.text.push_back(sec);
                else if (sec.name == "__cstring") image.cstrings.push_back(sec);
                else if (sec.name == "__cfstring") image.cfstrings.push_back(sec);
            }
        } else if (lc->cmd == LC_FUNCTION_STARTS &&
                   lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)cursor;
            startsOff = cmd->dataoff; startsSize = cmd->datasize;
        }
        cursor += lc->cmdsize;
    }
    if (image.text.empty() || image.cstrings.empty()) {
        if (reason) *reason = @"required-sections-missing"; return false;
    }

    if (startsSize && HFAInside(startsOff, startsSize, data.length)) {
        const uint8_t *p = bytes + startsOff, *limit = p + startsSize;
        uint64_t address = image.textBase;
        while (p < limit && image.starts.size() < 100000) {
            uint64_t delta = 0; unsigned shift = 0; bool done = false;
            while (p < limit && shift < 64) {
                uint8_t b = *p++;
                delta |= (uint64_t)(b & 0x7fU) << shift;
                if (!(b & 0x80U)) { done = true; break; }
                shift += 7;
            }
            if (!done || !delta || UINT64_MAX - address < delta) break;
            address += delta; image.starts.push_back(address);
        }
    }
    image.data = data; image.bytes = bytes; image.length = data.length;
    return true;
}

static std::vector<uint64_t> HFAStrings(const HFAImage &image, NSString *text) {
    std::vector<uint64_t> out;
    NSData *needleData = [text dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *needle = (const uint8_t *)needleData.bytes;
    size_t n = needleData.length;
    if (!n || n > 128) return out;
    for (const HFASection &sec : image.cstrings) {
        const uint8_t *p = image.bytes + sec.off;
        for (uint64_t i = 0; i + n < sec.size; ++i) {
            if ((i && p[i - 1] != 0) || p[i + n] != 0) continue;
            if (!memcmp(p + i, needle, n)) out.push_back(sec.addr + i);
        }
    }
    return out;
}

static std::vector<uint64_t> HFACFStrings(const HFAImage &image, uint64_t stringAddr,
                                           NSUInteger length) {
    std::vector<uint64_t> out;
    for (const HFASection &sec : image.cfstrings) {
        for (uint64_t i = 0; i + 32 <= sec.size; i += 8) {
            const uint8_t *r = image.bytes + sec.off + i;
            if (HFAU64(r + 16) == stringAddr && HFAU64(r + 24) == length)
                out.push_back(sec.addr + i);
        }
    }
    return out;
}

static bool HFAADR(uint32_t w, uint64_t pc, uint64_t *target, unsigned *reg) {
    if ((w & 0x9f000000U) != 0x10000000U) return false;
    uint64_t imm = (((uint64_t)w >> 5U) & 0x7ffffU) << 2U;
    imm |= ((uint64_t)w >> 29U) & 3U;
    if (target) *target = (uint64_t)((int64_t)pc + HFASign(imm, 21));
    if (reg) *reg = w & 31U;
    return true;
}

static bool HFAADRP(uint32_t w, uint64_t pc, uint64_t *page, unsigned *reg) {
    if ((w & 0x9f000000U) != 0x90000000U) return false;
    uint64_t imm = (((uint64_t)w >> 5U) & 0x7ffffU) << 2U;
    imm |= ((uint64_t)w >> 29U) & 3U;
    if (page) *page = (uint64_t)((int64_t)(pc & ~0xfffULL) + (HFASign(imm, 21) << 12));
    if (reg) *reg = w & 31U;
    return true;
}

static bool HFAAddImm(uint32_t w, unsigned expected, uint64_t *imm) {
    if ((w & 0xff000000U) != 0x91000000U) return false;
    unsigned rd = w & 31U, rn = (w >> 5U) & 31U;
    if (rd != expected || rn != expected) return false;
    uint64_t v = (w >> 10U) & 0xfffU;
    if ((w >> 22U) & 1U) v <<= 12;
    if (imm) *imm = v;
    return true;
}

static std::vector<uint64_t> HFARefs(const HFAImage &image, const std::set<uint64_t> &targets) {
    std::vector<uint64_t> out;
    for (const HFASection &sec : image.text) {
        for (uint64_t i = 0; i + 4 <= sec.size; i += 4) {
            uint64_t pc = sec.addr + i;
            const uint8_t *raw = image.bytes + sec.off + i;
            uint32_t w = HFAU32(raw);
            uint64_t target = 0; unsigned reg = 0;
            if (HFAADR(w, pc, &target, &reg) && targets.count(target)) {
                out.push_back(pc); continue;
            }
            uint64_t page = 0;
            if (!HFAADRP(w, pc, &page, &reg)) continue;
            for (unsigned k = 1; k <= 3 && i + k * 4 + 4 <= sec.size; ++k) {
                uint64_t add = 0;
                if (HFAAddImm(HFAU32(raw + k * 4), reg, &add) && targets.count(page + add)) {
                    out.push_back(pc); break;
                }
            }
        }
    }
    return out;
}

static void HFAFunction(const HFAImage &image, uint64_t address,
                        uint64_t *startOut, uint64_t *endOut) {
    uint64_t start = address > 0x100 ? address - 0x100 : 0;
    uint64_t end = address + 0x100;
    if (!image.starts.empty()) {
        auto upper = std::upper_bound(image.starts.begin(), image.starts.end(), address);
        if (upper != image.starts.begin()) start = *(upper - 1);
        if (upper != image.starts.end()) end = *upper;
    }
    if (end <= start || end - start > 0x10000) end = start + 0x1000;
    if (startOut) *startOut = start; if (endOut) *endOut = end;
}

static bool HFAOffset(const HFAImage &image, uint64_t address, uint64_t *out,
                      const HFASection **sectionOut) {
    for (const HFASection &sec : image.text) {
        if (address < sec.addr || address - sec.addr >= sec.size) continue;
        uint64_t off = sec.off + (address - sec.addr);
        if (!HFAInside(off, 4, image.length)) return false;
        if (out) *out = off; if (sectionOut) *sectionOut = &sec;
        return true;
    }
    return false;
}

static NSDictionary *HFASemantics(const HFAImage &image, uint64_t start, uint64_t end) {
    uint64_t off = 0; const HFASection *sec = NULL;
    if (!HFAOffset(image, start, &off, &sec)) return @{};
    uint64_t limit = std::min(end, start + 0x2000ULL);
    NSUInteger fmul = 0, fdiv = 0, rets = 0, conditionals = 0, scvtf = 0, fcvtzs = 0;
    for (uint64_t pc = start; pc + 4 <= limit; pc += 4) {
        uint64_t p = sec->off + (pc - sec->addr);
        if (!HFAInside(p, 4, image.length)) break;
        uint32_t w = HFAU32(image.bytes + p);
        uint32_t fp = w & 0xFFE0FC00U;
        if (fp == 0x1E600800U || fp == 0x1E200800U) ++fmul;
        if (fp == 0x1E601800U || fp == 0x1E201800U) ++fdiv;
        if (w == 0xD65F03C0U) ++rets;
        if ((w & 0x7E000000U) == 0x34000000U ||
            (w & 0xFF000010U) == 0x54000000U ||
            (w & 0x7E000000U) == 0x36000000U) ++conditionals;
        if ((w & 0xFF20FC00U) == 0x9E620000U || (w & 0xFF20FC00U) == 0x1E220000U) ++scvtf;
        if ((w & 0xFF20FC00U) == 0x9E780000U || (w & 0xFF20FC00U) == 0x1E380000U) ++fcvtzs;
    }
    NSMutableArray *ops = [NSMutableArray array];
    if (fmul) [ops addObject:@"multiply"];
    if (fdiv) [ops addObject:@"divide"];
    if (rets > 1 && conditionals) [ops addObject:@"conditional-early-return"];
    return @{ @"floatMultiplyCount": @(fmul), @"floatDivideCount": @(fdiv),
              @"returnCount": @(rets), @"conditionalBranchCount": @(conditionals),
              @"signedIntToFloatCount": @(scvtf), @"floatToSignedIntCount": @(fcvtzs),
              @"operationCandidates": ops };
}

} // namespace

NSDictionary *HFAMapResolveStaticNativeConsumers(NSDictionary *candidate,
                                                  NSArray<NSDictionary *> *registry,
                                                  NSTimeInterval deadline) {
    NSTimeInterval started = NSDate.date.timeIntervalSince1970;
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : nil;
    if (!path.length || !registry.count)
        return @{ @"schema": @"com.hfa.static-native-consumer/v1",
                  @"status": @"not-applicable", @"groups": @[], @"featureLinks": @[] };

    HFAImage image = {};
    NSString *reason = nil;
    if (!HFAParse(path, image, &reason))
        return @{ @"schema": @"com.hfa.static-native-consumer/v1",
                  @"status": reason ?: @"parse-failed", @"groups": @[], @"featureLinks": @[] };

    NSMutableDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *byFunction = [NSMutableDictionary dictionary];
    NSMutableArray *featureLinks = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];

    for (NSDictionary *record in registry) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        NSString *identifier = [record[@"identifier"] isKindOfClass:NSString.class] ? record[@"identifier"] : nil;
        if (!identifier.length || identifier.length > 128 || [seen containsObject:identifier]) continue;
        [seen addObject:identifier];

        std::vector<uint64_t> strings = HFAStrings(image, identifier);
        std::set<uint64_t> targets;
        for (uint64_t s : strings) {
            targets.insert(s);
            std::vector<uint64_t> cfs = HFACFStrings(image, s,
                [identifier lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
            targets.insert(cfs.begin(), cfs.end());
        }
        if (targets.empty()) continue;
        std::vector<uint64_t> refs = HFARefs(image, targets);
        NSMutableSet *functionsForFeature = [NSMutableSet set];
        for (uint64_t ref : refs) {
            uint64_t start = 0, end = 0; HFAFunction(image, ref, &start, &end);
            if (!start || [functionsForFeature containsObject:@(start)]) continue;
            [functionsForFeature addObject:@(start)];
            NSMutableArray *records = byFunction[@(start)];
            if (!records) { records = [NSMutableArray array]; byFunction[@(start)] = records; }
            [records addObject:@{ @"name": record[@"name"] ?: identifier,
                                  @"identifier": identifier,
                                  @"referenceRVA": [NSString stringWithFormat:@"0x%llX", ref] }];
            [featureLinks addObject:@{ @"name": record[@"name"] ?: identifier,
                                       @"identifier": identifier,
                                       @"consumerRVA": [NSString stringWithFormat:@"0x%llX", start],
                                       @"identifierReferenceRVA": [NSString stringWithFormat:@"0x%llX", ref] }];
        }
    }

    NSMutableArray *groups = [NSMutableArray array];
    for (NSNumber *key in byFunction) {
        NSArray *records = byFunction[key];
        NSMutableSet *identifiers = [NSMutableSet set];
        for (NSDictionary *r in records) [identifiers addObject:r[@"identifier"] ?: @""];
        if (identifiers.count < 2) continue;
        uint64_t start = key.unsignedLongLongValue, end = 0;
        HFAFunction(image, start, NULL, &end);
        [groups addObject:@{
            @"classification": @"shared-native-consumer",
            @"consumerRVA": [NSString stringWithFormat:@"0x%llX", start],
            @"consumerRVAValue": @(start),
            @"featureCount": @(identifiers.count),
            @"features": records,
            @"semantics": HFASemantics(image, start, end),
            @"evidence": @[@"exact-feature-identifier", @"static-text-xref",
                            @"same-native-function-boundary"],
            @"analysisOnly": @YES,
            @"memoryWritten": @NO,
            @"selectorInvoked": @NO,
            @"blockInvoked": @NO
        }];
    }

    [groups sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        uint64_t av = [a[@"consumerRVAValue"] unsignedLongLongValue];
        uint64_t bv = [b[@"consumerRVAValue"] unsignedLongLongValue];
        return av < bv ? NSOrderedAscending : (av > bv ? NSOrderedDescending : NSOrderedSame);
    }];

    BOOL timeout = NSDate.date.timeIntervalSince1970 > deadline;
    return @{ @"schema": @"com.hfa.static-native-consumer/v1",
              @"status": timeout ? @"timeout" : (groups.count ? @"resolved" : @"no-shared-consumer"),
              @"menuImage": candidate[@"image"] ?: path.lastPathComponent ?: @"",
              @"groups": groups,
              @"groupCount": @(groups.count),
              @"featureLinks": featureLinks,
              @"featureLinkCount": @(featureLinks.count),
              @"policy": @"exact-identifier-xref-function-grouping-read-only-no-fixed-rva",
              @"metrics": @{ @"elapsedMs": @((NSDate.date.timeIntervalSince1970 - started) * 1000.0),
                              @"identifiers": @(seen.count) } };
}
