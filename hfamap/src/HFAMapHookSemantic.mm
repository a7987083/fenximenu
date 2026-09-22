#import "HFAMapHookSemantic.h"

#import <mach-o/loader.h>
#import <mach/machine.h>
#import <mach/mach.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

static const uint64_t kHFAMaxMenuFileBytes = 64ULL * 1024ULL * 1024ULL;
static const uint64_t kHFAMaxExecutableBytes = 384ULL * 1024ULL * 1024ULL;
static const uint64_t kHFAMaxExecutableSegmentBytes = 192ULL * 1024ULL * 1024ULL;
static const vm_size_t kHFAScanChunkBytes = 1024U * 1024U;
static const NSUInteger kHFAMaxSemanticMappings = 32;
static const NSUInteger kHFAMaxCandidatesPerField = 32;
static const uint64_t kHFAMaxSharedCallbackTargetSpan = 0x8000ULL;

struct HFAFileSection {
    uint64_t address;
    uint64_t size;
    uint64_t offset;
    std::string segment;
    std::string section;
};

struct HFAMenuImage {
    NSData *data;
    const uint8_t *bytes;
    uint64_t length;
    uint64_t textVMAddress;
    std::vector<HFAFileSection> textSections;
    std::vector<HFAFileSection> cstringSections;
    std::vector<HFAFileSection> cfstringSections;
    std::vector<uint64_t> functionStarts;
};

static bool HFARangeInside(uint64_t offset, uint64_t size, uint64_t length) {
    return offset <= length && size <= length - offset;
}

static std::string HFAFixedName(const char raw[16]) {
    size_t length = 0;
    while (length < 16 && raw[length]) ++length;
    return std::string(raw, raw + length);
}

static uint32_t HFAReadU32(const uint8_t *bytes) {
    uint32_t value = 0;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static uint64_t HFAReadU64(const uint8_t *bytes) {
    uint64_t value = 0;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static bool HFAParseMenuImage(NSString *path, HFAMenuImage &image, NSString **reason) {
    NSDictionary *attributes = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    uint64_t fileSize = [attributes[NSFileSize] unsignedLongLongValue];
    if (!fileSize || fileSize > kHFAMaxMenuFileBytes) {
        if (reason) *reason = @"menu-file-size-out-of-bounds";
        return false;
    }
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (data.length != fileSize || data.length < sizeof(struct mach_header_64)) {
        if (reason) *reason = @"menu-file-read-failed";
        return false;
    }
    const uint8_t *bytes = static_cast<const uint8_t *>(data.bytes);
    const struct mach_header_64 *header = reinterpret_cast<const struct mach_header_64 *>(bytes);
    if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_ARM64 ||
        header->ncmds > 4096 || header->sizeofcmds > 4U * 1024U * 1024U ||
        !HFARangeInside(sizeof(*header), header->sizeofcmds, data.length)) {
        if (reason) *reason = @"unsupported-or-invalid-menu-mach-o";
        return false;
    }

    uint32_t functionDataOffset = 0, functionDataSize = 0;
    const uint8_t *cursor = bytes + sizeof(*header);
    const uint8_t *commandEnd = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if (cursor + sizeof(struct load_command) > commandEnd) {
            if (reason) *reason = @"truncated-menu-load-command";
            return false;
        }
        const struct load_command *command = reinterpret_cast<const struct load_command *>(cursor);
        if (command->cmdsize < sizeof(*command) || cursor + command->cmdsize > commandEnd) {
            if (reason) *reason = @"invalid-menu-load-command-size";
            return false;
        }
        if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment =
                reinterpret_cast<const struct segment_command_64 *>(cursor);
            uint64_t sectionBytes = (uint64_t)segment->nsects * sizeof(struct section_64);
            if (sizeof(*segment) + sectionBytes > command->cmdsize) {
                if (reason) *reason = @"invalid-menu-section-table";
                return false;
            }
            std::string segmentName = HFAFixedName(segment->segname);
            if (segmentName == "__TEXT") image.textVMAddress = segment->vmaddr;
            const struct section_64 *sections = reinterpret_cast<const struct section_64 *>(segment + 1);
            for (uint32_t s = 0; s < segment->nsects; ++s) {
                if (!HFARangeInside(sections[s].offset, sections[s].size, data.length)) continue;
                HFAFileSection entry = { sections[s].addr, sections[s].size, sections[s].offset,
                                         HFAFixedName(sections[s].segname),
                                         HFAFixedName(sections[s].sectname) };
                if (entry.section == "__text") image.textSections.push_back(entry);
                else if (entry.section == "__cstring") image.cstringSections.push_back(entry);
                else if (entry.section == "__cfstring") image.cfstringSections.push_back(entry);
            }
        } else if (command->cmd == LC_FUNCTION_STARTS &&
                   command->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *starts =
                reinterpret_cast<const struct linkedit_data_command *>(cursor);
            functionDataOffset = starts->dataoff;
            functionDataSize = starts->datasize;
        }
        cursor += command->cmdsize;
    }
    if (image.textSections.empty() || image.cstringSections.empty()) {
        if (reason) *reason = @"required-menu-sections-missing";
        return false;
    }

    if (functionDataSize && HFARangeInside(functionDataOffset, functionDataSize, data.length)) {
        const uint8_t *p = bytes + functionDataOffset;
        const uint8_t *end = p + functionDataSize;
        uint64_t address = image.textVMAddress;
        while (p < end && image.functionStarts.size() < 100000) {
            uint64_t delta = 0;
            unsigned shift = 0;
            bool terminated = false;
            while (p < end && shift < 64) {
                uint8_t byte = *p++;
                delta |= (uint64_t)(byte & 0x7fU) << shift;
                if (!(byte & 0x80U)) { terminated = true; break; }
                shift += 7;
            }
            if (!terminated || !delta || UINT64_MAX - address < delta) break;
            address += delta;
            image.functionStarts.push_back(address);
        }
    }
    image.data = data;
    image.bytes = bytes;
    image.length = data.length;
    return true;
}

static bool HFAAddressToFileOffset(const HFAMenuImage &image, uint64_t address,
                                   uint64_t *offsetOut, const HFAFileSection **sectionOut) {
    for (const HFAFileSection &section : image.textSections) {
        if (address < section.address || address - section.address >= section.size) continue;
        uint64_t offset = section.offset + (address - section.address);
        if (!HFARangeInside(offset, 4, image.length)) return false;
        if (offsetOut) *offsetOut = offset;
        if (sectionOut) *sectionOut = &section;
        return true;
    }
    return false;
}

static std::vector<uint64_t> HFAExactCStringAddresses(const HFAMenuImage &image,
                                                       NSString *text) {
    std::vector<uint64_t> result;
    NSData *needleData = [text dataUsingEncoding:NSUTF8StringEncoding];
    const uint8_t *needle = static_cast<const uint8_t *>(needleData.bytes);
    size_t length = needleData.length;
    if (!length || length > 128) return result;
    for (const HFAFileSection &section : image.cstringSections) {
        const uint8_t *start = image.bytes + section.offset;
        for (uint64_t index = 0; index + length < section.size; ++index) {
            if ((index && start[index - 1] != 0) || start[index + length] != 0) continue;
            if (memcmp(start + index, needle, length) != 0) continue;
            result.push_back(section.address + index);
        }
    }
    return result;
}

static std::vector<uint64_t> HFACFStringAddresses(const HFAMenuImage &image,
                                                   uint64_t stringAddress,
                                                   NSUInteger stringLength) {
    std::vector<uint64_t> result;
    for (const HFAFileSection &section : image.cfstringSections) {
        for (uint64_t index = 0; index + 32 <= section.size; index += 8) {
            const uint8_t *record = image.bytes + section.offset + index;
            if (HFAReadU64(record + 16) != stringAddress ||
                HFAReadU64(record + 24) != stringLength) continue;
            result.push_back(section.address + index);
        }
    }
    return result;
}

static int64_t HFASignExtend(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static bool HFADecodeADR(uint32_t word, uint64_t pc, uint64_t *target, unsigned *reg) {
    if ((word & 0x9f000000U) != 0x10000000U) return false;
    uint64_t immediate = (((uint64_t)word >> 5U) & 0x7ffffU) << 2U;
    immediate |= ((uint64_t)word >> 29U) & 3U;
    if (target) *target = (uint64_t)((int64_t)pc + HFASignExtend(immediate, 21));
    if (reg) *reg = word & 31U;
    return true;
}

static bool HFADecodeADRP(uint32_t word, uint64_t pc, uint64_t *page, unsigned *reg) {
    if ((word & 0x9f000000U) != 0x90000000U) return false;
    uint64_t immediate = (((uint64_t)word >> 5U) & 0x7ffffU) << 2U;
    immediate |= ((uint64_t)word >> 29U) & 3U;
    if (page) *page = (uint64_t)((int64_t)(pc & ~0xfffULL) +
                                 (HFASignExtend(immediate, 21) << 12));
    if (reg) *reg = word & 31U;
    return true;
}

static bool HFADecodeAddImmediate64(uint32_t word, unsigned expectedReg,
                                    uint64_t *immediate) {
    if ((word & 0xff000000U) != 0x91000000U) return false;
    unsigned destination = word & 31U, source = (word >> 5U) & 31U;
    if (destination != expectedReg || source != expectedReg) return false;
    uint64_t value = (word >> 10U) & 0xfffU;
    if ((word >> 22U) & 1U) value <<= 12U;
    if (immediate) *immediate = value;
    return true;
}

static std::vector<uint64_t> HFATextReferences(const HFAMenuImage &image,
                                                const std::set<uint64_t> &targets) {
    std::vector<uint64_t> result;
    for (const HFAFileSection &section : image.textSections) {
        for (uint64_t index = 0; index + 4 <= section.size; index += 4) {
            uint64_t pc = section.address + index;
            const uint8_t *raw = image.bytes + section.offset + index;
            uint32_t word = HFAReadU32(raw);
            uint64_t direct = 0;
            unsigned reg = 0;
            if (HFADecodeADR(word, pc, &direct, &reg) && targets.count(direct)) {
                result.push_back(pc);
                continue;
            }
            uint64_t page = 0;
            if (!HFADecodeADRP(word, pc, &page, &reg)) continue;
            for (unsigned lookahead = 1; lookahead <= 3 && index + lookahead * 4 + 4 <= section.size;
                 ++lookahead) {
                uint64_t addImmediate = 0;
                uint32_t next = HFAReadU32(raw + lookahead * 4);
                if (!HFADecodeAddImmediate64(next, reg, &addImmediate)) continue;
                if (targets.count(page + addImmediate)) result.push_back(pc);
                break;
            }
        }
    }
    return result;
}

static void HFAFunctionBounds(const HFAMenuImage &image, uint64_t address,
                              uint64_t *startOut, uint64_t *endOut) {
    uint64_t start = address > 0x100 ? address - 0x100 : 0;
    uint64_t end = address + 0x100;
    if (!image.functionStarts.empty()) {
        auto upper = std::upper_bound(image.functionStarts.begin(), image.functionStarts.end(), address);
        if (upper != image.functionStarts.begin()) start = *(upper - 1);
        if (upper != image.functionStarts.end()) end = *upper;
    }
    if (end <= start || end - start > 0x8000) end = start + 0x8000;
    if (startOut) *startOut = start;
    if (endOut) *endOut = end;
}

static bool HFAIsConditionalBranch(uint32_t word) {
    return (word & 0x7e000000U) == 0x34000000U ||
           (word & 0xff000010U) == 0x54000000U ||
           (word & 0x7e000000U) == 0x36000000U;
}

static bool HFADecodeMoveWide32(uint32_t word, uint32_t *values, bool *known) {
    unsigned reg = word & 31U;
    unsigned shift = ((word >> 21U) & 3U) * 16U;
    uint32_t immediate = (word >> 5U) & 0xffffU;
    if ((word & 0x7f800000U) == 0x52800000U) {
        values[reg] = immediate << shift;
        known[reg] = true;
        return true;
    }
    if ((word & 0x7f800000U) == 0x72800000U && known[reg]) {
        uint32_t mask = 0xffffU << shift;
        values[reg] = (values[reg] & ~mask) | (immediate << shift);
        return true;
    }
    return false;
}

static NSDictionary *HFAFieldMappingAtReference(const HFAMenuImage &image,
                                                 uint64_t reference,
                                                 NSString *identifier) {
    uint64_t functionStart = 0, functionEnd = 0;
    HFAFunctionBounds(image, reference, &functionStart, &functionEnd);
    uint64_t referenceOffset = 0;
    const HFAFileSection *section = NULL;
    if (!HFAAddressToFileOffset(image, reference, &referenceOffset, &section)) return nil;
    uint64_t maxAddress = std::min(functionEnd, reference + 0x80ULL);
    bool sawConditionalBranch = false;
    uint32_t registerValues[32] = {};
    bool registerKnown[32] = {};
    for (uint64_t address = reference; address + 4 <= maxAddress; address += 4) {
        uint64_t offset = section->offset + (address - section->address);
        if (!HFARangeInside(offset, 4, image.length)) break;
        uint32_t word = HFAReadU32(image.bytes + offset);
        if (HFAIsConditionalBranch(word)) sawConditionalBranch = true;
        if (HFADecodeMoveWide32(word, registerValues, registerKnown)) continue;
        if ((word & 0xffc00000U) != 0xb9000000U) continue;
        unsigned valueReg = word & 31U;
        unsigned baseReg = (word >> 5U) & 31U;
        uint32_t fieldOffset = ((word >> 10U) & 0xfffU) * 4U;
        if (!sawConditionalBranch || !registerKnown[valueReg] || baseReg == 31U ||
            fieldOffset < 4U || fieldOffset > 0x4000U) continue;
        uint32_t value = registerValues[valueReg];
        float floatValue = 0.0f;
        memcpy(&floatValue, &value, sizeof(floatValue));
        return @{ @"identifier": identifier,
                  @"status": @"menu-field-mapping",
                  @"fieldOffset": [NSString stringWithFormat:@"0x%X", fieldOffset],
                  @"fieldOffsetValue": @(fieldOffset),
                  @"writeBits": [NSString stringWithFormat:@"0x%08X", value],
                  @"writeFloat": @(floatValue),
                  @"baseRegister": @(baseReg),
                  @"valueRegister": @(valueReg),
                  @"callbackRVA": [NSString stringWithFormat:@"0x%llX", functionStart],
                  @"identifierReferenceRVA": [NSString stringWithFormat:@"0x%llX", reference],
                  @"writeInstructionRVA": [NSString stringWithFormat:@"0x%llX", address],
                  @"evidence": @[@"exact-identifier-cstring", @"cfstring-reference",
                                  @"conditional-branch", @"bounded-constant-field-write"] };
    }
    return nil;
}

static NSArray<NSDictionary *> *HFAMenuFieldMappings(const HFAMenuImage &image,
                                                       NSArray<NSDictionary *> *registry) {
    NSMutableArray<NSDictionary *> *mappings = [NSMutableArray array];
    NSMutableSet<NSString *> *seenIdentifiers = [NSMutableSet set];
    for (NSDictionary *record in registry) {
        if (mappings.count >= kHFAMaxSemanticMappings || [record[@"canonicalEligible"] boolValue]) continue;
        NSString *identifier = [record[@"identifier"] isKindOfClass:NSString.class] ? record[@"identifier"] : nil;
        if (!identifier.length || identifier.length > 128 || [seenIdentifiers containsObject:identifier]) continue;
        [seenIdentifiers addObject:identifier];
        std::vector<uint64_t> strings = HFAExactCStringAddresses(image, identifier);
        std::set<uint64_t> referenceTargets;
        for (uint64_t stringAddress : strings) {
            referenceTargets.insert(stringAddress);
            std::vector<uint64_t> cfstrings = HFACFStringAddresses(image, stringAddress,
                [identifier lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
            referenceTargets.insert(cfstrings.begin(), cfstrings.end());
        }
        if (referenceTargets.empty()) continue;
        std::vector<uint64_t> references = HFATextReferences(image, referenceTargets);
        NSMutableArray<NSDictionary *> *candidates = [NSMutableArray array];
        NSMutableSet<NSString *> *candidateKeys = [NSMutableSet set];
        for (uint64_t reference : references) {
            NSDictionary *mapping = HFAFieldMappingAtReference(image, reference, identifier);
            if (!mapping) continue;
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@", mapping[@"callbackRVA"],
                             mapping[@"fieldOffset"], mapping[@"writeBits"]];
            if ([candidateKeys containsObject:key]) continue;
            [candidateKeys addObject:key];
            [candidates addObject:mapping];
        }
        if (candidates.count == 1) {
            NSMutableDictionary *mapping = [candidates.firstObject mutableCopy];
            mapping[@"name"] = record[@"name"] ?: identifier;
            mapping[@"candidateCount"] = @1;
            [mappings addObject:mapping];
        } else if (candidates.count > 1) {
            [mappings addObject:@{ @"identifier": identifier,
                                   @"name": record[@"name"] ?: identifier,
                                   @"status": @"ambiguous-menu-field-mapping",
                                   @"candidateCount": @(candidates.count),
                                   @"candidates": candidates }];
        }
    }
    return mappings;
}

static bool HFADecodeLdrS(uint32_t word, uint32_t *field, unsigned *valueReg,
                          unsigned *baseReg) {
    if ((word & 0xffc00000U) != 0xbd400000U) return false;
    if (field) *field = ((word >> 10U) & 0xfffU) * 4U;
    if (valueReg) *valueReg = word & 31U;
    if (baseReg) *baseReg = (word >> 5U) & 31U;
    return true;
}

static bool HFAIsFsubS(uint32_t word, unsigned valueReg) {
    return (word & 0xffe0fc00U) == 0x1e203800U &&
           (word & 31U) == valueReg && ((word >> 5U) & 31U) == valueReg;
}

static bool HFAIsStrS(uint32_t word, uint32_t field, unsigned valueReg,
                      unsigned baseReg) {
    return (word & 0xffc00000U) == 0xbd000000U &&
           (((word >> 10U) & 0xfffU) * 4U) == field &&
           (word & 31U) == valueReg && ((word >> 5U) & 31U) == baseReg;
}

static NSString *HFAWordHexLE(uint32_t word) {
    return [NSString stringWithFormat:@"%02X%02X%02X%02X", word & 0xffU,
            (word >> 8U) & 0xffU, (word >> 16U) & 0xffU, (word >> 24U) & 0xffU];
}

static bool HFAExcludedTargetImage(NSString *image, NSString *menuImage) {
    NSString *lower = image.lowercaseString;
    return [image isEqualToString:menuImage] || [lower containsString:@"hfamapuniversal"] ||
           [lower containsString:@"substrate"] || [lower containsString:@"ellekit"];
}

static NSDictionary *
HFATargetFieldFlowCandidates(NSArray<NSDictionary *> *images,
                             const std::set<uint32_t> &fields,
                             NSString *menuImage,
                             NSTimeInterval deadline) {
    NSMutableDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *result = [NSMutableDictionary dictionary];
    for (uint32_t field : fields) result[@(field)] = [NSMutableArray array];
    uint64_t eligibleBytes = 0, attemptedBytes = 0, scannedBytes = 0;
    NSUInteger eligibleSegments = 0, completeSegments = 0, failedChunks = 0;
    NSUInteger truncatedSegments = 0;
    BOOL timedOut = NO, candidateLimitHit = NO;
    std::vector<uint8_t> buffer((size_t)kHFAScanChunkBytes + 64U);
    for (NSDictionary *image in images) {
        NSString *imageName = image[@"image"] ?: @"?";
        if (HFAExcludedTargetImage(imageName, menuImage)) continue;
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue];
        uint64_t rawVMSize = [image[@"vmsize"] unsignedLongLongValue];
        if (!rawVMSize) continue;
        ++eligibleSegments;
        eligibleBytes = UINT64_MAX - eligibleBytes < rawVMSize ? UINT64_MAX
                                                               : eligibleBytes + rawVMSize;
        uint64_t remainingBudget = attemptedBytes < kHFAMaxExecutableBytes
            ? kHFAMaxExecutableBytes - attemptedBytes : 0;
        uint64_t vmsize = MIN(rawVMSize, kHFAMaxExecutableSegmentBytes);
        vmsize = MIN(vmsize, remainingBudget);
        BOOL segmentComplete = vmsize == rawVMSize;
        if (!segmentComplete) ++truncatedSegments;
        if (!vmsize) continue;
        int64_t slide = [image[@"slide"] longLongValue];
        uintptr_t runtimeStart = (uintptr_t)((int64_t)vmaddr + slide);
        for (uint64_t segmentOffset = 0; segmentOffset < vmsize; segmentOffset += kHFAScanChunkBytes) {
            if (NSDate.date.timeIntervalSince1970 > deadline) {
                timedOut = YES;
                segmentComplete = NO;
                break;
            }
            vm_size_t logical = (vm_size_t)MIN((uint64_t)kHFAScanChunkBytes, vmsize - segmentOffset);
            vm_size_t requested = (vm_size_t)MIN((uint64_t)logical + 64ULL, vmsize - segmentOffset);
            attemptedBytes += logical;
            vm_size_t copied = 0;
            kern_return_t kr = vm_read_overwrite(mach_task_self(),
                (vm_address_t)(runtimeStart + segmentOffset), requested,
                (vm_address_t)buffer.data(), &copied);
            if (kr != KERN_SUCCESS || copied < logical) {
                ++failedChunks;
                segmentComplete = NO;
                if (kr != KERN_SUCCESS || copied < 4) continue;
            }
            uint64_t scanLimit = MIN((uint64_t)logical, (uint64_t)copied);
            scannedBytes += scanLimit;
            for (uint64_t index = 0; index + 48 <= copied && index < scanLimit; index += 4) {
                uint32_t load = HFAReadU32(buffer.data() + index);
                uint32_t field = 0;
                unsigned valueReg = 0, baseReg = 0;
                if (!HFADecodeLdrS(load, &field, &valueReg, &baseReg) ||
                    !fields.count(field) || baseReg == 31U) continue;
                NSMutableArray<NSDictionary *> *fieldCandidates = result[@(field)];
                if (fieldCandidates.count >= kHFAMaxCandidatesPerField) {
                    candidateLimitHit = YES;
                    continue;
                }
                for (unsigned arithmeticIndex = 1; arithmeticIndex <= 9; ++arithmeticIndex) {
                    uint64_t arithmeticOffset = index + arithmeticIndex * 4ULL;
                    if (arithmeticOffset + 4 > copied) break;
                    uint32_t arithmetic = HFAReadU32(buffer.data() + arithmeticOffset);
                    if (!HFAIsFsubS(arithmetic, valueReg)) continue;
                    for (unsigned storeIndex = arithmeticIndex + 1;
                         storeIndex <= arithmeticIndex + 4; ++storeIndex) {
                        uint64_t storeOffset = index + storeIndex * 4ULL;
                        if (storeOffset + 4 > copied) break;
                        uint32_t store = HFAReadU32(buffer.data() + storeOffset);
                        if (!HFAIsStrS(store, field, valueReg, baseReg)) continue;
                        uint64_t loadRVA = vmaddr + segmentOffset + index;
                        uint64_t patchRVA = vmaddr + segmentOffset + arithmeticOffset;
                        uint64_t storeRVA = vmaddr + segmentOffset + storeOffset;
                        NSString *dedup = [NSString stringWithFormat:@"%@:%llX", imageName, patchRVA];
                        BOOL duplicate = NO;
                        for (NSDictionary *existing in fieldCandidates)
                            if ([existing[@"dedupKey"] isEqualToString:dedup]) { duplicate = YES; break; }
                        if (!duplicate) {
                            [fieldCandidates addObject:@{
                                @"dedupKey": dedup,
                                @"targetImage": imageName,
                                @"targetUUID": image[@"uuid"] ?: @"unknown",
                                @"fieldOffset": [NSString stringWithFormat:@"0x%X", field],
                                @"loadRVA": [NSString stringWithFormat:@"0x%llX", loadRVA],
                                @"patchRVA": [NSString stringWithFormat:@"0x%llX", patchRVA],
                                @"storeRVA": [NSString stringWithFormat:@"0x%llX", storeRVA],
                                @"patchRVAValue": @(patchRVA),
                                @"baseRegister": @(baseReg),
                                @"valueRegister": @(valueReg),
                                @"original": HFAWordHexLE(arithmetic),
                                @"enabled": @"1F2003D5"
                            }];
                        }
                    }
                    break;
                }
            }
        }
        if (segmentComplete) ++completeSegments;
    }
    BOOL coverageComplete = eligibleSegments > 0 && completeSegments == eligibleSegments &&
        !timedOut && !failedChunks && !truncatedSegments && !candidateLimitHit &&
        scannedBytes == eligibleBytes;
    NSDictionary *coverage = @{
        @"complete": @(coverageComplete),
        @"eligibleSegments": @(eligibleSegments),
        @"completeSegments": @(completeSegments),
        @"eligibleBytes": @(eligibleBytes),
        @"attemptedBytes": @(attemptedBytes),
        @"scannedBytes": @(scannedBytes),
        @"failedChunks": @(failedChunks),
        @"truncatedSegments": @(truncatedSegments),
        @"candidateLimitHit": @(candidateLimitHit),
        @"deadlineExceeded": @(timedOut)
    };
    return @{ @"candidates": result, @"coverage": coverage };
}

static NSArray<NSDictionary *> *HFAConsensusCandidatesForMapping(
    NSDictionary *mapping,
    NSArray<NSDictionary *> *mappings,
    NSDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *candidates) {
    uint32_t field = [mapping[@"fieldOffsetValue"] unsignedIntValue];
    NSArray<NSDictionary *> *matches = candidates[@(field)] ?: @[];
    NSString *callback = mapping[@"callbackRVA"];
    NSMutableSet<NSNumber *> *peerFields = [NSMutableSet set];
    for (NSDictionary *peer in mappings) {
        if (![peer[@"status"] isEqualToString:@"menu-field-mapping"] ||
            ![peer[@"callbackRVA"] isEqualToString:callback]) continue;
        uint32_t peerField = [peer[@"fieldOffsetValue"] unsignedIntValue];
        if (peerField != field) [peerFields addObject:@(peerField)];
    }
    if (!peerFields.count) return matches;

    NSMutableArray<NSDictionary *> *filtered = [NSMutableArray array];
    for (NSDictionary *candidate in matches) {
        NSString *image = candidate[@"targetImage"];
        uint64_t patchRVA = [candidate[@"patchRVAValue"] unsignedLongLongValue];
        NSNumber *baseRegister = candidate[@"baseRegister"];
        BOOL coversAllPeers = YES;
        for (NSNumber *peerField in peerFields) {
            BOOL peerMatched = NO;
            for (NSDictionary *peerCandidate in candidates[peerField] ?: @[]) {
                if (![peerCandidate[@"targetImage"] isEqualToString:image] ||
                    ![peerCandidate[@"baseRegister"] isEqualToNumber:baseRegister]) continue;
                uint64_t peerRVA = [peerCandidate[@"patchRVAValue"] unsignedLongLongValue];
                uint64_t distance = patchRVA > peerRVA ? patchRVA - peerRVA : peerRVA - patchRVA;
                if (distance <= kHFAMaxSharedCallbackTargetSpan) { peerMatched = YES; break; }
            }
            if (!peerMatched) { coversAllPeers = NO; break; }
        }
        if (coversAllPeers) [filtered addObject:candidate];
    }
    return filtered;
}

} // namespace

NSDictionary *HFAMapResolveHookSemanticFeatures(NSDictionary *candidate,
                                                 NSArray<NSDictionary *> *registry,
                                                 NSArray<NSDictionary *> *executableImages,
                                                 NSTimeInterval deadline) {
    NSTimeInterval started = NSDate.date.timeIntervalSince1970;
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : nil;
    NSString *menuImage = candidate[@"image"] ?: path.lastPathComponent ?: @"?";
    if (!path.length || !registry.count)
        return @{ @"status": @"not-applicable", @"features": @[], @"resolutions": @[],
                  @"metrics": @{ @"elapsedMs": @0, @"menuMappings": @0, @"scannedBytes": @0 } };

    HFAMenuImage image = {};
    NSString *parseReason = nil;
    if (!HFAParseMenuImage(path, image, &parseReason)) {
        return @{ @"status": parseReason ?: @"menu-parse-failed", @"features": @[],
                  @"resolutions": @[],
                  @"metrics": @{ @"elapsedMs": @((NSDate.date.timeIntervalSince1970 - started) * 1000.0),
                                  @"menuMappings": @0, @"scannedBytes": @0 } };
    }

    NSArray<NSDictionary *> *mappings = HFAMenuFieldMappings(image, registry);
    std::set<uint32_t> fields;
    for (NSDictionary *mapping in mappings)
        if ([mapping[@"status"] isEqualToString:@"menu-field-mapping"])
            fields.insert([mapping[@"fieldOffsetValue"] unsignedIntValue]);

    NSDictionary *scanResult = fields.empty()
        ? @{ @"candidates": @{},
             @"coverage": @{ @"complete": @YES, @"eligibleSegments": @0,
                               @"completeSegments": @0, @"eligibleBytes": @0,
                               @"attemptedBytes": @0, @"scannedBytes": @0,
                               @"failedChunks": @0, @"truncatedSegments": @0,
                               @"candidateLimitHit": @NO, @"deadlineExceeded": @NO } }
        : HFATargetFieldFlowCandidates(executableImages, fields, menuImage, deadline);
    NSDictionary<NSNumber *, NSMutableArray<NSDictionary *> *> *candidates = scanResult[@"candidates"];
    NSMutableDictionary *scanCoverage = [scanResult[@"coverage"] mutableCopy];
    if (!fields.empty() && NSDate.date.timeIntervalSince1970 > deadline) {
        scanCoverage[@"complete"] = @NO;
        scanCoverage[@"deadlineExceeded"] = @YES;
    }
    BOOL scanCoverageComplete = [scanCoverage[@"complete"] boolValue];
    NSMutableArray<NSDictionary *> *features = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *resolutions = [NSMutableArray array];
    NSMutableSet<NSString *> *resolvedIdentifiers = [NSMutableSet set];
    for (NSDictionary *mapping in mappings) {
        NSString *identifier = mapping[@"identifier"] ?: @"?";
        if (![mapping[@"status"] isEqualToString:@"menu-field-mapping"]) {
            [resolutions addObject:mapping];
            continue;
        }
        uint32_t field = [mapping[@"fieldOffsetValue"] unsignedIntValue];
        NSArray<NSDictionary *> *rawMatches = candidates[@(field)] ?: @[];
        NSArray<NSDictionary *> *matches = HFAConsensusCandidatesForMapping(mapping, mappings,
                                                                              candidates);
        if (!scanCoverageComplete) {
            NSMutableDictionary *resolution = [mapping mutableCopy];
            resolution[@"status"] = @"target-scan-incomplete";
            resolution[@"targetCandidateCount"] = @(matches.count);
            resolution[@"rawTargetCandidateCount"] = @(rawMatches.count);
            resolution[@"scanCoverage"] = scanCoverage;
            if (matches.count) resolution[@"targetCandidates"] = matches;
            [resolutions addObject:resolution];
            continue;
        }
        if (matches.count != 1) {
            NSMutableDictionary *resolution = [mapping mutableCopy];
            resolution[@"status"] = matches.count ? @"ambiguous-target-field-flow"
                                                    : @"target-field-flow-not-found";
            resolution[@"targetCandidateCount"] = @(matches.count);
            resolution[@"rawTargetCandidateCount"] = @(rawMatches.count);
            if (matches.count) resolution[@"targetCandidates"] = matches;
            [resolutions addObject:resolution];
            continue;
        }
        NSDictionary *match = matches.firstObject;
        NSString *original = match[@"original"];
        NSMutableDictionary *feature = [@{
            @"name": mapping[@"name"] ?: identifier,
            @"identifier": identifier,
            @"offset": match[@"patchRVA"],
            @"patch": match[@"enabled"],
            @"original": original,
            @"currentBytes": original,
            @"targetImage": match[@"targetImage"],
            @"targetUUID": match[@"targetUUID"],
            @"offsetSemantics": @"preferred-mach-o-vmaddr",
            @"canonicalEligible": @YES,
            @"confidence": @"byte-validated",
            @"sourceFamily": candidate[@"family"] ?: @"unknown",
            @"descriptorClass": @"MenuHookSemantic",
            @"resolutionPath": @"menu-hook-callback-field-dataflow",
            @"fieldOffset": mapping[@"fieldOffset"],
            @"menuSemantic": mapping,
            @"targetDataflow": match,
            @"evidence": @[@"exact-menu-identifier", @"menu-callback-field-write",
                            @"target-load-fsub-store-same-field", @"unique-field-flow-candidate",
                            @"same-menu-callback-field-consensus",
                            @"executable-range", @"live-original-bytes-match"]
        } mutableCopy];
        [features addObject:feature];
        [resolvedIdentifiers addObject:identifier];
        NSMutableDictionary *resolution = [mapping mutableCopy];
        resolution[@"status"] = @"resolved";
        resolution[@"targetCandidateCount"] = @1;
        resolution[@"rawTargetCandidateCount"] = @(rawMatches.count);
        resolution[@"canonicalPatch"] = feature;
        [resolutions addObject:resolution];
    }

    BOOL finalDeadlineExceeded = !fields.empty() && NSDate.date.timeIntervalSince1970 > deadline;
    if (finalDeadlineExceeded) {
        scanCoverage[@"complete"] = @NO;
        scanCoverage[@"deadlineExceeded"] = @YES;
        [features removeAllObjects];
        [resolvedIdentifiers removeAllObjects];
        for (NSUInteger index = 0; index < resolutions.count; ++index) {
            NSDictionary *existing = resolutions[index];
            if (![existing[@"status"] isEqualToString:@"resolved"]) continue;
            NSMutableDictionary *replacement = [existing mutableCopy];
            replacement[@"status"] = @"target-scan-incomplete";
            replacement[@"scanCoverage"] = scanCoverage;
            [replacement removeObjectForKey:@"canonicalPatch"];
            resolutions[index] = replacement;
        }
        scanCoverageComplete = NO;
    }
    NSTimeInterval elapsed = (NSDate.date.timeIntervalSince1970 - started) * 1000.0;
    NSString *status = finalDeadlineExceeded ? @"timeout"
        : (!fields.empty() && !scanCoverageComplete ? @"incomplete" : @"complete");
    return @{ @"status": status,
              @"features": features,
              @"resolutions": resolutions,
              @"resolvedIdentifiers": resolvedIdentifiers.allObjects,
              @"analysisOnly": @NO,
              @"memoryWritten": @NO,
              @"selectorInvoked": @NO,
              @"hookInstalled": @NO,
              @"scanCoverage": scanCoverage,
              @"metrics": @{ @"elapsedMs": @(elapsed),
                              @"menuMappings": @(mappings.count),
                              @"fieldCount": @(fields.size()),
                              @"resolved": @(features.count),
                              @"scannedBytes": scanCoverage[@"scannedBytes"] ?: @0,
                              @"scanCoverageComplete": @(scanCoverageComplete),
                              @"scanFailedChunks": scanCoverage[@"failedChunks"] ?: @0,
                              @"scanTruncatedSegments": scanCoverage[@"truncatedSegments"] ?: @0 } };
}
