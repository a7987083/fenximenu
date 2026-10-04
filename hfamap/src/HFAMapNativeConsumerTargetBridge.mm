#import "HFAMapNativeConsumerTargetBridge.h"
#import "HFAIL2CPPMethodIndex.h"
#import "HFAMapRecursiveNativeTargetResolver.h"

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/machine.h>
#include <algorithm>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <string.h>

namespace {

struct HFASection { uint64_t addr, size, off; std::string name; };
struct HFAImage {
    NSData *data;
    const uint8_t *bytes;
    uint64_t length;
    uint64_t textBase;
    std::vector<HFASection> text;
    std::vector<HFASection> dataSections;
    std::vector<uint64_t> starts;
};

static bool HFAInside(uint64_t off, uint64_t size, uint64_t length) {
    return off <= length && size <= length - off;
}
static uint32_t HFAU32(const uint8_t *p) { uint32_t v = 0; memcpy(&v, p, sizeof(v)); return v; }
static std::string HFAName(const char raw[16]) {
    size_t n = 0; while (n < 16 && raw[n]) ++n; return std::string(raw, raw + n);
}
static int64_t HFASign(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U); return (int64_t)((value ^ sign) - sign);
}

static bool HFAParse(NSString *path, HFAImage &image, NSString **reason) {
    NSDictionary *attrs = [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    uint64_t size = [attrs[NSFileSize] unsignedLongLongValue];
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
    const uint8_t *cursor = bytes + sizeof(*mh), *end = cursor + mh->sizeofcmds;
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
                HFASection sec = {sects[s].addr, sects[s].size, sects[s].offset, HFAName(sects[s].sectname)};
                if (sec.name == "__text" && HFAInside(sec.off, sec.size, data.length)) image.text.push_back(sec);
                std::string segName = HFAName(sects[s].segname);
                if (segName == "__DATA" || segName == "__DATA_CONST" ||
                    segName == "__AUTH" || segName == "__AUTH_CONST")
                    image.dataSections.push_back(sec);
            }
        } else if (lc->cmd == LC_FUNCTION_STARTS && lc->cmdsize >= sizeof(struct linkedit_data_command)) {
            const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)cursor;
            startsOff = cmd->dataoff; startsSize = cmd->datasize;
        }
        cursor += lc->cmdsize;
    }
    if (image.text.empty()) { if (reason) *reason = @"text-section-missing"; return false; }

    if (startsSize && HFAInside(startsOff, startsSize, data.length)) {
        const uint8_t *p = bytes + startsOff, *limit = p + startsSize;
        uint64_t address = image.textBase;
        while (p < limit && image.starts.size() < 100000) {
            uint64_t delta = 0; unsigned shift = 0; bool done = false;
            while (p < limit && shift < 64) {
                uint8_t b = *p++; delta |= (uint64_t)(b & 0x7fU) << shift;
                if (!(b & 0x80U)) { done = true; break; } shift += 7;
            }
            if (!done || !delta || UINT64_MAX - address < delta) break;
            address += delta; image.starts.push_back(address);
        }
    }
    image.data = data; image.bytes = bytes; image.length = data.length;
    return true;
}

static bool HFAOffset(const HFAImage &image, uint64_t address, uint64_t *out, const HFASection **sectionOut) {
    for (const HFASection &sec : image.text) {
        if (address < sec.addr || address - sec.addr >= sec.size) continue;
        uint64_t off = sec.off + (address - sec.addr);
        if (!HFAInside(off, 4, image.length)) return false;
        if (out) *out = off; if (sectionOut) *sectionOut = &sec; return true;
    }
    return false;
}
static void HFAFunction(const HFAImage &image, uint64_t address, uint64_t *startOut, uint64_t *endOut) {
    uint64_t start = address, end = address + 0x800;
    if (!image.starts.empty()) {
        auto upper = std::upper_bound(image.starts.begin(), image.starts.end(), address);
        if (upper != image.starts.begin()) start = *(upper - 1);
        if (upper != image.starts.end()) end = *upper;
    }
    if (end <= start || end - start > 0x4000) end = start + 0x1000;
    if (startOut) *startOut = start; if (endOut) *endOut = end;
}
static bool HFAADRP(uint32_t w, uint64_t pc, uint64_t *page, unsigned *reg) {
    if ((w & 0x9f000000U) != 0x90000000U) return false;
    uint64_t imm = (((uint64_t)w >> 5U) & 0x7ffffU) << 2U; imm |= ((uint64_t)w >> 29U) & 3U;
    if (page) *page = (uint64_t)((int64_t)(pc & ~0xfffULL) + (HFASign(imm, 21) << 12));
    if (reg) *reg = w & 31U; return true;
}
static bool HFAAddImm(uint32_t w, unsigned expected, uint64_t *imm) {
    if ((w & 0xff000000U) != 0x91000000U) return false;
    unsigned rd = w & 31U, rn = (w >> 5U) & 31U; if (rd != expected || rn != expected) return false;
    uint64_t v = (w >> 10U) & 0xfffU; if ((w >> 22U) & 1U) v <<= 12;
    if (imm) *imm = v; return true;
}
static bool HFALdrXUnsigned(uint32_t w, unsigned baseReg, unsigned *dst, uint64_t *byteOffset) {
    if ((w & 0xffc00000U) != 0xf9400000U) return false;
    if (((w >> 5U) & 31U) != baseReg) return false;
    if (dst) *dst = w & 31U; if (byteOffset) *byteOffset = ((w >> 10U) & 0xfffU) * 8ULL;
    return true;
}
static bool HFABranchRegister(uint32_t w, unsigned reg, NSString **kind) {
    if (((w >> 5U) & 31U) != reg) return false;
    if ((w & 0xfffffc1fU) == 0xd61f0000U) { if (kind) *kind = @"BR"; return true; }
    if ((w & 0xfffffc1fU) == 0xd63f0000U) { if (kind) *kind = @"BLR"; return true; }
    return false;
}
static BOOL HFAAddressInData(const HFAImage &image, uint64_t address) {
    for (const HFASection &sec : image.dataSections)
        if (address >= sec.addr && address - sec.addr < sec.size) return YES;
    return NO;
}

static const struct mach_header_64 *HFALoadedImage(NSString *name, NSString *path) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *raw = _dyld_get_image_name(i); if (!raw) continue;
        NSString *loadedPath = [NSString stringWithUTF8String:raw] ?: @"";
        if (!((name.length && [loadedPath.lastPathComponent isEqualToString:name]) ||
              (path.length && [loadedPath isEqualToString:path]))) continue;
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (header && header->magic == MH_MAGIC_64) return header;
    }
    return NULL;
}

static BOOL HFAReadPointer(uintptr_t address, uintptr_t *valueOut) {
    uintptr_t value = 0; mach_vm_size_t read = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)address,
                                               sizeof(value), (mach_vm_address_t)&value, &read);
    if (kr != KERN_SUCCESS || read != sizeof(value)) return NO;
    *valueOut = value; return YES;
}

static NSDictionary *HFALiveTarget(uintptr_t target, NSString *menuImage, NSTimeInterval deadline) {
    Dl_info info = {}; if (!target || !dladdr((void *)target, &info) || !info.dli_fbase || !info.dli_fname) return nil;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
    NSString *image = path.lastPathComponent ?: @"";
    uint64_t rva = (uint64_t)(target - (uintptr_t)info.dli_fbase);
    BOOL external = !menuImage.length || ![image isEqualToString:menuImage];
    NSMutableDictionary *record = [@{
        @"targetRuntimeToken": [NSString stringWithFormat:@"0x%llX", (unsigned long long)target],
        @"targetImage": image ?: @"", @"targetPath": path ?: @"",
        @"targetRVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)rva],
        @"targetRVAValue": @(rva), @"externalToMenu": @(external)
    } mutableCopy];
    if (external && [image isEqualToString:@"UnityFramework"]) {
        HFAIL2CPPBuildMethodIndex(deadline);
        NSDictionary *exact = HFAIL2CPPMethodForRuntimeAddress((const void *)target);
        NSDictionary *method = exact ?: HFAIL2CPPMethodContainingRuntimeAddress((const void *)target);
        if (method) {
            record[@"il2cppMethod"] = method;
            record[@"il2cppResolution"] = exact ? @"exact-method-entry" : (method[@"matchType"] ?: @"containing-method-range");
        } else record[@"il2cppResolution"] = @"unresolved";
    }
    return record;
}

static NSArray *HFASlotCandidates(const HFAImage &image, uint64_t consumerRVA) {
    uint64_t start = 0, end = 0; HFAFunction(image, consumerRVA, &start, &end);
    uint64_t fileOff = 0; const HFASection *section = NULL;
    if (!HFAOffset(image, start, &fileOff, &section)) return @[];
    uint64_t limit = std::min(end, start + 0x2000ULL);
    NSMutableArray *out = [NSMutableArray array]; NSMutableSet *dedup = [NSMutableSet set];

    for (uint64_t pc = start; pc + 4 <= limit; pc += 4) {
        uint64_t off = section->off + (pc - section->addr);
        if (!HFAInside(off, 4, image.length)) break;
        uint64_t page = 0; unsigned baseReg = 0;
        if (!HFAADRP(HFAU32(image.bytes + off), pc, &page, &baseReg)) continue;
        uint64_t baseAddress = page;

        for (unsigned k = 1; k <= 4 && pc + k * 4 + 4 <= limit; ++k) {
            uint64_t nextOff = off + k * 4; if (!HFAInside(nextOff, 4, image.length)) break;
            uint32_t w = HFAU32(image.bytes + nextOff); uint64_t add = 0;
            if (HFAAddImm(w, baseReg, &add)) { baseAddress = page + add; continue; }

            unsigned loadedReg = 0; uint64_t ldrOff = 0;
            if (!HFALdrXUnsigned(w, baseReg, &loadedReg, &ldrOff)) continue;
            uint64_t slot = baseAddress + ldrOff; if (!HFAAddressInData(image, slot)) continue;

            NSString *branchKind = nil; uint64_t branchRVA = 0;
            for (unsigned j = k + 1; j <= k + 8 && pc + j * 4 + 4 <= limit; ++j) {
                uint64_t boff = off + j * 4; if (!HFAInside(boff, 4, image.length)) break;
                if (HFABranchRegister(HFAU32(image.bytes + boff), loadedReg, &branchKind)) {
                    branchRVA = pc + j * 4; break;
                }
            }
            if (!branchRVA) continue;
            NSString *key = [NSString stringWithFormat:@"%llX:%@", (unsigned long long)slot, branchKind ?: @"?"];
            if ([dedup containsObject:key]) continue; [dedup addObject:key];
            [out addObject:@{
                @"slotRVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)slot],
                @"slotRVAValue": @(slot),
                @"loadInstructionRVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(pc + k * 4)],
                @"branchInstructionRVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)branchRVA],
                @"branchKind": branchKind ?: @"unknown", @"loadedRegister": @(loadedReg)
            }];
        }
    }
    return out;
}
} // namespace

NSDictionary *HFAMapResolveNativeConsumerTargets(NSDictionary *candidate,
                                                 NSDictionary *staticConsumers,
                                                 NSTimeInterval deadline) {
    NSTimeInterval started = NSDate.date.timeIntervalSince1970;
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : nil;
    NSString *menuImage = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : path.lastPathComponent;
    NSArray *groups = [staticConsumers[@"groups"] isKindOfClass:NSArray.class] ? staticConsumers[@"groups"] : @[];
    if (!path.length || !groups.count)
        return @{@"schema": @"com.hfa.native-consumer-target-bridge/v2", @"status": @"not-applicable",
                 @"groups": @[], @"analysisOnly": @YES, @"memoryWritten": @NO};

    HFAImage image = {}; NSString *reason = nil;
    if (!HFAParse(path, image, &reason))
        return @{@"schema": @"com.hfa.native-consumer-target-bridge/v1", @"status": reason ?: @"parse-failed",
                 @"groups": @[], @"analysisOnly": @YES, @"memoryWritten": @NO};

    const struct mach_header_64 *loaded = HFALoadedImage(menuImage, path);
    if (!loaded)
        return @{@"schema": @"com.hfa.native-consumer-target-bridge/v1", @"status": @"selected-menu-not-loaded",
                 @"groups": @[], @"analysisOnly": @YES, @"memoryWritten": @NO};

    NSMutableArray *resolvedGroups = [NSMutableArray array];
    NSUInteger slotsInspected = 0, livePointers = 0, externalPointers = 0, il2cppResolved = 0;
    for (NSDictionary *group in groups) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        uint64_t consumer = [group[@"consumerRVAValue"] unsignedLongLongValue]; if (!consumer) continue;
        NSArray *slots = HFASlotCandidates(image, consumer); NSMutableArray *slotRecords = [NSMutableArray array];

        for (NSDictionary *slot in slots) {
            if (NSDate.date.timeIntervalSince1970 > deadline) break;
            ++slotsInspected;
            uint64_t slotRVA = [slot[@"slotRVAValue"] unsignedLongLongValue];
            NSMutableDictionary *record = [NSMutableDictionary dictionaryWithDictionary:slot];
            if (slotRVA < image.textBase) { record[@"liveStatus"] = @"invalid-slot-rva"; [slotRecords addObject:record]; continue; }
            uintptr_t runtimeSlot = (uintptr_t)loaded + (uintptr_t)(slotRVA - image.textBase);
            record[@"slotRuntimeToken"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)runtimeSlot];
            uintptr_t pointee = 0;
            if (!HFAReadPointer(runtimeSlot, &pointee) || !pointee) {
                record[@"liveStatus"] = @"uninitialized-or-unreadable"; [slotRecords addObject:record]; continue;
            }
            ++livePointers;
            NSDictionary *target = HFALiveTarget(pointee, menuImage, deadline);
            if (!target) {
                record[@"liveStatus"] = @"pointee-not-symbolizable";
                record[@"targetRuntimeToken"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)pointee];
                [slotRecords addObject:record]; continue;
            }
            record[@"liveStatus"] = @"resolved-live-pointee"; [record addEntriesFromDictionary:target];
            if ([target[@"externalToMenu"] boolValue]) {
                ++externalPointers;
                if ([target[@"il2cppMethod"] isKindOfClass:NSDictionary.class]) ++il2cppResolved;
            } else {
                NSDictionary *recursive = HFAMapResolveRecursiveNativeTarget(
                    pointee, menuImage, deadline);
                record[@"recursiveTargetEvidence"] = recursive ?: @{};
                NSDictionary *finalTarget =
                    [recursive[@"finalTarget"] isKindOfClass:NSDictionary.class] ?
                        recursive[@"finalTarget"] : nil;
                if ([finalTarget[@"externalToMenu"] boolValue]) {
                    record[@"recursiveResolvedTarget"] = finalTarget;
                    ++externalPointers;
                    if ([finalTarget[@"il2cppMethod"] isKindOfClass:NSDictionary.class])
                        ++il2cppResolved;
                }
            }
            [slotRecords addObject:record];
        }

        NSMutableArray *externalUnity = [NSMutableArray array];
        for (NSDictionary *record in slotRecords) {
            if ([record[@"externalToMenu"] boolValue] &&
                [record[@"targetImage"] isEqualToString:@"UnityFramework"]) {
                [externalUnity addObject:record];
                continue;
            }
            NSDictionary *recursiveTarget =
                [record[@"recursiveResolvedTarget"] isKindOfClass:NSDictionary.class] ?
                    record[@"recursiveResolvedTarget"] : nil;
            if ([recursiveTarget[@"externalToMenu"] boolValue] &&
                [recursiveTarget[@"image"] isEqualToString:@"UnityFramework"])
                [externalUnity addObject:recursiveTarget];
        }

        NSMutableDictionary *result = [NSMutableDictionary dictionaryWithDictionary:group];
        result[@"slotCandidates"] = slotRecords;
        result[@"slotCandidateCount"] = @(slotRecords.count);
        result[@"externalUnityTargetCount"] = @(externalUnity.count);
        if (externalUnity.count == 1) {
            result[@"resolvedTarget"] = externalUnity.firstObject;
            result[@"targetResolutionStatus"] = @"unique-unity-live-pointee";
        } else if (externalUnity.count > 1) {
            result[@"targetResolutionStatus"] = @"ambiguous-multiple-unity-live-pointees";
        } else result[@"targetResolutionStatus"] = @"no-unity-live-pointee";
        [resolvedGroups addObject:result];
    }

    BOOL timeout = NSDate.date.timeIntervalSince1970 > deadline;
    return @{
        @"schema": @"com.hfa.native-consumer-target-bridge/v1",
        @"status": timeout ? @"timeout" : (resolvedGroups.count ? @"complete" : @"no-consumer-groups"),
        @"menuImage": menuImage ?: @"", @"groups": resolvedGroups, @"groupCount": @(resolvedGroups.count),
        @"slotsInspected": @(slotsInspected), @"livePointers": @(livePointers),
        @"externalPointers": @(externalPointers), @"il2cppResolved": @(il2cppResolved),
        @"analysisOnly": @YES, @"memoryWritten": @NO, @"selectorInvoked": @NO,
        @"blockInvoked": @NO, @"consumerInvoked": @NO, @"hookInstalled": @NO,
        @"policy": @"static-slot+recursive-executable-trampoline+unique-edge+cycle-detection+fail-closed",
        @"metrics": @{@"elapsedMs": @((NSDate.date.timeIntervalSince1970 - started) * 1000.0)}
    };
}
