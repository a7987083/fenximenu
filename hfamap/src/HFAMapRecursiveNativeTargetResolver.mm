#import "HFAMapRecursiveNativeTargetResolver.h"
#import "HFAIL2CPPMethodIndex.h"

#import <mach/mach.h>
#import <mach/mach_vm.h>
#include <dlfcn.h>
#include <set>
#include <vector>
#include <string.h>

namespace {
static const NSUInteger kHFAMaxRecursiveDepth = 6;
static const NSUInteger kHFAMaxInstructions = 16;

static int64_t HFASignExtend(uint64_t value, unsigned bits) {
    const uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL HFAReadBytes(uintptr_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    mach_vm_size_t read = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(),
                                               (mach_vm_address_t)address,
                                               (mach_vm_size_t)size,
                                               (mach_vm_address_t)buffer,
                                               &read);
    return kr == KERN_SUCCESS && read == size;
}

static BOOL HFAReadPointer(uintptr_t address, uintptr_t *valueOut) {
    uintptr_t value = 0;
    if (!HFAReadBytes(address, &value, sizeof(value))) return NO;
    if (valueOut) *valueOut = value;
    return YES;
}

static BOOL HFAExecutableAddress(uintptr_t address) {
    mach_vm_address_t region = (mach_vm_address_t)address;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info = {};
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &region, &size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &count, &object);
    if (kr != KERN_SUCCESS) return NO;
    if ((mach_vm_address_t)address < region ||
        (mach_vm_address_t)address - region >= size) return NO;
    return (info.protection & VM_PROT_EXECUTE) != 0;
}

static NSDictionary *HFADescribeTarget(uintptr_t target, NSString *menuImage,
                                       NSTimeInterval deadline) {
    Dl_info info = {};
    if (!target || !dladdr((const void *)target, &info) || !info.dli_fbase || !info.dli_fname)
        return nil;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
    NSString *image = path.lastPathComponent ?: @"";
    uint64_t rva = (uint64_t)(target - (uintptr_t)info.dli_fbase);
    BOOL external = !menuImage.length || ![image isEqualToString:menuImage];
    NSMutableDictionary *record = [@{
        @"runtimeToken": [NSString stringWithFormat:@"0x%llX", (unsigned long long)target],
        @"image": image,
        @"path": path,
        @"rva": [NSString stringWithFormat:@"0x%llX", (unsigned long long)rva],
        @"rvaValue": @(rva),
        @"externalToMenu": @(external),
        @"executable": @(HFAExecutableAddress(target))
    } mutableCopy];
    if (external && [image isEqualToString:@"UnityFramework"]) {
        HFAIL2CPPBuildMethodIndex(deadline);
        NSDictionary *exact = HFAIL2CPPMethodForRuntimeAddress((const void *)target);
        NSDictionary *method = exact ?: HFAIL2CPPMethodContainingRuntimeAddress((const void *)target);
        if (method) {
            record[@"il2cppMethod"] = method;
            record[@"il2cppResolution"] = exact ? @"exact-method-entry" :
                (method[@"matchType"] ?: @"containing-method-range");
        } else {
            record[@"il2cppResolution"] = @"unresolved";
        }
    }
    return [record autorelease];
}

static BOOL HFADecodeDirectBranch(uint32_t insn, uintptr_t pc,
                                  uintptr_t *targetOut, NSString **kindOut) {
    uint32_t op = insn & 0xFC000000U;
    if (op != 0x14000000U && op != 0x94000000U) return NO;
    int64_t imm = HFASignExtend((uint64_t)(insn & 0x03FFFFFFU), 26) << 2;
    if (targetOut) *targetOut = (uintptr_t)((int64_t)pc + imm);
    if (kindOut) *kindOut = (op == 0x14000000U) ? @"B" : @"BL";
    return YES;
}

static BOOL HFADecodeADRP(uint32_t insn, uintptr_t pc, uintptr_t *pageOut, unsigned *regOut) {
    if ((insn & 0x9F000000U) != 0x90000000U) return NO;
    uint64_t imm = (((uint64_t)insn >> 5U) & 0x7FFFFU) << 2U;
    imm |= ((uint64_t)insn >> 29U) & 3U;
    int64_t delta = HFASignExtend(imm, 21) << 12;
    if (pageOut) *pageOut = (uintptr_t)((int64_t)(pc & ~0xFFFULL) + delta);
    if (regOut) *regOut = insn & 31U;
    return YES;
}

static BOOL HFADecodeADD(uint32_t insn, unsigned baseReg, uintptr_t base,
                         uintptr_t *valueOut, unsigned *dstOut) {
    if ((insn & 0xFF000000U) != 0x91000000U) return NO;
    unsigned rd = insn & 31U, rn = (insn >> 5U) & 31U;
    if (rn != baseReg) return NO;
    uint64_t imm = (insn >> 10U) & 0xFFFU;
    if ((insn >> 22U) & 1U) imm <<= 12;
    if (valueOut) *valueOut = base + imm;
    if (dstOut) *dstOut = rd;
    return YES;
}

static BOOL HFADecodeLDRUnsignedX(uint32_t insn, unsigned baseReg, uintptr_t base,
                                  uintptr_t *slotOut, unsigned *dstOut) {
    if ((insn & 0xFFC00000U) != 0xF9400000U) return NO;
    unsigned rn = (insn >> 5U) & 31U;
    if (rn != baseReg) return NO;
    if (slotOut) *slotOut = base + (((insn >> 10U) & 0xFFFU) * 8ULL);
    if (dstOut) *dstOut = insn & 31U;
    return YES;
}

static BOOL HFADecodeLDRLiteralX(uint32_t insn, uintptr_t pc,
                                 uintptr_t *slotOut, unsigned *dstOut) {
    if ((insn & 0xFF000000U) != 0x58000000U) return NO;
    int64_t imm = HFASignExtend((insn >> 5U) & 0x7FFFFU, 19) << 2;
    if (slotOut) *slotOut = (uintptr_t)((int64_t)pc + imm);
    if (dstOut) *dstOut = insn & 31U;
    return YES;
}

static BOOL HFADecodeBR(uint32_t insn, unsigned reg, NSString **kindOut) {
    if (((insn >> 5U) & 31U) != reg) return NO;
    if ((insn & 0xFFFFFC1FU) == 0xD61F0000U) {
        if (kindOut) *kindOut = @"BR";
        return YES;
    }
    if ((insn & 0xFFFFFC1FU) == 0xD63F0000U) {
        if (kindOut) *kindOut = @"BLR";
        return YES;
    }
    return NO;
}

static BOOL HFAIsRET(uint32_t insn) {
    return (insn & 0xFFFFFC1FU) == 0xD65F0000U;
}

static NSArray *HFANextCandidates(uintptr_t current, NSString *menuImage,
                                  NSTimeInterval deadline) {
    if (NSDate.date.timeIntervalSince1970 > deadline || !HFAExecutableAddress(current))
        return @[];

    uint32_t code[kHFAMaxInstructions] = {};
    if (!HFAReadBytes(current, code, sizeof(code))) return @[];

    NSMutableArray *candidates = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];

    auto addCandidate = ^(uintptr_t target, NSString *kind, uintptr_t instruction,
                          uintptr_t slot, BOOL indirect) {
        if (!target || target == current) return;
        NSDictionary *desc = HFADescribeTarget(target, menuImage, deadline);
        if (!desc || ![desc[@"executable"] boolValue]) return;
        NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)target];
        if ([seen containsObject:key]) return;
        [seen addObject:key];
        NSMutableDictionary *record = [NSMutableDictionary dictionaryWithDictionary:desc];
        record[@"edgeKind"] = kind ?: @"unknown";
        record[@"instructionRuntimeToken"] =
            [NSString stringWithFormat:@"0x%llX", (unsigned long long)instruction];
        record[@"indirect"] = @(indirect);
        if (slot) {
            record[@"slotRuntimeToken"] =
                [NSString stringWithFormat:@"0x%llX", (unsigned long long)slot];
        }
        [candidates addObject:record];
    };

    // Strong trampoline form: direct B. BL is accepted only for tiny BL;RET wrappers.
    for (NSUInteger i = 0; i < kHFAMaxInstructions; ++i) {
        uintptr_t pc = current + i * 4U;
        uintptr_t target = 0;
        NSString *kind = nil;
        if (!HFADecodeDirectBranch(code[i], pc, &target, &kind)) continue;
        if ([kind isEqualToString:@"B"]) {
            addCandidate(target, @"direct-B", pc, 0, NO);
        } else if (i + 1 < kHFAMaxInstructions && HFAIsRET(code[i + 1])) {
            addCandidate(target, @"direct-BL-RET", pc, 0, NO);
        }
    }

    // Register-indirect forms: ADRP+ADD+BR, ADRP+LDR+BR, or LDR literal+BR.
    for (NSUInteger i = 0; i < kHFAMaxInstructions; ++i) {
        uintptr_t pc = current + i * 4U;
        uintptr_t page = 0;
        unsigned baseReg = 0;
        if (HFADecodeADRP(code[i], pc, &page, &baseReg)) {
            uintptr_t base = page;
            unsigned addressReg = baseReg;
            for (NSUInteger j = i + 1; j < kHFAMaxInstructions && j <= i + 4; ++j) {
                uintptr_t value = 0;
                unsigned dst = 0;
                if (HFADecodeADD(code[j], addressReg, base, &value, &dst)) {
                    base = value;
                    addressReg = dst;
                    for (NSUInteger k = j + 1; k < kHFAMaxInstructions && k <= j + 4; ++k) {
                        NSString *bk = nil;
                        if (HFADecodeBR(code[k], addressReg, &bk)) {
                            addCandidate(base, @"ADRP+ADD+BR", current + k * 4U, 0, NO);
                            break;
                        }
                    }
                    continue;
                }

                uintptr_t slot = 0;
                if (HFADecodeLDRUnsignedX(code[j], addressReg, base, &slot, &dst)) {
                    for (NSUInteger k = j + 1; k < kHFAMaxInstructions && k <= j + 6; ++k) {
                        NSString *bk = nil;
                        if (!HFADecodeBR(code[k], dst, &bk)) continue;
                        uintptr_t pointee = 0;
                        if (HFAReadPointer(slot, &pointee))
                            addCandidate(pointee, @"ADRP+LDR+BR", current + k * 4U, slot, YES);
                        break;
                    }
                }
            }
        }

        uintptr_t literalSlot = 0;
        unsigned literalReg = 0;
        if (HFADecodeLDRLiteralX(code[i], pc, &literalSlot, &literalReg)) {
            for (NSUInteger k = i + 1; k < kHFAMaxInstructions && k <= i + 6; ++k) {
                NSString *bk = nil;
                if (!HFADecodeBR(code[k], literalReg, &bk)) continue;
                uintptr_t pointee = 0;
                if (HFAReadPointer(literalSlot, &pointee))
                    addCandidate(pointee, @"LDR-literal+BR", current + k * 4U, literalSlot, YES);
                break;
            }
        }
    }

    return candidates;
}
} // namespace

NSDictionary *HFAMapResolveRecursiveNativeTarget(uintptr_t startTarget,
                                                 NSString *menuImage,
                                                 NSTimeInterval deadline) {
    NSMutableArray *hops = [NSMutableArray array];
    NSMutableSet *visited = [NSMutableSet set];
    uintptr_t current = startTarget;
    NSString *status = @"unresolved";
    NSDictionary *finalTarget = nil;

    for (NSUInteger depth = 0; depth < kHFAMaxRecursiveDepth; ++depth) {
        if (NSDate.date.timeIntervalSince1970 > deadline) {
            status = @"timeout";
            break;
        }
        NSDictionary *currentDesc = HFADescribeTarget(current, menuImage, deadline);
        if (!currentDesc) {
            status = @"current-target-not-symbolizable";
            break;
        }
        NSString *key = currentDesc[@"runtimeToken"] ?: @"";
        if ([visited containsObject:key]) {
            status = @"cycle-detected";
            break;
        }
        [visited addObject:key];

        if ([currentDesc[@"externalToMenu"] boolValue]) {
            finalTarget = currentDesc;
            status = [currentDesc[@"image"] isEqualToString:@"UnityFramework"] ?
                @"resolved-external-unity-target" : @"resolved-external-non-unity-target";
            break;
        }

        NSArray *next = HFANextCandidates(current, menuImage, deadline);
        NSMutableDictionary *hop = [@{
            @"depth": @(depth),
            @"current": currentDesc,
            @"candidateCount": @(next.count),
            @"candidates": next
        } mutableCopy];

        if (next.count != 1) {
            hop[@"decision"] = next.count ? @"ambiguous-multiple-next-targets" :
                                            @"no-structural-next-target";
            [hops addObject:hop];
            [hop release];
            status = next.count ? @"ambiguous-multiple-next-targets" :
                                  @"no-structural-next-target";
            break;
        }

        NSDictionary *chosen = next.firstObject;
        hop[@"decision"] = @"unique-next-target";
        hop[@"chosen"] = chosen;
        [hops addObject:hop];
        [hop release];
        current = (uintptr_t)[chosen[@"runtimeToken"] longLongValue];
        // NSString hex -> longLongValue returns 0; parse explicitly.
        NSScanner *scanner = [NSScanner scannerWithString:chosen[@"runtimeToken"] ?: @""];
        unsigned long long parsed = 0;
        [scanner scanHexLongLong:&parsed];
        current = (uintptr_t)parsed;
        if (!current) {
            status = @"chosen-target-parse-failed";
            break;
        }
    }

    if (!finalTarget && [status isEqualToString:@"unresolved"])
        status = @"max-depth-reached";

    return @{
        @"schema": @"com.hfa.recursive-native-target/v1",
        @"status": status,
        @"startTargetRuntimeToken":
            [NSString stringWithFormat:@"0x%llX", (unsigned long long)startTarget],
        @"menuImage": menuImage ?: @"",
        @"hopCount": @(hops.count),
        @"hops": hops,
        @"finalTarget": finalTarget ?: @{},
        @"il2cppResolved": @([finalTarget[@"il2cppMethod"] isKindOfClass:NSDictionary.class]),
        @"analysisOnly": @YES,
        @"memoryWritten": @NO,
        @"codeInvoked": @NO,
        @"maxDepth": @(kHFAMaxRecursiveDepth),
        @"policy": @"bounded-executable-only+unique-edge-only+cycle-detection+fail-closed"
    };
}
