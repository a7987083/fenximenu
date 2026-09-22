#import "HFAMapStrippedActionAnalyzer.h"

#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <string.h>

static const NSUInteger kHFAActionMaxInstructions = 512;
static const NSUInteger kHFAActionMaxCalls = 64;
static const NSUInteger kHFAActionMaxBranches = 128;
static const NSUInteger kHFAActionMaxString = 192;

typedef NS_ENUM(uint8_t, HFARegKind) {
    HFARegUnknown = 0,
    HFARegImmediate,
    HFARegAddress,
    HFARegLoadedPointer,
};

typedef struct {
    HFARegKind kind;
    uint64_t value;
    uint64_t sourceRVA;
} HFARegState;

static int64_t HFASignExtend(uint64_t value, unsigned bits) {
    const uint64_t sign = 1ULL << (bits - 1);
    return (int64_t)((value ^ sign) - sign);
}

static NSString *HFAReadCStringBounded(uint64_t address) {
    if (!address) return nil;
    char bytes[kHFAActionMaxString + 1] = {};
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         (vm_size_t)kHFAActionMaxString,
                                         (vm_address_t)bytes, &copied);
    if (kr != KERN_SUCCESS || !copied) return nil;
    size_t n = strnlen(bytes, copied);
    if (!n || n >= copied) return nil;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)bytes[i];
        if (c < 0x20 || c > 0x7e) return nil;
    }
    return [NSString stringWithUTF8String:bytes];
}

static BOOL HFAReadPointer(uint64_t address, uint64_t *valueOut) {
    if (!address || !valueOut) return NO;
    uint64_t value = 0;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         sizeof(value), (vm_address_t)&value, &copied);
    if (kr != KERN_SUCCESS || copied != sizeof(value)) return NO;
    *valueOut = value;
    return YES;
}

static NSDictionary *HFARegEvidence(HFARegState reg) {
    if (reg.kind == HFARegUnknown) return @{};
    NSMutableDictionary *record = [@{
        @"kind": reg.kind == HFARegImmediate ? @"immediate" :
                  (reg.kind == HFARegAddress ? @"address" : @"loaded-pointer"),
        @"value": @(reg.value),
        @"valueHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)reg.value],
        @"sourceRVA": @(reg.sourceRVA),
        @"binding": @"local-dataflow-candidate"
    } mutableCopy];
    NSString *string = HFAReadCStringBounded(reg.value);
    if (string.length) record[@"ascii"] = string;
    return [record autorelease];
}

static uint64_t HFABranchTarget(uint64_t pc, uint32_t instruction) {
    int64_t imm26 = HFASignExtend(instruction & 0x03ffffffU, 26) << 2;
    return (uint64_t)((int64_t)pc + imm26);
}

NSDictionary *HFAMapAnalyzeStrippedActionIMP(const void *implementation,
                                              NSString *implementationPath) {
    if (!implementation || !implementationPath.length)
        return @{ @"schema": @"com.hfa.stripped-action/v1", @"status": @"missing-input",
                  @"analysisOnly": @YES, @"canonicalEligible": @NO };

    Dl_info info = {};
    if (!dladdr(implementation, &info) || !info.dli_fbase)
        return @{ @"schema": @"com.hfa.stripped-action/v1", @"status": @"dladdr-failed",
                  @"analysisOnly": @YES, @"canonicalEligible": @NO };

    uint64_t base = (uint64_t)(uintptr_t)info.dli_fbase;
    uint64_t start = (uint64_t)(uintptr_t)implementation;
    uint64_t startRVA = start - base;
    HFARegState regs[31] = {};
    NSMutableArray *calls = [NSMutableArray array];
    NSMutableArray *branches = [NSMutableArray array];
    NSUInteger decoded = 0;

    for (NSUInteger index = 0; index < kHFAActionMaxInstructions; ++index) {
        uint32_t insn = 0;
        vm_size_t copied = 0;
        uint64_t pc = start + index * 4ULL;
        if (vm_read_overwrite(mach_task_self(), (vm_address_t)pc, sizeof(insn),
                              (vm_address_t)&insn, &copied) != KERN_SUCCESS || copied != sizeof(insn)) break;
        ++decoded;
        uint64_t rva = pc - base;

        // ADRP Xd, imm
        if ((insn & 0x9f000000U) == 0x90000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFASignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                        ((insn >> 29) & 0x3U), 21) << 12;
            regs[rd] = { HFARegAddress, (pc & ~0xfffULL) + imm, rva };
            continue;
        }
        // ADR Xd, imm
        if ((insn & 0x9f000000U) == 0x10000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFASignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                        ((insn >> 29) & 0x3U), 21);
            regs[rd] = { HFARegAddress, pc + imm, rva };
            continue;
        }
        // ADD (immediate), 64-bit
        if ((insn & 0xffc00000U) == 0x91000000U) {
            unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
            uint64_t imm12 = (insn >> 10) & 0xfffU;
            if (insn & (1U << 22)) imm12 <<= 12;
            if (rn < 31 && regs[rn].kind != HFARegUnknown)
                regs[rd] = { regs[rn].kind, regs[rn].value + imm12, rva };
            continue;
        }
        // MOVZ 64-bit
        if ((insn & 0xff800000U) == 0xd2800000U) {
            unsigned rd = insn & 31U;
            uint64_t imm16 = (insn >> 5) & 0xffffU;
            unsigned shift = ((insn >> 21) & 3U) * 16U;
            regs[rd] = { HFARegImmediate, imm16 << shift, rva };
            continue;
        }
        // MOVK 64-bit
        if ((insn & 0xff800000U) == 0xf2800000U) {
            unsigned rd = insn & 31U;
            uint64_t imm16 = (insn >> 5) & 0xffffU;
            unsigned shift = ((insn >> 21) & 3U) * 16U;
            uint64_t mask = ~(0xffffULL << shift);
            uint64_t prior = regs[rd].kind == HFARegImmediate ? regs[rd].value : 0;
            regs[rd] = { HFARegImmediate, (prior & mask) | (imm16 << shift), rva };
            continue;
        }
        // LDR Xt, [Xn,#imm] unsigned immediate
        if ((insn & 0xffc00000U) == 0xf9400000U) {
            unsigned rt = insn & 31U, rn = (insn >> 5) & 31U;
            uint64_t imm = ((insn >> 10) & 0xfffU) << 3;
            if (rn < 31 && regs[rn].kind != HFARegUnknown) {
                uint64_t slot = regs[rn].value + imm, loaded = 0;
                if (HFAReadPointer(slot, &loaded)) regs[rt] = { HFARegLoadedPointer, loaded, rva };
            }
            continue;
        }
        // BL imm26
        if ((insn & 0xfc000000U) == 0x94000000U) {
            if (calls.count < kHFAActionMaxCalls) {
                uint64_t target = HFABranchTarget(pc, insn);
                NSMutableDictionary *args = [NSMutableDictionary dictionary];
                for (unsigned r = 0; r <= 7; ++r) {
                    NSDictionary *e = HFARegEvidence(regs[r]);
                    if (e.count) args[[NSString stringWithFormat:@"x%u", r]] = e;
                }
                Dl_info targetInfo = {};
                NSMutableDictionary *call = [@{
                    @"callsiteRVA": @(rva),
                    @"targetRuntime": @(target),
                    @"targetRVAIfSameImage": target >= base ? @(target - base) : @0,
                    @"arguments": args,
                    @"abi": @"arm64-x0-x7-candidate",
                    @"analysisOnly": @YES
                } mutableCopy];
                if (dladdr((const void *)(uintptr_t)target, &targetInfo) && targetInfo.dli_sname)
                    call[@"targetSymbol"] = [NSString stringWithUTF8String:targetInfo.dli_sname];
                [calls addObject:[call autorelease]];
            }
            continue;
        }
        // B imm26
        if ((insn & 0xfc000000U) == 0x14000000U) {
            if (branches.count < kHFAActionMaxBranches)
                [branches addObject:@{ @"kind": @"b", @"fromRVA": @(rva),
                                        @"targetRVAIfSameImage": @(HFABranchTarget(pc, insn) - base) }];
            continue;
        }
        // CBZ/CBNZ and TBZ/TBNZ inventories; no recursive execution.
        if ((insn & 0x7e000000U) == 0x34000000U && branches.count < kHFAActionMaxBranches)
            [branches addObject:@{ @"kind": @"cbz-cbnz", @"fromRVA": @(rva) }];
        else if ((insn & 0x7e000000U) == 0x36000000U && branches.count < kHFAActionMaxBranches)
            [branches addObject:@{ @"kind": @"tbz-tbnz", @"fromRVA": @(rva) }];

        // RET terminates this local linear window.
        if ((insn & 0xfffffc1fU) == 0xd65f0000U) break;
    }

    return @{
        @"schema": @"com.hfa.stripped-action/v1",
        @"status": decoded ? @"decoded" : @"no-readable-code",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"implementationPath": implementationPath,
        @"implementationRVA": @(startRVA),
        @"decodedInstructionCount": @(decoded),
        @"instructionBudget": @(kHFAActionMaxInstructions),
        @"calls": calls,
        @"branches": branches,
        @"capabilities": @[ @"adr", @"adrp", @"add-immediate", @"ldr-uimm",
                             @"movz", @"movk", @"bl", @"b", @"cbz-cbnz", @"tbz-tbnz",
                             @"x0-x7-local-provenance", @"bounded-cstring-probe" ],
        @"policy": @"read-only-local-dataflow-no-hook-no-callback-invocation-no-memory-write"
    };
}
