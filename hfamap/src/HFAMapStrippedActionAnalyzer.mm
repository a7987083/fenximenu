#import "HFAMapStrippedActionAnalyzer.h"
#import "HFAIL2CPPMethodIndex.h"

#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#include <string.h>

static const NSUInteger kHFAActionMaxInstructions = 2048;
static const NSUInteger kHFAActionMaxInstructionsPerBlock = 96;
static const NSUInteger kHFAActionMaxBlocks = 96;
static const NSUInteger kHFAActionMaxDepth = 12;
static const NSUInteger kHFAActionMaxCalls = 128;
static const NSUInteger kHFAActionMaxBranches = 256;
static const NSUInteger kHFAActionMaxString = 192;
static const NSUInteger kHFAStubSummaryMaxInstructions = 16;
static const NSUInteger kHFAMaxMessageChains = 64;

typedef NS_ENUM(uint8_t, HFARegKind) {
    HFARegUnknown = 0,
    HFARegImmediate,
    HFARegAddress,
    HFARegLoadedPointer,
    HFARegCallResult,
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

static BOOL HFARegHasConcreteValue(HFARegState reg) {
    return reg.kind == HFARegImmediate || reg.kind == HFARegAddress || reg.kind == HFARegLoadedPointer;
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
    if (reg.kind == HFARegCallResult) {
        return @{ @"kind": @"call-result", @"sourceRVA": @(reg.sourceRVA),
                  @"binding": @"arm64-x0-return-provenance", @"concreteValueKnown": @NO };
    }
    NSMutableDictionary *record = [@{
        @"kind": reg.kind == HFARegImmediate ? @"immediate" :
                  (reg.kind == HFARegAddress ? @"address" : @"loaded-pointer"),
        @"value": @(reg.value),
        @"valueHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)reg.value],
        @"sourceRVA": @(reg.sourceRVA),
        @"binding": @"cfg-dataflow-candidate",
        @"concreteValueKnown": @YES
    } mutableCopy];
    NSString *string = HFAReadCStringBounded(reg.value);
    if (string.length) record[@"ascii"] = string;
    NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)reg.value);
    if (method) record[@"il2cppMethod"] = method;
    return [record autorelease];
}

static BOOL HFAKnownObjCRuntimeSymbol(NSString *symbol) {
    if (!symbol.length) return NO;
    static NSArray<NSString *> *tokens;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        tokens = [[NSArray alloc] initWithObjects:
            @"objc_msgSend", @"objc_msgSendSuper", @"objc_msgSendSuper2",
            @"objc_opt_class", @"objc_opt_isKindOfClass", @"objc_opt_respondsToSelector",
            @"objc_getClass", @"object_getClass", @"class_getMethodImplementation", nil];
    });
    for (NSString *token in tokens)
        if ([symbol containsString:token]) return YES;
    return NO;
}

static NSString *HFAExactKnownRuntimeSymbol(uint64_t target) {
    if (!target) return nil;
    static NSArray<NSString *> *names;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        names = [[NSArray alloc] initWithObjects:
            @"objc_msgSend", @"objc_msgSendSuper", @"objc_msgSendSuper2",
            @"objc_opt_class", @"objc_opt_isKindOfClass", @"objc_opt_respondsToSelector",
            @"objc_getClass", @"object_getClass", @"class_getMethodImplementation", nil];
    });
    for (NSString *name in names) {
        void *resolved = dlsym(RTLD_DEFAULT, name.UTF8String);
        if (resolved && (uint64_t)(uintptr_t)resolved == target) return name;
    }
    return nil;
}

static NSDictionary *HFARuntimeTargetClassification(uint64_t target, HFARegState regs[31]) {
    if (!target) return @{};
    NSMutableDictionary *record = [@{
        @"targetRuntime": @(target),
        @"targetHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)target],
        @"classification": @"external-or-unclassified-runtime-target",
        @"analysisOnly": @YES
    } mutableCopy];
    Dl_info info = {};
    if (dladdr((const void *)(uintptr_t)target, &info)) {
        if (info.dli_fname) {
            NSString *path = [NSString stringWithUTF8String:info.dli_fname] ?: @"";
            record[@"targetPath"] = path;
            record[@"targetImage"] = path.lastPathComponent ?: @"?";
            if (info.dli_fbase)
                record[@"targetOffsetFromLoadBase"] = [NSString stringWithFormat:@"0x%llX",
                    (unsigned long long)(target - (uint64_t)(uintptr_t)info.dli_fbase)];
        }
        if (info.dli_sname) {
            NSString *symbol = [NSString stringWithUTF8String:info.dli_sname] ?: @"";
            if (symbol.length) record[@"targetSymbol"] = symbol;
        }
    }
    NSString *symbol = record[@"targetSymbol"];
    NSString *exact = HFAExactKnownRuntimeSymbol(target);
    if (exact.length) {
        symbol = exact;
        record[@"targetSymbol"] = exact;
        record[@"symbolResolution"] = @"exact-dlsym-runtime-address";
    } else if (symbol.length) {
        record[@"symbolResolution"] = @"dladdr-nearest-symbol";
    }
    BOOL objcRuntime = HFAKnownObjCRuntimeSymbol(symbol);
    if (objcRuntime) {
        record[@"classification"] = @"objc-runtime-dispatch";
        record[@"objcRuntimeDispatch"] = @YES;
        record[@"objcRuntimeFamily"] = [symbol containsString:@"objc_msgSend"] ? @"message-send" : @"objc-runtime-helper";
        if (regs[0].kind != HFARegUnknown) record[@"receiverEvidence"] = HFARegEvidence(regs[0]);
        if (HFARegHasConcreteValue(regs[1])) {
            record[@"selectorRegisterEvidence"] = HFARegEvidence(regs[1]);
            NSString *selector = HFAReadCStringBounded(regs[1].value);
            if (selector.length) {
                record[@"selectorCandidate"] = selector;
                record[@"selectorResolution"] = @"bounded-x1-cstring-read";
            }
        }
    } else {
        record[@"objcRuntimeDispatch"] = @NO;
    }
    NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)target);
    if (method) {
        record[@"classification"] = [method[@"matchType"] isEqualToString:@"exact-method-entry"]
            ? @"assembly-csharp-method-pointer" : @"assembly-csharp-containing-method";
        record[@"il2cppMethod"] = method;
    }
    return [record autorelease];
}

static uint64_t HFABranchTarget26(uint64_t pc, uint32_t instruction) {
    int64_t imm26 = HFASignExtend(instruction & 0x03ffffffU, 26) << 2;
    return (uint64_t)((int64_t)pc + imm26);
}

static uint64_t HFABranchTarget19(uint64_t pc, uint32_t instruction) {
    int64_t imm19 = HFASignExtend((instruction >> 5) & 0x7ffffU, 19) << 2;
    return (uint64_t)((int64_t)pc + imm19);
}

static uint64_t HFABranchTarget14(uint64_t pc, uint32_t instruction) {
    int64_t imm14 = HFASignExtend((instruction >> 5) & 0x3fffU, 14) << 2;
    return (uint64_t)((int64_t)pc + imm14);
}

static BOOL HFASameImage(uint64_t address, const void *imageBase) {
    if (!address || !imageBase) return NO;
    Dl_info info = {};
    return dladdr((const void *)(uintptr_t)address, &info) && info.dli_fbase == imageBase;
}

static void HFAApplySimpleDataflowInstruction(uint32_t insn, uint64_t pc, uint64_t base, HFARegState regs[31]) {
    uint64_t rva = pc - base;
    if ((insn & 0x9f000000U) == 0x90000000U) {
        unsigned rd = insn & 31U;
        int64_t imm = HFASignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) | ((insn >> 29) & 3U), 21) << 12;
        if (rd < 31) regs[rd] = { HFARegAddress, (pc & ~0xfffULL) + imm, rva };
    } else if ((insn & 0x9f000000U) == 0x10000000U) {
        unsigned rd = insn & 31U;
        int64_t imm = HFASignExtend((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) | ((insn >> 29) & 3U), 21);
        if (rd < 31) regs[rd] = { HFARegAddress, pc + imm, rva };
    } else if ((insn & 0xffe0ffe0U) == 0xaa0003e0U) {
        unsigned rd = insn & 31U, rm = (insn >> 16) & 31U;
        if (rd < 31 && rm < 31) { regs[rd] = regs[rm]; regs[rd].sourceRVA = rva; }
    } else if ((insn & 0xffc00000U) == 0x91000000U) {
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t imm12 = (insn >> 10) & 0xfffU;
        if (insn & (1U << 22)) imm12 <<= 12;
        if (rd < 31 && rn < 31 && HFARegHasConcreteValue(regs[rn])) regs[rd] = { regs[rn].kind, regs[rn].value + imm12, rva };
    } else if ((insn & 0xff800000U) == 0xd2800000U) {
        unsigned rd = insn & 31U; uint64_t imm16 = (insn >> 5) & 0xffffU; unsigned shift = ((insn >> 21) & 3U) * 16U;
        if (rd < 31) regs[rd] = { HFARegImmediate, imm16 << shift, rva };
    } else if ((insn & 0xff800000U) == 0xf2800000U) {
        unsigned rd = insn & 31U; uint64_t imm16 = (insn >> 5) & 0xffffU; unsigned shift = ((insn >> 21) & 3U) * 16U;
        uint64_t mask = ~(0xffffULL << shift); uint64_t prior = (rd < 31 && regs[rd].kind == HFARegImmediate) ? regs[rd].value : 0;
        if (rd < 31) regs[rd] = { HFARegImmediate, (prior & mask) | (imm16 << shift), rva };
    } else if ((insn & 0xff000000U) == 0x58000000U) {
        unsigned rt = insn & 31U; uint64_t slot = HFABranchTarget19(pc, insn), loaded = 0;
        if (rt < 31 && HFAReadPointer(slot, &loaded)) regs[rt] = { HFARegLoadedPointer, loaded, rva };
    } else if ((insn & 0xffc00000U) == 0xf9400000U) {
        unsigned rt = insn & 31U, rn = (insn >> 5) & 31U; uint64_t imm = ((insn >> 10) & 0xfffU) << 3;
        if (rt < 31 && rn < 31 && HFARegHasConcreteValue(regs[rn])) {
            uint64_t loaded = 0; if (HFAReadPointer(regs[rn].value + imm, &loaded)) regs[rt] = { HFARegLoadedPointer, loaded, rva };
        }
    } else if ((insn & 0xffe00c00U) == 0xf8400000U) {
        unsigned rt = insn & 31U, rn = (insn >> 5) & 31U; int64_t imm9 = HFASignExtend((insn >> 12) & 0x1ffU, 9);
        if (rt < 31 && rn < 31 && HFARegHasConcreteValue(regs[rn])) {
            uint64_t loaded = 0, slot = (uint64_t)((int64_t)regs[rn].value + imm9);
            if (HFAReadPointer(slot, &loaded)) regs[rt] = { HFARegLoadedPointer, loaded, rva };
        }
    }
}

static NSDictionary *HFASummarizeSameImageTailStub(uint64_t target, const void *imageBase,
                                                    uint64_t base, HFARegState callerRegs[31]) {
    if (!HFASameImage(target, imageBase)) return nil;
    HFARegState regs[31] = {};
    memcpy(regs, callerRegs, sizeof(regs));
    for (NSUInteger i = 0; i < kHFAStubSummaryMaxInstructions; ++i) {
        uint64_t pc = target + i * 4ULL;
        if (!HFASameImage(pc, imageBase)) break;
        uint32_t insn = 0; vm_size_t copied = 0;
        if (vm_read_overwrite(mach_task_self(), (vm_address_t)pc, sizeof(insn), (vm_address_t)&insn, &copied) != KERN_SUCCESS || copied != sizeof(insn)) break;
        HFAApplySimpleDataflowInstruction(insn, pc, base, regs);
        if ((insn & 0xfffffc1fU) == 0xd61f0000U || (insn & 0xfffffc1fU) == 0xd63f0000U) {
            unsigned rn = (insn >> 5) & 31U;
            if (rn >= 31 || !HFARegHasConcreteValue(regs[rn])) return nil;
            NSDictionary *runtime = HFARuntimeTargetClassification(regs[rn].value, callerRegs);
            if (![runtime[@"objcRuntimeDispatch"] boolValue]) return nil;
            return @{ @"semantic": @"objc-message-send-stub", @"stubRuntime": @(target),
                      @"stubRVA": @(target - base), @"tailKind": ((insn & 0xfffffc1fU) == 0xd61f0000U ? @"br" : @"blr"),
                      @"tailRegister": [NSString stringWithFormat:@"x%u", rn], @"runtimeTarget": runtime,
                      @"instructionCount": @(i + 1), @"analysisOnly": @YES };
        }
        if ((insn & 0xfffffc1fU) == 0xd65f0000U) break;
    }
    return nil;
}

static void HFAClobberCallerSaved(HFARegState regs[31], uint64_t callsiteRVA, BOOL preserveReturn) {
    for (unsigned r = 0; r <= 18; ++r) regs[r] = { HFARegUnknown, 0, callsiteRVA };
    if (preserveReturn) regs[0] = { HFARegCallResult, 0, callsiteRVA };
}

static NSMutableDictionary *HFACallRecord(uint64_t base, uint64_t rva, uint64_t target,
                                           NSString *kind, HFARegState regs[31]) {
    NSMutableDictionary *args = [NSMutableDictionary dictionary];
    for (unsigned r = 0; r <= 7; ++r) {
        NSDictionary *e = HFARegEvidence(regs[r]); if (e.count) args[[NSString stringWithFormat:@"x%u", r]] = e;
    }
    NSMutableDictionary *call = [@{ @"kind": kind ?: @"call", @"callsiteRVA": @(rva),
        @"targetRuntime": @(target), @"targetRVAIfSameImage": target >= base ? @(target - base) : @0,
        @"arguments": args, @"abi": @"arm64-x0-x7-candidate", @"runtimeTarget": HFARuntimeTargetClassification(target, regs),
        @"analysisOnly": @YES, @"canonicalEligible": @NO } mutableCopy];
    NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)target);
    if (method) {
        call[@"il2cppMethod"] = method;
        call[@"correlation"] = [method[@"matchType"] isEqualToString:@"exact-method-entry"]
            ? @"exact-method-pointer-address" : @"containing-method-range";
    }
    return [call autorelease];
}

static NSData *HFARegSnapshot(HFARegState regs[31]) { return [NSData dataWithBytes:regs length:sizeof(HFARegState) * 31U]; }
static void HFARegRestore(NSData *data, HFARegState regs[31]) {
    memset(regs, 0, sizeof(HFARegState) * 31U);
    if (data.length >= sizeof(HFARegState) * 31U) memcpy(regs, data.bytes, sizeof(HFARegState) * 31U);
}

static void HFAEnqueueBlock(NSMutableArray *queue, NSMutableSet *scheduled, uint64_t pc,
                            NSUInteger depth, HFARegState regs[31], const void *imageBase) {
    if (!pc || depth > kHFAActionMaxDepth || queue.count >= kHFAActionMaxBlocks || !HFASameImage(pc, imageBase)) return;
    NSNumber *key = @(pc); if ([scheduled containsObject:key]) return;
    [scheduled addObject:key];
    [queue addObject:@{ @"pc": key, @"depth": @(depth), @"regs": HFARegSnapshot(regs) }];
}

NSDictionary *HFAMapAnalyzeStrippedActionIMP(const void *implementation, NSString *implementationPath) {
    if (!implementation || !implementationPath.length)
        return @{ @"schema": @"com.hfa.stripped-action/v5", @"status": @"missing-input", @"analysisOnly": @YES, @"canonicalEligible": @NO };

    NSTimeInterval indexDeadline = NSDate.date.timeIntervalSince1970 + 0.75;
    NSDictionary *methodIndex = HFAIL2CPPBuildMethodIndex(indexDeadline);
    Dl_info info = {};
    if (!dladdr(implementation, &info) || !info.dli_fbase)
        return @{ @"schema": @"com.hfa.stripped-action/v5", @"status": @"dladdr-failed", @"analysisOnly": @YES,
                  @"canonicalEligible": @NO, @"il2cppMethodIndex": methodIndex ?: @{} };

    uint64_t base = (uint64_t)(uintptr_t)info.dli_fbase, start = (uint64_t)(uintptr_t)implementation, startRVA = start - base;
    NSMutableArray *calls = [NSMutableArray array], *branches = [NSMutableArray array], *indirectBranches = [NSMutableArray array];
    NSMutableArray *blocks = [NSMutableArray array], *messageChains = [NSMutableArray array];
    NSMutableArray *queue = [NSMutableArray array]; NSMutableSet *scheduled = [NSMutableSet set], *visited = [NSMutableSet set];
    NSUInteger decoded = 0, blockCount = 0, il2cppCorrelations = 0, unresolvedIndirectBranches = 0;
    HFARegState initialRegs[31] = {}; HFAEnqueueBlock(queue, scheduled, start, 0, initialRegs, info.dli_fbase);

    while (queue.count && blockCount < kHFAActionMaxBlocks && decoded < kHFAActionMaxInstructions) {
        NSDictionary *item = [[queue objectAtIndex:0] retain]; [queue removeObjectAtIndex:0];
        uint64_t blockStart = [item[@"pc"] unsignedLongLongValue]; NSUInteger depth = [item[@"depth"] unsignedIntegerValue];
        NSNumber *blockKey = @(blockStart); if ([visited containsObject:blockKey]) { [item release]; continue; }
        [visited addObject:blockKey]; ++blockCount;
        HFARegState regs[31] = {}; HFARegRestore(item[@"regs"], regs);
        [blocks addObject:@{ @"startRVA": @(blockStart - base), @"depth": @(depth) }]; [item release];

        for (NSUInteger index = 0; index < kHFAActionMaxInstructionsPerBlock && decoded < kHFAActionMaxInstructions; ++index) {
            uint64_t pc = blockStart + index * 4ULL; if (!HFASameImage(pc, info.dli_fbase)) break;
            uint32_t insn = 0; vm_size_t copied = 0;
            if (vm_read_overwrite(mach_task_self(), (vm_address_t)pc, sizeof(insn), (vm_address_t)&insn, &copied) != KERN_SUCCESS || copied != sizeof(insn)) break;
            ++decoded; uint64_t rva = pc - base;

            if ((insn & 0x9f000000U) == 0x90000000U || (insn & 0x9f000000U) == 0x10000000U ||
                (insn & 0xffe0ffe0U) == 0xaa0003e0U || (insn & 0xffc00000U) == 0x91000000U ||
                (insn & 0xff800000U) == 0xd2800000U || (insn & 0xff800000U) == 0xf2800000U ||
                (insn & 0xff000000U) == 0x58000000U || (insn & 0xffc00000U) == 0xf9400000U ||
                (insn & 0xffe00c00U) == 0xf8400000U) {
                HFAApplySimpleDataflowInstruction(insn, pc, base, regs); continue;
            }

            if ((insn & 0xfc000000U) == 0x94000000U) {
                uint64_t target = HFABranchTarget26(pc, insn);
                HFARegState preCall[31]; memcpy(preCall, regs, sizeof(preCall));
                NSMutableDictionary *call = HFACallRecord(base, rva, target, @"bl-direct", preCall);
                NSDictionary *stub = HFASummarizeSameImageTailStub(target, info.dli_fbase, base, preCall);
                if (stub) {
                    call[@"callSummary"] = stub; call[@"semantic"] = @"objc-message-send-stub";
                    NSDictionary *rt = stub[@"runtimeTarget"];
                    if (messageChains.count < kHFAMaxMessageChains) [messageChains addObject:@{
                        @"callsiteRVA": @(rva), @"viaStubRVA": stub[@"stubRVA"] ?: @0,
                        @"runtimeTarget": rt ?: @{}, @"selectorCandidate": rt[@"selectorCandidate"] ?: @"",
                        @"receiverEvidence": rt[@"receiverEvidence"] ?: @{}, @"returnRegister": @"x0",
                        @"returnProvenance": @"objc-message-result", @"analysisOnly": @YES }];
                }
                if (call[@"il2cppMethod"]) ++il2cppCorrelations;
                if (calls.count < kHFAActionMaxCalls) [calls addObject:call];
                if (!stub) HFAEnqueueBlock(queue, scheduled, target, depth + 1, preCall, info.dli_fbase);
                HFAClobberCallerSaved(regs, rva, YES);
                continue;
            }

            if ((insn & 0xfffffc1fU) == 0xd63f0000U) {
                unsigned rn = (insn >> 5) & 31U; HFARegState preCall[31]; memcpy(preCall, regs, sizeof(preCall));
                if (rn < 31 && HFARegHasConcreteValue(preCall[rn])) {
                    uint64_t target = preCall[rn].value; NSMutableDictionary *call = HFACallRecord(base, rva, target, @"blr-register", preCall);
                    call[@"targetRegister"] = [NSString stringWithFormat:@"x%u", rn]; call[@"targetRegisterEvidence"] = HFARegEvidence(preCall[rn]);
                    if (call[@"il2cppMethod"]) ++il2cppCorrelations;
                    if (calls.count < kHFAActionMaxCalls) [calls addObject:call];
                    NSDictionary *rt = call[@"runtimeTarget"];
                    if ([rt[@"objcRuntimeDispatch"] boolValue] && messageChains.count < kHFAMaxMessageChains)
                        [messageChains addObject:@{ @"callsiteRVA": @(rva), @"runtimeTarget": rt, @"selectorCandidate": rt[@"selectorCandidate"] ?: @"",
                            @"receiverEvidence": rt[@"receiverEvidence"] ?: @{}, @"returnRegister": @"x0", @"returnProvenance": @"objc-message-result", @"analysisOnly": @YES }];
                    HFAEnqueueBlock(queue, scheduled, target, depth + 1, preCall, info.dli_fbase);
                    HFAClobberCallerSaved(regs, rva, YES);
                } else { ++unresolvedIndirectBranches; HFAClobberCallerSaved(regs, rva, YES); }
                continue;
            }

            if ((insn & 0xfffffc1fU) == 0xd61f0000U) {
                unsigned rn = (insn >> 5) & 31U;
                NSMutableDictionary *branch = [@{ @"kind": @"br-register", @"fromRVA": @(rva),
                    @"targetRegister": [NSString stringWithFormat:@"x%u", rn], @"analysisOnly": @YES, @"canonicalEligible": @NO } mutableCopy];
                if (rn < 31 && HFARegHasConcreteValue(regs[rn])) {
                    uint64_t target = regs[rn].value; branch[@"targetRuntime"] = @(target); branch[@"targetRegisterEvidence"] = HFARegEvidence(regs[rn]);
                    branch[@"runtimeTarget"] = HFARuntimeTargetClassification(target, regs);
                    NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)target);
                    if (method) { branch[@"il2cppMethod"] = method; branch[@"correlation"] = method[@"matchType"] ?: @"containing-method-range"; ++il2cppCorrelations; }
                    NSDictionary *rt = branch[@"runtimeTarget"];
                    if ([rt[@"objcRuntimeDispatch"] boolValue] && messageChains.count < kHFAMaxMessageChains)
                        [messageChains addObject:@{ @"fromRVA": @(rva), @"runtimeTarget": rt, @"selectorCandidate": rt[@"selectorCandidate"] ?: @"",
                            @"receiverEvidence": rt[@"receiverEvidence"] ?: @{}, @"tailCall": @YES, @"returnRegister": @"x0", @"analysisOnly": @YES }];
                    HFAEnqueueBlock(queue, scheduled, target, depth + 1, regs, info.dli_fbase);
                } else { branch[@"resolutionStatus"] = @"register-target-unresolved"; ++unresolvedIndirectBranches; }
                if (indirectBranches.count < kHFAActionMaxBranches) [indirectBranches addObject:branch]; [branch release]; break;
            }

            if ((insn & 0xfc000000U) == 0x14000000U) {
                uint64_t target = HFABranchTarget26(pc, insn); if (branches.count < kHFAActionMaxBranches)
                    [branches addObject:@{ @"kind": @"b", @"fromRVA": @(rva), @"targetRVAIfSameImage": target >= base ? @(target-base) : @0 }];
                HFAEnqueueBlock(queue, scheduled, target, depth + 1, regs, info.dli_fbase); break;
            }
            if ((insn & 0x7e000000U) == 0x34000000U) {
                uint64_t target = HFABranchTarget19(pc, insn); if (branches.count < kHFAActionMaxBranches)
                    [branches addObject:@{ @"kind": @"cbz-cbnz", @"fromRVA": @(rva), @"targetRVAIfSameImage": target >= base ? @(target-base) : @0 }];
                HFAEnqueueBlock(queue, scheduled, target, depth + 1, regs, info.dli_fbase); HFAEnqueueBlock(queue, scheduled, pc+4, depth+1, regs, info.dli_fbase); break;
            }
            if ((insn & 0x7e000000U) == 0x36000000U) {
                uint64_t target = HFABranchTarget14(pc, insn); if (branches.count < kHFAActionMaxBranches)
                    [branches addObject:@{ @"kind": @"tbz-tbnz", @"fromRVA": @(rva), @"targetRVAIfSameImage": target >= base ? @(target-base) : @0 }];
                HFAEnqueueBlock(queue, scheduled, target, depth + 1, regs, info.dli_fbase); HFAEnqueueBlock(queue, scheduled, pc+4, depth+1, regs, info.dli_fbase); break;
            }
            if ((insn & 0xff000010U) == 0x54000000U) {
                uint64_t target = HFABranchTarget19(pc, insn); if (branches.count < kHFAActionMaxBranches)
                    [branches addObject:@{ @"kind": @"b-cond", @"fromRVA": @(rva), @"targetRVAIfSameImage": target >= base ? @(target-base) : @0 }];
                HFAEnqueueBlock(queue, scheduled, target, depth + 1, regs, info.dli_fbase); HFAEnqueueBlock(queue, scheduled, pc+4, depth+1, regs, info.dli_fbase); break;
            }
            if ((insn & 0xfffffc1fU) == 0xd65f0000U) break;
        }
    }

    NSUInteger objcRuntimeDispatchCount = 0; NSMutableArray *objcRuntimeDispatches = [NSMutableArray array];
    for (NSDictionary *call in calls) { NSDictionary *target = call[@"runtimeTarget"];
        if ([target[@"objcRuntimeDispatch"] boolValue]) { ++objcRuntimeDispatchCount; if (objcRuntimeDispatches.count < 64)
            [objcRuntimeDispatches addObject:@{ @"source": @"call", @"callsiteRVA": call[@"callsiteRVA"] ?: @0, @"kind": call[@"kind"] ?: @"call", @"runtimeTarget": target }]; }
        NSDictionary *stub = call[@"callSummary"][@"runtimeTarget"];
        if ([stub[@"objcRuntimeDispatch"] boolValue]) { ++objcRuntimeDispatchCount; if (objcRuntimeDispatches.count < 64)
            [objcRuntimeDispatches addObject:@{ @"source": @"same-image-stub", @"callsiteRVA": call[@"callsiteRVA"] ?: @0, @"runtimeTarget": stub }]; }
    }
    for (NSDictionary *branch in indirectBranches) { NSDictionary *target = branch[@"runtimeTarget"];
        if ([target[@"objcRuntimeDispatch"] boolValue]) { ++objcRuntimeDispatchCount; if (objcRuntimeDispatches.count < 64)
            [objcRuntimeDispatches addObject:@{ @"source": @"indirect-branch", @"fromRVA": branch[@"fromRVA"] ?: @0, @"kind": branch[@"kind"] ?: @"branch", @"runtimeTarget": target }]; }
    }

    return @{ @"schema": @"com.hfa.stripped-action/v5", @"status": decoded ? @"cfg-decoded" : @"no-readable-code",
        @"analysisOnly": @YES, @"canonicalEligible": @NO, @"implementationPath": implementationPath,
        @"implementationRVA": @(startRVA), @"decodedInstructionCount": @(decoded), @"instructionBudget": @(kHFAActionMaxInstructions),
        @"blockCount": @(blockCount), @"blockBudget": @(kHFAActionMaxBlocks), @"maxDepth": @(kHFAActionMaxDepth),
        @"blocks": blocks, @"calls": calls, @"branches": branches, @"indirectBranches": indirectBranches,
        @"unresolvedIndirectBranchCount": @(unresolvedIndirectBranches), @"objcRuntimeDispatchCount": @(objcRuntimeDispatchCount),
        @"objcRuntimeDispatches": objcRuntimeDispatches, @"objcMessageChainCount": @(messageChains.count), @"messageChains": messageChains,
        @"il2cppMethodIndex": methodIndex ?: @{}, @"il2cppCorrelationCount": @(il2cppCorrelations),
        @"capabilities": @[ @"bounded-cfg-worklist", @"adr", @"adrp", @"add-immediate", @"mov-register", @"ldr-literal",
            @"ldr-uimm", @"ldur", @"movz", @"movk", @"bl", @"blr", @"br", @"b", @"b-cond", @"cbz-cbnz", @"tbz-tbnz",
            @"same-image-helper-traversal", @"same-image-objc-tail-stub-summary", @"arm64-call-return-clobber-model",
            @"x0-return-provenance", @"objc-message-chain", @"x0-x7-cfg-provenance", @"bounded-cstring-probe",
            @"assembly-csharp-method-pointer-correlation", @"assembly-csharp-containing-method-range",
            @"dladdr-runtime-target-classification", @"dlsym-known-objc-runtime-match", @"objc-msgsend-family-classification",
            @"x1-selector-candidate", @"x0-receiver-provenance" ],
        @"referenceModel": @"verify.dylib-native-dispatch-plus-h5gg-1.9.6-offset-to-method",
        @"policy": @"read-only-bounded-cfg-no-hook-no-selector-invocation-no-memory-write" };
}
