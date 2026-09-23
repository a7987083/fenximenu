#import "HFAMapFeatureContextAnalyzer.h"
#import "HFAIL2CPPMethodIndex.h"

#import <objc/runtime.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <string.h>

static const NSUInteger kHFAContextMaxInstructions = 768;
static const NSUInteger kHFAContextMaxBlocks = 64;
static const NSUInteger kHFAContextMaxInstructionsPerBlock = 80;
static const NSUInteger kHFAContextMaxDepth = 10;
static const NSUInteger kHFAContextMaxBranches = 128;
static const NSUInteger kHFAContextMaxObjCEvaluations = 64;
static const NSUInteger kHFAContextMaxMethodLinks = 64;

typedef struct {
    BOOL known;
    uint64_t value;
    uint64_t sourceRVA;
    const char *origin;
} HFAContextReg;

typedef struct {
    BOOL valid;
    BOOL known;
    uint64_t lhs;
    uint64_t rhs;
    uint64_t sourceRVA;
    const char *kind;
} HFAContextFlags;

static int64_t HFASignExtendContext(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL HFAContextRead(uint64_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         (vm_size_t)size, (vm_address_t)buffer, &copied);
    return kr == KERN_SUCCESS && copied == size;
}

static NSString *HFAContextCString(uint64_t address) {
    if (!address) return nil;
    char bytes[193] = {};
    vm_size_t copied = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)address, 192,
                          (vm_address_t)bytes, &copied) != KERN_SUCCESS || !copied) return nil;
    size_t n = strnlen(bytes, copied);
    if (!n || n >= copied) return nil;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)bytes[i];
        if (c < 0x20 || c > 0x7e) return nil;
    }
    return [NSString stringWithUTF8String:bytes];
}

static BOOL HFAContextSameImage(uint64_t address, const void *imageBase) {
    if (!address || !imageBase) return NO;
    Dl_info info = {};
    return dladdr((const void *)(uintptr_t)address, &info) && info.dli_fbase == imageBase;
}

static uint64_t HFAContextBranch26(uint64_t pc, uint32_t insn) {
    return (uint64_t)((int64_t)pc + (HFASignExtendContext(insn & 0x03ffffffU, 26) << 2));
}
static uint64_t HFAContextBranch19(uint64_t pc, uint32_t insn) {
    return (uint64_t)((int64_t)pc + (HFASignExtendContext((insn >> 5) & 0x7ffffU, 19) << 2));
}
static uint64_t HFAContextBranch14(uint64_t pc, uint32_t insn) {
    return (uint64_t)((int64_t)pc + (HFASignExtendContext((insn >> 5) & 0x3fffU, 14) << 2));
}

static NSDictionary *HFAContextRegEvidence(HFAContextReg reg) {
    if (!reg.known) return @{};
    NSMutableDictionary *d = [@{
        @"known": @YES,
        @"value": @(reg.value),
        @"valueHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)reg.value],
        @"sourceRVA": @(reg.sourceRVA),
        @"origin": reg.origin ? [NSString stringWithUTF8String:reg.origin] : @"dataflow"
    } mutableCopy];
    NSString *ascii = HFAContextCString(reg.value);
    if (ascii.length) d[@"ascii"] = ascii;
    NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)reg.value);
    if (method) d[@"il2cppMethod"] = method;
    return [d autorelease];
}

static BOOL HFAContextObjectIsKindOfClass(id object, Class candidate) {
    if (!object || !candidate) return NO;
    Class cls = object_getClass(object);
    if (class_isMetaClass(cls)) {
        // For a Class receiver, compare the class object first, then its superclass chain.
        Class represented = (Class)object;
        for (Class c = represented; c; c = class_getSuperclass(c)) if (c == candidate) return YES;
        return NO;
    }
    for (Class c = cls; c; c = class_getSuperclass(c)) if (c == candidate) return YES;
    return NO;
}

static NSString *HFAContextSelectorName(uint64_t selectorValue) {
    NSString *ascii = HFAContextCString(selectorValue);
    if (ascii.length) return ascii;
    return nil;
}

// Recognize the common three-instruction dyld/objc veneer:
// ADRP Xn, page ; LDR Xn,[Xn,#imm] ; BR Xn.
static uint64_t HFAContextResolveTailStub(uint64_t target, const void *imageBase) {
    if (!HFAContextSameImage(target, imageBase)) return 0;
    uint32_t words[3] = {};
    if (!HFAContextRead(target, words, sizeof(words))) return 0;
    if ((words[0] & 0x9f000000U) != 0x90000000U) return 0;
    unsigned rd = words[0] & 31U;
    int64_t imm = HFASignExtendContext((((uint64_t)(words[0] >> 5) & 0x7ffffULL) << 2) |
                                       ((words[0] >> 29) & 3U), 21) << 12;
    uint64_t page = (target & ~0xfffULL) + imm;
    if ((words[1] & 0xffc00000U) != 0xf9400000U) return 0;
    unsigned rt = words[1] & 31U, rn = (words[1] >> 5) & 31U;
    if (rt != rd || rn != rd) return 0;
    uint64_t off = ((words[1] >> 10) & 0xfffU) << 3;
    if ((words[2] & 0xfffffc1fU) != 0xd61f0000U || ((words[2] >> 5) & 31U) != rd) return 0;
    uint64_t resolved = 0;
    return HFAContextRead(page + off, &resolved, sizeof(resolved)) ? resolved : 0;
}

static BOOL HFAContextIsObjCMessageSend(uint64_t address) {
    if (!address) return NO;
    void *msg = dlsym(RTLD_DEFAULT, "objc_msgSend");
    void *super1 = dlsym(RTLD_DEFAULT, "objc_msgSendSuper");
    void *super2 = dlsym(RTLD_DEFAULT, "objc_msgSendSuper2");
    return address == (uint64_t)(uintptr_t)msg || address == (uint64_t)(uintptr_t)super1 ||
           address == (uint64_t)(uintptr_t)super2;
}

static BOOL HFAContextApplySimple(uint32_t insn, uint64_t pc, uint64_t base,
                                  HFAContextReg regs[31], HFAContextFlags *flags) {
    uint64_t rva = pc - base;
    if ((insn & 0x9f000000U) == 0x90000000U) {
        unsigned rd = insn & 31U;
        int64_t imm = HFASignExtendContext((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                           ((insn >> 29) & 3U), 21) << 12;
        if (rd < 31) regs[rd] = { YES, (pc & ~0xfffULL) + imm, rva, "adrp" };
        return YES;
    }
    if ((insn & 0x9f000000U) == 0x10000000U) {
        unsigned rd = insn & 31U;
        int64_t imm = HFASignExtendContext((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                           ((insn >> 29) & 3U), 21);
        if (rd < 31) regs[rd] = { YES, pc + imm, rva, "adr" };
        return YES;
    }
    if ((insn & 0xffe0ffe0U) == 0xaa0003e0U) {
        unsigned rd = insn & 31U, rm = (insn >> 16) & 31U;
        if (rd < 31 && rm < 31) { regs[rd] = regs[rm]; regs[rd].sourceRVA = rva; }
        return YES;
    }
    if ((insn & 0xffc00000U) == 0x91000000U) {
        unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t imm = (insn >> 10) & 0xfffU; if (insn & (1U << 22)) imm <<= 12;
        if (rd < 31 && rn < 31 && regs[rn].known) {
            regs[rd] = { YES, regs[rn].value + imm, rva, regs[rn].origin };
        }
        return YES;
    }
    if ((insn & 0xff800000U) == 0xd2800000U) {
        unsigned rd = insn & 31U, shift = ((insn >> 21) & 3U) * 16U;
        uint64_t imm = ((uint64_t)(insn >> 5) & 0xffffU) << shift;
        if (rd < 31) regs[rd] = { YES, imm, rva, "movz" };
        return YES;
    }
    if ((insn & 0xff800000U) == 0xf2800000U) {
        unsigned rd = insn & 31U, shift = ((insn >> 21) & 3U) * 16U;
        uint64_t imm = ((uint64_t)(insn >> 5) & 0xffffU) << shift;
        if (rd < 31) {
            uint64_t prior = regs[rd].known ? regs[rd].value : 0;
            uint64_t mask = ~(0xffffULL << shift);
            regs[rd] = { YES, (prior & mask) | imm, rva, regs[rd].origin ?: "movk" };
        }
        return YES;
    }
    if ((insn & 0xff000000U) == 0x58000000U) {
        unsigned rt = insn & 31U; uint64_t slot = HFAContextBranch19(pc, insn), loaded = 0;
        if (rt < 31 && HFAContextRead(slot, &loaded, sizeof(loaded))) regs[rt] = { YES, loaded, rva, "ldr-literal" };
        return YES;
    }
    if ((insn & 0xffc00000U) == 0xf9400000U) {
        unsigned rt = insn & 31U, rn = (insn >> 5) & 31U;
        uint64_t off = ((insn >> 10) & 0xfffU) << 3, loaded = 0;
        if (rt < 31 && rn < 31 && regs[rn].known && HFAContextRead(regs[rn].value + off, &loaded, sizeof(loaded)))
            regs[rt] = { YES, loaded, rva, regs[rn].origin ?: "ldr-uimm" };
        return YES;
    }
    if ((insn & 0xffe00c00U) == 0xf8400000U) {
        unsigned rt = insn & 31U, rn = (insn >> 5) & 31U;
        int64_t off = HFASignExtendContext((insn >> 12) & 0x1ffU, 9); uint64_t loaded = 0;
        if (rt < 31 && rn < 31 && regs[rn].known && HFAContextRead((uint64_t)((int64_t)regs[rn].value + off), &loaded, sizeof(loaded)))
            regs[rt] = { YES, loaded, rva, regs[rn].origin ?: "ldur" };
        return YES;
    }
    // CMP Xn,#imm (SUBS XZR,Xn,#imm)
    if ((insn & 0xff00001fU) == 0xf100001fU) {
        unsigned rn = (insn >> 5) & 31U; uint64_t imm = (insn >> 10) & 0xfffU;
        if (insn & (1U << 22)) imm <<= 12;
        if (flags) { flags->valid = YES; flags->known = rn < 31 && regs[rn].known; flags->lhs = flags->known ? regs[rn].value : 0; flags->rhs = imm; flags->sourceRVA = rva; flags->kind = "cmp-immediate"; }
        return YES;
    }
    // CMP Xn,Xm (SUBS XZR,Xn,Xm)
    if ((insn & 0xffe0fc1fU) == 0xeb00001fU) {
        unsigned rn = (insn >> 5) & 31U, rm = (insn >> 16) & 31U;
        if (flags) { flags->valid = YES; flags->known = rn < 31 && rm < 31 && regs[rn].known && regs[rm].known; flags->lhs = flags->known ? regs[rn].value : 0; flags->rhs = flags->known ? regs[rm].value : 0; flags->sourceRVA = rva; flags->kind = "cmp-register"; }
        return YES;
    }
    return NO;
}

static BOOL HFAContextEvaluateCond(unsigned cond, HFAContextFlags flags, BOOL *knownOut) {
    if (knownOut) *knownOut = NO;
    if (!flags.valid || !flags.known) return NO;
    BOOL eq = flags.lhs == flags.rhs;
    if (cond == 0) { if (knownOut) *knownOut = YES; return eq; }
    if (cond == 1) { if (knownOut) *knownOut = YES; return !eq; }
    return NO;
}

static void HFAContextEnqueue(NSMutableArray *queue, NSMutableSet *scheduled, uint64_t pc,
                              NSUInteger depth, HFAContextReg regs[31], HFAContextFlags flags,
                              const void *imageBase) {
    if (!pc || depth > kHFAContextMaxDepth || queue.count >= kHFAContextMaxBlocks || !HFAContextSameImage(pc, imageBase)) return;
    NSNumber *key = @(pc); if ([scheduled containsObject:key]) return; [scheduled addObject:key];
    NSData *snapshot = [NSData dataWithBytes:regs length:sizeof(HFAContextReg) * 31U];
    NSData *flagData = [NSData dataWithBytes:&flags length:sizeof(flags)];
    [queue addObject:@{ @"pc": key, @"depth": @(depth), @"regs": snapshot, @"flags": flagData }];
}

NSDictionary *HFAMapAnalyzeFeatureCallbackContext(const void *implementation,
                                                   NSString *implementationPath,
                                                   id target,
                                                   SEL selector,
                                                   UIControl *sender) {
    if (!implementation || !implementationPath.length || !target || !selector || !sender)
        return @{ @"schema": @"com.hfa.feature-context/v1", @"status": @"missing-input", @"analysisOnly": @YES };
    Dl_info info = {};
    if (!dladdr(implementation, &info) || !info.dli_fbase)
        return @{ @"schema": @"com.hfa.feature-context/v1", @"status": @"dladdr-failed", @"analysisOnly": @YES };

    HFAIL2CPPBuildMethodIndex(NSDate.date.timeIntervalSince1970 + 0.50);
    uint64_t base = (uint64_t)(uintptr_t)info.dli_fbase;
    uint64_t start = (uint64_t)(uintptr_t)implementation;
    HFAContextReg initial[31] = {};
    initial[0] = { YES, (uint64_t)(uintptr_t)(__bridge void *)target, start - base, "objc-target-self" };
    initial[1] = { YES, (uint64_t)(uintptr_t)selector, start - base, "objc-selector-cmd" };
    initial[2] = { YES, (uint64_t)(uintptr_t)(__bridge void *)sender, start - base, "exact-ui-control-sender" };
    HFAContextFlags initialFlags = {};

    NSMutableArray *queue = [NSMutableArray array], *branches = [NSMutableArray array];
    NSMutableArray *objcEvaluations = [NSMutableArray array], *methodLinks = [NSMutableArray array];
    NSMutableSet *scheduled = [NSMutableSet set], *visited = [NSMutableSet set];
    HFAContextEnqueue(queue, scheduled, start, 0, initial, initialFlags, info.dli_fbase);
    NSUInteger decoded = 0, blocks = 0, resolvedConditionals = 0, unresolvedConditionals = 0;

    while (queue.count && decoded < kHFAContextMaxInstructions && blocks < kHFAContextMaxBlocks) {
        NSDictionary *item = [[queue objectAtIndex:0] retain]; [queue removeObjectAtIndex:0];
        uint64_t blockStart = [item[@"pc"] unsignedLongLongValue];
        if ([visited containsObject:@(blockStart)]) { [item release]; continue; }
        [visited addObject:@(blockStart)]; ++blocks;
        NSUInteger depth = [item[@"depth"] unsignedIntegerValue];
        HFAContextReg regs[31] = {}; memcpy(regs, [item[@"regs"] bytes], sizeof(regs));
        HFAContextFlags flags = {}; memcpy(&flags, [item[@"flags"] bytes], sizeof(flags));
        [item release];

        for (NSUInteger i = 0; i < kHFAContextMaxInstructionsPerBlock && decoded < kHFAContextMaxInstructions; ++i) {
            uint64_t pc = blockStart + i * 4ULL; if (!HFAContextSameImage(pc, info.dli_fbase)) break;
            uint32_t insn = 0; if (!HFAContextRead(pc, &insn, sizeof(insn))) break; ++decoded;
            uint64_t rva = pc - base;
            if (HFAContextApplySimple(insn, pc, base, regs, &flags)) continue;

            if ((insn & 0xfc000000U) == 0x94000000U) {
                uint64_t callTarget = HFAContextBranch26(pc, insn);
                uint64_t resolved = HFAContextResolveTailStub(callTarget, info.dli_fbase);
                uint64_t semanticTarget = resolved ?: callTarget;
                NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)semanticTarget);
                if (method && methodLinks.count < kHFAContextMaxMethodLinks)
                    [methodLinks addObject:@{ @"callsiteRVA": @(rva), @"targetRuntime": @(semanticTarget), @"method": method }];

                if (HFAContextIsObjCMessageSend(semanticTarget)) {
                    NSString *selName = regs[1].known ? HFAContextSelectorName(regs[1].value) : nil;
                    NSMutableDictionary *evaluation = [@{ @"callsiteRVA": @(rva), @"selector": selName ?: @"?",
                        @"receiver": HFAContextRegEvidence(regs[0]), @"argument2": HFAContextRegEvidence(regs[2]),
                        @"evaluatedWithoutSelectorInvocation": @NO } mutableCopy];
                    BOOL computed = NO; uint64_t result = 0;
                    if ([selName isEqualToString:@"class"] && regs[0].known) {
                        id receiver = (__bridge id)(void *)(uintptr_t)regs[0].value;
                        Class cls = receiver ? object_getClass(receiver) : Nil;
                        if (cls) { computed = YES; result = (uint64_t)(uintptr_t)cls; evaluation[@"evaluation"] = @"object_getClass-metadata"; }
                    } else if ([selName isEqualToString:@"isKindOfClass:"] && regs[0].known && regs[2].known) {
                        id receiver = (__bridge id)(void *)(uintptr_t)regs[0].value;
                        Class candidate = (Class)(uintptr_t)regs[2].value;
                        computed = YES; result = HFAContextObjectIsKindOfClass(receiver, candidate) ? 1 : 0;
                        evaluation[@"evaluation"] = @"class-hierarchy-metadata";
                    }
                    for (unsigned r = 0; r <= 18; ++r) regs[r] = { NO, 0, rva, "call-clobber" };
                    if (computed) {
                        regs[0] = { YES, result, rva, "metadata-evaluated-objc-return" };
                        evaluation[@"evaluatedWithoutSelectorInvocation"] = @YES;
                        evaluation[@"result"] = @(result);
                        evaluation[@"resultHex"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)result];
                    }
                    if (objcEvaluations.count < kHFAContextMaxObjCEvaluations) [objcEvaluations addObject:evaluation];
                    [evaluation release];
                    flags.valid = NO;
                    continue;
                }
                // Unknown calls are ABI-clobbered, but x19-x28 remain available.
                for (unsigned r = 0; r <= 18; ++r) regs[r] = { NO, 0, rva, "call-clobber" };
                flags.valid = NO;
                continue;
            }

            if ((insn & 0xfc000000U) == 0x14000000U) {
                uint64_t dst = HFAContextBranch26(pc, insn);
                [branches addObject:@{ @"kind": @"b", @"fromRVA": @(rva), @"targetRVA": @(dst - base), @"resolved": @YES }];
                HFAContextEnqueue(queue, scheduled, dst, depth + 1, regs, flags, info.dli_fbase); break;
            }
            if ((insn & 0x7e000000U) == 0x34000000U) {
                uint64_t dst = HFAContextBranch19(pc, insn); unsigned rt = insn & 31U;
                BOOL cbnz = (insn & 0x01000000U) != 0; BOOL known = rt < 31 && regs[rt].known;
                BOOL taken = known ? (cbnz ? regs[rt].value != 0 : regs[rt].value == 0) : NO;
                if (known) ++resolvedConditionals; else ++unresolvedConditionals;
                NSMutableDictionary *record = [@{ @"kind": cbnz ? @"cbnz" : @"cbz", @"fromRVA": @(rva),
                    @"targetRVA": @(dst - base), @"fallthroughRVA": @(pc + 4 - base), @"resolved": @(known),
                    @"testedRegister": [NSString stringWithFormat:@"x%u", rt], @"testedValue": HFAContextRegEvidence(regs[rt]) } mutableCopy];
                if (known) record[@"taken"] = @(taken); if (branches.count < kHFAContextMaxBranches) [branches addObject:record]; [record release];
                if (known) HFAContextEnqueue(queue, scheduled, taken ? dst : pc + 4, depth + 1, regs, flags, info.dli_fbase);
                else { HFAContextEnqueue(queue, scheduled, dst, depth + 1, regs, flags, info.dli_fbase); HFAContextEnqueue(queue, scheduled, pc + 4, depth + 1, regs, flags, info.dli_fbase); }
                break;
            }
            if ((insn & 0x7e000000U) == 0x36000000U) {
                uint64_t dst = HFAContextBranch14(pc, insn); unsigned rt = insn & 31U;
                unsigned bit = ((insn >> 19) & 0x1fU) | ((insn >> 26) & 0x20U); BOOL tbnz = (insn & 0x01000000U) != 0;
                BOOL known = rt < 31 && regs[rt].known; BOOL bitSet = known ? ((regs[rt].value >> bit) & 1U) : NO;
                BOOL taken = known ? (tbnz ? bitSet : !bitSet) : NO;
                if (known) ++resolvedConditionals; else ++unresolvedConditionals;
                NSMutableDictionary *record = [@{ @"kind": tbnz ? @"tbnz" : @"tbz", @"fromRVA": @(rva), @"targetRVA": @(dst - base),
                    @"fallthroughRVA": @(pc + 4 - base), @"bit": @(bit), @"resolved": @(known),
                    @"testedRegister": [NSString stringWithFormat:@"x%u", rt], @"testedValue": HFAContextRegEvidence(regs[rt]) } mutableCopy];
                if (known) record[@"taken"] = @(taken); if (branches.count < kHFAContextMaxBranches) [branches addObject:record]; [record release];
                if (known) HFAContextEnqueue(queue, scheduled, taken ? dst : pc + 4, depth + 1, regs, flags, info.dli_fbase);
                else { HFAContextEnqueue(queue, scheduled, dst, depth + 1, regs, flags, info.dli_fbase); HFAContextEnqueue(queue, scheduled, pc + 4, depth + 1, regs, flags, info.dli_fbase); }
                break;
            }
            if ((insn & 0xff000010U) == 0x54000000U) {
                uint64_t dst = HFAContextBranch19(pc, insn); unsigned cond = insn & 0xfU; BOOL known = NO;
                BOOL taken = HFAContextEvaluateCond(cond, flags, &known);
                if (known) ++resolvedConditionals; else ++unresolvedConditionals;
                NSMutableDictionary *record = [@{ @"kind": @"b-cond", @"condition": cond == 0 ? @"eq" : (cond == 1 ? @"ne" : @"other"),
                    @"fromRVA": @(rva), @"targetRVA": @(dst - base), @"fallthroughRVA": @(pc + 4 - base), @"resolved": @(known),
                    @"conditionSourceRVA": @(flags.sourceRVA), @"conditionKind": flags.kind ? [NSString stringWithUTF8String:flags.kind] : @"unknown" } mutableCopy];
                if (known) { record[@"taken"] = @(taken); record[@"lhs"] = @(flags.lhs); record[@"rhs"] = @(flags.rhs); }
                if (branches.count < kHFAContextMaxBranches) [branches addObject:record]; [record release];
                if (known) HFAContextEnqueue(queue, scheduled, taken ? dst : pc + 4, depth + 1, regs, flags, info.dli_fbase);
                else { HFAContextEnqueue(queue, scheduled, dst, depth + 1, regs, flags, info.dli_fbase); HFAContextEnqueue(queue, scheduled, pc + 4, depth + 1, regs, flags, info.dli_fbase); }
                break;
            }
            if ((insn & 0xfffffc1fU) == 0xd65f0000U) break;
        }
    }

    NSString *senderClass = NSStringFromClass(object_getClass(sender)) ?: @"?";
    NSString *targetClass = NSStringFromClass(object_getClass(target)) ?: @"?";
    return @{ @"schema": @"com.hfa.feature-context/v1", @"status": decoded ? @"context-cfg-decoded" : @"no-readable-code",
        @"analysisOnly": @YES, @"canonicalEligible": @NO, @"implementationRVA": @(start - base),
        @"seedPolicy": @"exact-callback-arm64-abi-x0-target-x1-selector-x2-sender",
        @"targetClass": targetClass, @"senderClass": senderClass, @"selector": NSStringFromSelector(selector) ?: @"?",
        @"contextSeeds": @{ @"x0": HFAContextRegEvidence(initial[0]), @"x1": HFAContextRegEvidence(initial[1]), @"x2": HFAContextRegEvidence(initial[2]) },
        @"decodedInstructionCount": @(decoded), @"blockCount": @(blocks), @"resolvedConditionalCount": @(resolvedConditionals),
        @"unresolvedConditionalCount": @(unresolvedConditionals), @"branches": branches, @"objcEvaluationCount": @(objcEvaluations.count),
        @"objcEvaluations": objcEvaluations, @"il2cppCorrelationCount": @(methodLinks.count), @"il2cppMethodLinks": methodLinks,
        @"referenceModel": @"verify.dylib-descriptor-callback-downstream-plus-h5gg-method-range",
        @"policy": @"read-only-bounded-context-seeded-no-hook-no-selector-invocation-no-memory-write" };
}
