#import "HFAMapFeatureHandlerResolver.h"
#import "HFAIL2CPPMethodIndex.h"

#import <objc/runtime.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

static const NSUInteger kHFAHandlerMaxNodes = 48;
static const NSUInteger kHFAHandlerMaxDepth = 2;
static const NSUInteger kHFAHandlerMaxBlocks = 24;
static const NSUInteger kHFAHandlerMaxInstructions = 256;
static const NSUInteger kHFAHandlerMaxStrings = 24;

typedef struct {
    uintptr_t isa;
    int32_t flags;
    int32_t reserved;
    uintptr_t invoke;
    uintptr_t descriptor;
} HFABlockHeader;

typedef struct {
    BOOL known;
    uint64_t value;
} HFAKnownReg;

static int64_t HFASignExtendHandler(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL HFAHandlerRead(uint64_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         (vm_size_t)size, (vm_address_t)buffer, &copied);
    return kr == KERN_SUCCESS && copied == size;
}

static NSString *HFAHandlerCString(uint64_t address) {
    if (!address) return nil;
    char bytes[193] = {};
    vm_size_t copied = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)address, 192,
                          (vm_address_t)bytes, &copied) != KERN_SUCCESS || !copied) return nil;
    size_t n = strnlen(bytes, copied);
    if (!n || n >= copied || n > 160) return nil;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)bytes[i];
        if (c < 0x20 || c > 0x7e) return nil;
    }
    return [NSString stringWithUTF8String:bytes];
}

static NSString *HFAHandlerImageForAddress(uint64_t address, const void **baseOut) {
    Dl_info info = {};
    if (!address || !dladdr((const void *)(uintptr_t)address, &info) || !info.dli_fname || !info.dli_fbase)
        return nil;
    if (baseOut) *baseOut = info.dli_fbase;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    return path.lastPathComponent;
}

static BOOL HFAHandlerIsBlock(id value) {
    if (!value) return NO;
    NSString *name = NSStringFromClass(object_getClass(value)) ?: @"";
    return [name isEqualToString:@"__NSGlobalBlock__"] ||
           [name isEqualToString:@"__NSMallocBlock__"] ||
           [name isEqualToString:@"__NSStackBlock__"] ||
           [name hasSuffix:@"Block"] || [name hasSuffix:@"Block__"];
}

static NSString *HFAHandlerStringRole(NSString *value) {
    if (!value.length) return @"unknown";
    NSString *lower = value.lowercaseString;
    if ([lower hasSuffix:@".dll"] || [lower hasSuffix:@".exe"]) return @"assembly-like";
    if ([value containsString:@"."] && ![value containsString:@" "] && value.length <= 160)
        return @"qualified-type-like";
    NSCharacterSet *identifier = [NSCharacterSet characterSetWithCharactersInString:
        @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_`<>$@"];
    if (value.length <= 128 && [[value stringByTrimmingCharactersInSet:identifier] length] == 0)
        return @"identifier-like";
    return @"literal";
}

static void HFAHandlerAppendString(NSMutableArray *strings, NSMutableSet *seen,
                                   NSString *value, uint64_t sourceRVA, unsigned reg) {
    if (!value.length || strings.count >= kHFAHandlerMaxStrings) return;
    NSString *key = [NSString stringWithFormat:@"%@:%llu", value, (unsigned long long)sourceRVA];
    if ([seen containsObject:key]) return;
    [seen addObject:key];
    [strings addObject:@{ @"value": value,
                          @"role": HFAHandlerStringRole(value),
                          @"sourceRVA": @(sourceRVA),
                          @"sourceRVAHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)sourceRVA],
                          @"register": [NSString stringWithFormat:@"x%u", reg] }];
}

static NSDictionary *HFAAnalyzeBlockInvoke(uint64_t invoke, NSString *menuImage) {
    const void *basePtr = NULL;
    NSString *image = HFAHandlerImageForAddress(invoke, &basePtr);
    if (!image.length || ![image isEqualToString:menuImage] || !basePtr)
        return @{ @"schema": @"com.hfa.runtime-method-descriptor/v1",
                  @"status": @"invoke-outside-selected-menu", @"analysisOnly": @YES };

    uint64_t base = (uint64_t)(uintptr_t)basePtr;
    HFAKnownReg regs[31] = {};
    NSMutableArray *strings = [NSMutableArray array];
    NSMutableSet *seenStrings = [NSMutableSet set];
    NSMutableArray *methodLinks = [NSMutableArray array];
    NSUInteger directCalls = 0, indirectCalls = 0;
    BOOL sawReturn = NO;

    for (NSUInteger index = 0; index < kHFAHandlerMaxInstructions; ++index) {
        uint64_t pc = invoke + index * 4U;
        uint32_t insn = 0;
        if (!HFAHandlerRead(pc, &insn, sizeof(insn))) break;
        uint64_t rva = pc - base;

        if (insn == 0xD65F03C0U) { sawReturn = YES; break; }

        if ((insn & 0x9F000000U) == 0x90000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFASignExtendHandler((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                                ((insn >> 29) & 3U), 21) << 12;
            if (rd < 31) regs[rd] = { YES, (pc & ~0xfffULL) + imm };
            continue;
        }
        if ((insn & 0x9F000000U) == 0x10000000U) {
            unsigned rd = insn & 31U;
            int64_t imm = HFASignExtendHandler((((uint64_t)(insn >> 5) & 0x7ffffULL) << 2) |
                                                ((insn >> 29) & 3U), 21);
            if (rd < 31) {
                regs[rd] = { YES, pc + imm };
                NSString *text = HFAHandlerCString(regs[rd].value);
                if (text.length) HFAHandlerAppendString(strings, seenStrings, text, rva, rd);
            }
            continue;
        }
        if ((insn & 0xFFC00000U) == 0x91000000U) {
            unsigned rd = insn & 31U, rn = (insn >> 5) & 31U;
            uint64_t imm = (insn >> 10) & 0xfffU; if (insn & (1U << 22)) imm <<= 12;
            if (rd < 31 && rn < 31 && regs[rn].known) {
                regs[rd] = { YES, regs[rn].value + imm };
                NSString *text = HFAHandlerCString(regs[rd].value);
                if (text.length) HFAHandlerAppendString(strings, seenStrings, text, rva, rd);
            }
            continue;
        }
        if ((insn & 0xFF000000U) == 0x58000000U) {
            unsigned rt = insn & 31U;
            int64_t off = HFASignExtendHandler((insn >> 5) & 0x7ffffU, 19) << 2;
            uint64_t slot = (uint64_t)((int64_t)pc + off), loaded = 0;
            if (rt < 31 && HFAHandlerRead(slot, &loaded, sizeof(loaded))) {
                regs[rt] = { YES, loaded };
                NSString *text = HFAHandlerCString(loaded);
                if (text.length) HFAHandlerAppendString(strings, seenStrings, text, rva, rt);
            }
            continue;
        }
        if ((insn & 0xFFE0FFE0U) == 0xAA0003E0U) {
            unsigned rd = insn & 31U, rm = (insn >> 16) & 31U;
            if (rd < 31 && rm < 31) regs[rd] = regs[rm];
            continue;
        }
        if ((insn & 0xFC000000U) == 0x94000000U) {
            ++directCalls;
            int64_t off = HFASignExtendHandler(insn & 0x03ffffffU, 26) << 2;
            uint64_t target = (uint64_t)((int64_t)pc + off);
            NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)target);
            if (method && methodLinks.count < 16)
                [methodLinks addObject:@{ @"kind": @"direct-call", @"callsiteRVA": @(rva), @"method": method }];
            continue;
        }
        if ((insn & 0xFFFFFC1FU) == 0xD63F0000U || (insn & 0xFFFFFC1FU) == 0xD61F0000U) {
            ++indirectCalls;
            unsigned rn = (insn >> 5) & 31U;
            if (rn < 31 && regs[rn].known) {
                NSDictionary *method = HFAIL2CPPMethodContainingRuntimeAddress((const void *)(uintptr_t)regs[rn].value);
                if (method && methodLinks.count < 16)
                    [methodLinks addObject:@{ @"kind": @"indirect-call", @"callsiteRVA": @(rva),
                                              @"register": [NSString stringWithFormat:@"x%u", rn], @"method": method }];
            }
            if ((insn & 0xFFFFFC1FU) == 0xD61F0000U) break;
        }
    }

    NSUInteger assemblyLike = 0, identifierLike = 0, qualifiedLike = 0;
    for (NSDictionary *entry in strings) {
        NSString *role = entry[@"role"];
        if ([role isEqualToString:@"assembly-like"]) ++assemblyLike;
        else if ([role isEqualToString:@"identifier-like"]) ++identifierLike;
        else if ([role isEqualToString:@"qualified-type-like"]) ++qualifiedLike;
    }
    BOOL descriptor = assemblyLike > 0 && identifierLike >= 2 && indirectCalls > 0;
    return @{ @"schema": @"com.hfa.runtime-method-descriptor/v1",
              @"status": descriptor ? @"runtime-method-descriptor-candidate" : @"insufficient-method-descriptor-evidence",
              @"invokeRVA": @(invoke - base),
              @"invokeRVAHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(invoke - base)],
              @"implementationImage": image,
              @"strings": strings,
              @"assemblyLikeCount": @(assemblyLike),
              @"identifierLikeCount": @(identifierLike),
              @"qualifiedTypeLikeCount": @(qualifiedLike),
              @"directCallCount": @(directCalls),
              @"indirectCallCount": @(indirectCalls),
              @"il2cppMethodLinks": methodLinks,
              @"il2cppCorrelationCount": @(methodLinks.count),
              @"sawReturn": @(sawReturn),
              @"classification": descriptor ? @"runtime-method" : @"unknown",
              @"selectionPolicy": @"known-feature-object-graph-to-block-invoke-only",
              @"analysisOnly": @YES, @"canonicalEligible": @NO,
              @"blockInvokedByAnalyzer": @NO, @"selectorInvokedByAnalyzer": @NO,
              @"hookInstalled": @NO, @"memoryWritten": @NO };
}

static void HFAEnqueueObject(NSMutableArray *queue, NSHashTable *seen, id object,
                             NSUInteger depth, NSString *path) {
    if (!object || depth > kHFAHandlerMaxDepth || queue.count >= kHFAHandlerMaxNodes || [seen containsObject:object]) return;
    [seen addObject:object];
    [queue addObject:@{ @"object": object, @"depth": @(depth), @"path": path ?: @"root" }];
}

static NSArray *HFAAnalyzeObjectGraph(id root, NSString *rootName, NSString *menuImage) {
    if (!root) return @[];
    NSMutableArray *queue = [NSMutableArray array];
    NSHashTable *seen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *blocks = [NSMutableArray array];
    NSMutableSet *blockKeys = [NSMutableSet set];
    HFAEnqueueObject(queue, seen, root, 0, rootName);

    for (NSUInteger cursor = 0; cursor < queue.count && cursor < kHFAHandlerMaxNodes; ++cursor) {
        NSDictionary *node = queue[cursor];
        id object = node[@"object"];
        NSUInteger depth = [node[@"depth"] unsignedIntegerValue];
        NSString *path = node[@"path"] ?: @"root";
        if (HFAHandlerIsBlock(object)) {
            HFABlockHeader header = {};
            if (HFAHandlerRead((uint64_t)(uintptr_t)object, &header, sizeof(header)) && header.invoke) {
                NSString *key = [NSString stringWithFormat:@"0x%llX", (unsigned long long)header.invoke];
                if (![blockKeys containsObject:key] && blocks.count < kHFAHandlerMaxBlocks) {
                    [blockKeys addObject:key];
                    NSDictionary *semantic = HFAAnalyzeBlockInvoke(header.invoke, menuImage);
                    [blocks addObject:@{ @"objectPath": path,
                                         @"blockClass": NSStringFromClass(object_getClass(object)) ?: @"?",
                                         @"invokePointer": key,
                                         @"descriptorPointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)header.descriptor],
                                         @"semantic": semantic }];
                }
            }
            continue;
        }
        if (depth >= kHFAHandlerMaxDepth) continue;

        if ([object isKindOfClass:NSDictionary.class]) {
            NSUInteger count = 0;
            for (id key in (NSDictionary *)object) {
                if (++count > 24) break;
                id value = [(NSDictionary *)object objectForKey:key];
                if ([value isKindOfClass:NSObject.class])
                    HFAEnqueueObject(queue, seen, value, depth + 1,
                                     [path stringByAppendingFormat:@"[%@]", [key description]]);
            }
            continue;
        }
        if ([object isKindOfClass:NSArray.class]) {
            NSUInteger count = MIN([(NSArray *)object count], 24U);
            for (NSUInteger i = 0; i < count; ++i)
                HFAEnqueueObject(queue, seen, [(NSArray *)object objectAtIndex:i], depth + 1,
                                 [path stringByAppendingFormat:@"[%lu]", (unsigned long)i]);
            continue;
        }

        for (Class cls = object_getClass(object); cls && cls != NSObject.class; cls = class_getSuperclass(cls)) {
            unsigned count = 0;
            Ivar *ivars = class_copyIvarList(cls, &count);
            count = MIN(count, 32U);
            for (unsigned i = 0; ivars && i < count; ++i) {
                const char *type = ivar_getTypeEncoding(ivars[i]);
                const char *name = ivar_getName(ivars[i]);
                if (!type || type[0] != '@' || !name) continue;
                id value = object_getIvar(object, ivars[i]);
                if (!value) continue;
                HFAEnqueueObject(queue, seen, value, depth + 1,
                                 [path stringByAppendingFormat:@".%s", name]);
            }
            free(ivars);
        }
    }
    return blocks;
}

NSDictionary *HFAMapAnalyzeFeatureHandlerSnapshot(NSDictionary *snapshot,
                                                   NSDictionary *candidate) {
    if (!NSThread.isMainThread)
        return @{ @"schema": @"com.hfa.feature-handler-graph/v1", @"status": @"main-thread-required", @"analysisOnly": @YES };
    NSString *menuImage = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : @"";
    if (!menuImage.length)
        return @{ @"schema": @"com.hfa.feature-handler-graph/v1", @"status": @"missing-menu-image", @"analysisOnly": @YES };

    NSMutableArray *records = [NSMutableArray array];
    for (NSDictionary *seed in snapshot[@"actionSeeds"] ?: @[]) {
        if (records.count >= 64) break;
        id target = seed[@"target"];
        NSString *token = seed[@"controlToken"];
        uintptr_t pointer = token.length ? (uintptr_t)strtoull(token.UTF8String, NULL, 0) : 0;
        UIControl *control = pointer ? (__bridge UIControl *)(void *)pointer : nil;
        NSMutableArray *blocks = [NSMutableArray array];
        [blocks addObjectsFromArray:HFAAnalyzeObjectGraph(target, @"target", menuImage)];
        if (control && [control isKindOfClass:UIControl.class])
            [blocks addObjectsFromArray:HFAAnalyzeObjectGraph(control, @"sender", menuImage)];

        NSUInteger methodCandidates = 0, correlations = 0;
        for (NSDictionary *block in blocks) {
            NSDictionary *semantic = block[@"semantic"];
            if ([semantic[@"classification"] isEqualToString:@"runtime-method"]) ++methodCandidates;
            correlations += [semantic[@"il2cppCorrelationCount"] unsignedIntegerValue];
        }
        [records addObject:@{ @"label": seed[@"label"] ?: @"",
                              @"selector": seed[@"selector"] ?: @"",
                              @"registeredEvent": seed[@"event"] ?: @"",
                              @"controlToken": token ?: @"",
                              @"targetClass": target ? (NSStringFromClass(object_getClass(target)) ?: @"?") : @"?",
                              @"handlerBlocks": blocks,
                              @"handlerBlockCount": @(blocks.count),
                              @"runtimeMethodCandidateCount": @(methodCandidates),
                              @"il2cppCorrelationCount": @(correlations),
                              @"association": @"exact-action-seed-object-graph",
                              @"analysisOnly": @YES, @"canonicalEligible": @NO }];
    }
    NSUInteger totalCandidates = 0, totalCorrelations = 0;
    for (NSDictionary *record in records) {
        totalCandidates += [record[@"runtimeMethodCandidateCount"] unsignedIntegerValue];
        totalCorrelations += [record[@"il2cppCorrelationCount"] unsignedIntegerValue];
    }
    return @{ @"schema": @"com.hfa.feature-handler-graph/v1",
              @"status": @"complete",
              @"records": records,
              @"recordCount": @(records.count),
              @"runtimeMethodCandidateCount": @(totalCandidates),
              @"il2cppCorrelationCount": @(totalCorrelations),
              @"policy": @"verify-style-known-descriptor-callback-downstream-no-global-method-guessing",
              @"analysisOnly": @YES, @"canonicalEligible": @NO,
              @"selectorsInvoked": @NO, @"blocksInvoked": @NO,
              @"hooksInstalled": @NO, @"memoryWritten": @NO };
}
