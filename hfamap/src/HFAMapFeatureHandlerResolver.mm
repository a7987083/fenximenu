#import "HFAMapFeatureHandlerResolver.h"
#import "HFAIL2CPPMethodIndex.h"

#import <objc/runtime.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// v2.5.2: generic ownership-first feature resolver.
// The analyzer starts from an already-known UI action relationship and follows
// bounded, read-only object ownership links. It never uses sample method names,
// sample RVAs, global method guessing, selector invocation, block invocation,
// hooking, or target-memory writes.
static const NSUInteger kHFAHandlerMaxNodes = 96;
static const NSUInteger kHFAHandlerMaxDepth = 4;
static const NSUInteger kHFAHandlerMaxBlocks = 32;
static const NSUInteger kHFAHandlerMaxDescriptors = 48;
static const NSUInteger kHFAHandlerMaxInstructions = 320;
static const NSUInteger kHFAHandlerMaxStrings = 32;
static const NSUInteger kHFAHandlerMaxViewRelatives = 24;

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

static NSString *HFAHandlerImageForObject(id value) {
    if (!value) return @"";
    const char *path = class_getImageName(object_getClass(value));
    if (!path) return @"";
    NSString *string = [NSString stringWithUTF8String:path];
    return string.lastPathComponent ?: @"";
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
        return @{ @"schema": @"com.hfa.runtime-method-descriptor/v2",
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
            uint64_t imm = (insn >> 10) & 0xfffU;
            if (insn & (1U << 22)) imm <<= 12;
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
        if ((insn & 0xFFC00000U) == 0xF9400000U) {
            unsigned rt = insn & 31U, rn = (insn >> 5) & 31U;
            uint64_t off = ((insn >> 10) & 0xfffU) << 3;
            uint64_t loaded = 0;
            if (rt < 31 && rn < 31 && regs[rn].known &&
                HFAHandlerRead(regs[rn].value + off, &loaded, sizeof(loaded))) {
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
    return @{ @"schema": @"com.hfa.runtime-method-descriptor/v2",
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
              @"selectionPolicy": @"feature-owned-descriptor-to-block-invoke-structural-evidence",
              @"analysisOnly": @YES, @"canonicalEligible": @NO,
              @"blockInvokedByAnalyzer": @NO, @"selectorInvokedByAnalyzer": @NO,
              @"hookInstalled": @NO, @"memoryWritten": @NO };
}

static NSString *HFANormalizedFeatureText(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return @"";
    NSMutableString *result = [NSMutableString stringWithCapacity:value.length];
    NSString *lower = value.lowercaseString;
    NSCharacterSet *allowed = [NSCharacterSet alphanumericCharacterSet];
    for (NSUInteger i = 0; i < lower.length; ++i) {
        unichar c = [lower characterAtIndex:i];
        if ([allowed characterIsMember:c]) [result appendFormat:@"%C", c];
    }
    return result;
}

static NSString *HFANormalizedKey(id key) {
    if (![key isKindOfClass:NSString.class]) return @"";
    NSString *lower = [(NSString *)key lowercaseString];
    NSCharacterSet *trim = [NSCharacterSet characterSetWithCharactersInString:@"_- "];
    return [lower stringByTrimmingCharactersInSet:trim];
}

static id HFAFeatureAliasValue(NSDictionary *dictionary, NSArray *aliases, NSString **matchedKey) {
    for (id key in dictionary) {
        NSString *normalized = HFANormalizedKey(key);
        for (NSString *alias in aliases) {
            if ([normalized isEqualToString:alias]) {
                if (matchedKey) *matchedKey = key;
                return dictionary[key];
            }
        }
    }
    return nil;
}

static BOOL HFAFeatureIsHandlerKey(id key) {
    NSString *normalized = HFANormalizedKey(key);
    static NSSet *aliases;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        aliases = [[NSSet alloc] initWithArray:@[
            @"handler", @"action", @"callback", @"block", @"completion",
            @"taphandler", @"buttontaphandler", @"kbuttontaphandler",
            @"onchange", @"onvaluechanged", @"onclick", @"invoke"
        ]];
    });
    return [aliases containsObject:normalized];
}

static NSDictionary *HFAFeatureDescriptorMetadata(NSDictionary *dictionary,
                                                   NSString *seedLabel,
                                                   NSString *path,
                                                   NSString *origin) {
    NSString *labelKey = nil, *identifierKey = nil, *typeKey = nil;
    id labelValue = HFAFeatureAliasValue(dictionary,
        @[@"label", @"title", @"name", @"displayname"], &labelKey);
    id identifierValue = HFAFeatureAliasValue(dictionary,
        @[@"identifier", @"id", @"key"], &identifierKey);
    id typeValue = HFAFeatureAliasValue(dictionary,
        @[@"type", @"kind", @"controltype"], &typeKey);
    NSString *label = [labelValue isKindOfClass:NSString.class] ? labelValue : @"";
    NSString *identifier = [identifierValue isKindOfClass:NSString.class] ? identifierValue : @"";
    NSString *type = [typeValue isKindOfClass:NSString.class] ? typeValue : @"";

    NSUInteger handlerFields = 0, blockFields = 0;
    NSMutableArray *handlerKeys = [NSMutableArray array];
    for (id key in dictionary) {
        id value = dictionary[key];
        if (HFAFeatureIsHandlerKey(key)) {
            ++handlerFields;
            if (handlerKeys.count < 12) [handlerKeys addObject:[key description]];
        }
        if (HFAHandlerIsBlock(value)) ++blockFields;
    }

    BOOL descriptorShape = label.length || identifier.length || type.length || handlerFields || blockFields;
    if (!descriptorShape) return nil;

    NSString *seedNorm = HFANormalizedFeatureText(seedLabel);
    NSString *labelNorm = HFANormalizedFeatureText(label);
    BOOL exactLabel = seedNorm.length && labelNorm.length && [seedNorm isEqualToString:labelNorm];
    NSInteger score = 0;
    if (exactLabel) score += 80;
    if (label.length) score += 10;
    if (identifier.length) score += 15;
    if (type.length) score += 10;
    if (handlerFields) score += 30;
    if (blockFields) score += 20;
    if ([origin isEqualToString:@"sender"]) score += 15;
    else if ([origin isEqualToString:@"sender-superview"] || [origin isEqualToString:@"sender-relative"]) score += 10;
    else if ([origin isEqualToString:@"target"]) score += 5;

    return @{ @"label": label ?: @"",
              @"identifier": identifier ?: @"",
              @"type": type ?: @"",
              @"labelField": labelKey ?: @"",
              @"identifierField": identifierKey ?: @"",
              @"typeField": typeKey ?: @"",
              @"handlerFields": handlerKeys,
              @"handlerFieldCount": @(handlerFields),
              @"directBlockFieldCount": @(blockFields),
              @"objectPath": path ?: @"",
              @"origin": origin ?: @"unknown",
              @"exactLabelMatch": @(exactLabel),
              @"associationScore": @(score),
              @"status": exactLabel ? @"exact-label-feature-descriptor" : @"feature-descriptor-candidate" };
}

static BOOL HFAHandlerShouldTraverseIvars(id object, NSString *menuImage) {
    if (!object || !menuImage.length) return NO;
    if ([object isKindOfClass:NSDictionary.class] || [object isKindOfClass:NSArray.class] ||
        [object isKindOfClass:NSSet.class]) return YES;
    return [[HFAHandlerImageForObject(object) lastPathComponent] isEqualToString:menuImage];
}

static NSString *HFANodeSeenKey(id object, NSDictionary *descriptor, NSString *origin) {
    NSString *descriptorIdentity = descriptor ? [NSString stringWithFormat:@"%@|%@|%@",
        descriptor[@"label"] ?: @"", descriptor[@"identifier"] ?: @"", descriptor[@"objectPath"] ?: @""] : @"-";
    return [NSString stringWithFormat:@"%p|%@|%@", object, descriptorIdentity, origin ?: @""];
}

static void HFAEnqueueOwnershipObject(NSMutableArray *queue, NSMutableSet *seen,
                                      id object, NSUInteger depth, NSString *path,
                                      NSString *origin, NSDictionary *descriptor) {
    if (!object || depth > kHFAHandlerMaxDepth || queue.count >= kHFAHandlerMaxNodes) return;
    NSString *key = HFANodeSeenKey(object, descriptor, origin);
    if ([seen containsObject:key]) return;
    [seen addObject:key];
    NSMutableDictionary *node = [@{ @"object": object,
                                     @"depth": @(depth),
                                     @"path": path ?: @"root",
                                     @"origin": origin ?: @"unknown" } mutableCopy];
    if (descriptor) node[@"descriptor"] = descriptor;
    [queue addObject:node];
    [node release];
}

static void HFAAppendBlockRecord(NSMutableArray *blocks, NSMutableSet *blockKeys,
                                 id block, NSString *path, NSString *origin,
                                 NSDictionary *descriptor, NSString *menuImage) {
    if (!block || blocks.count >= kHFAHandlerMaxBlocks) return;
    HFABlockHeader header = {};
    if (!HFAHandlerRead((uint64_t)(uintptr_t)block, &header, sizeof(header)) || !header.invoke) return;
    NSString *descriptorKey = descriptor ? [NSString stringWithFormat:@"%@|%@|%@",
        descriptor[@"label"] ?: @"", descriptor[@"identifier"] ?: @"", descriptor[@"objectPath"] ?: @""] : @"-";
    NSString *key = [NSString stringWithFormat:@"0x%llX|%@|%@",
                     (unsigned long long)header.invoke, descriptorKey, path ?: @""];
    if ([blockKeys containsObject:key]) return;
    [blockKeys addObject:key];
    NSDictionary *semantic = HFAAnalyzeBlockInvoke(header.invoke, menuImage);
    NSInteger score = [descriptor[@"associationScore"] integerValue];
    BOOL exact = [descriptor[@"exactLabelMatch"] boolValue];
    [blocks addObject:@{ @"objectPath": path ?: @"",
                         @"origin": origin ?: @"unknown",
                         @"association": descriptor ? @"descriptor-owned-block" : @"object-graph-block",
                         @"descriptorOwned": @(descriptor != nil),
                         @"exactFeatureLabelMatch": @(exact),
                         @"associationScore": @(score),
                         @"featureDescriptor": descriptor ?: @{},
                         @"blockClass": NSStringFromClass(object_getClass(block)) ?: @"?",
                         @"invokePointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)header.invoke],
                         @"descriptorPointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)header.descriptor],
                         @"semantic": semantic ?: @{} }];
}

static NSDictionary *HFAAnalyzeOwnershipGraph(id target, UIControl *sender,
                                               NSString *seedLabel, NSString *menuImage) {
    NSMutableArray *queue = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    NSMutableArray *blocks = [NSMutableArray array];
    NSMutableSet *blockKeys = [NSMutableSet set];
    NSMutableArray *descriptors = [NSMutableArray array];
    NSMutableSet *descriptorKeys = [NSMutableSet set];

    HFAEnqueueOwnershipObject(queue, seen, target, 0, @"target", @"target", nil);
    HFAEnqueueOwnershipObject(queue, seen, sender, 0, @"sender", @"sender", nil);

    UIView *ancestor = sender.superview;
    for (NSUInteger depth = 0; ancestor && depth < kHFAHandlerMaxDepth; ++depth, ancestor = ancestor.superview) {
        HFAEnqueueOwnershipObject(queue, seen, ancestor, 1,
            [NSString stringWithFormat:@"sender.superview[%lu]", (unsigned long)depth],
            @"sender-superview", nil);
    }

    for (NSUInteger cursor = 0; cursor < queue.count && cursor < kHFAHandlerMaxNodes; ++cursor) {
        NSDictionary *node = queue[cursor];
        id object = node[@"object"];
        NSUInteger depth = [node[@"depth"] unsignedIntegerValue];
        NSString *path = node[@"path"] ?: @"root";
        NSString *origin = node[@"origin"] ?: @"unknown";
        NSDictionary *inheritedDescriptor = node[@"descriptor"];

        if (HFAHandlerIsBlock(object)) {
            HFAAppendBlockRecord(blocks, blockKeys, object, path, origin,
                                 inheritedDescriptor, menuImage);
            continue;
        }
        if (depth >= kHFAHandlerMaxDepth) continue;

        if ([object isKindOfClass:NSDictionary.class]) {
            NSDictionary *dictionary = object;
            NSDictionary *descriptor = HFAFeatureDescriptorMetadata(dictionary, seedLabel, path, origin);
            if (descriptor && descriptors.count < kHFAHandlerMaxDescriptors) {
                NSString *descriptorKey = [NSString stringWithFormat:@"%@|%@|%@",
                    descriptor[@"label"] ?: @"", descriptor[@"identifier"] ?: @"", path];
                if (![descriptorKeys containsObject:descriptorKey]) {
                    [descriptorKeys addObject:descriptorKey];
                    [descriptors addObject:descriptor];
                }
            }
            NSDictionary *context = descriptor ?: inheritedDescriptor;
            NSUInteger count = 0;
            for (id key in dictionary) {
                if (++count > 32) break;
                id value = dictionary[key];
                if (![value isKindOfClass:NSObject.class]) continue;
                NSString *childPath = [path stringByAppendingFormat:@"[%@]", [key description]];
                NSString *childOrigin = HFAFeatureIsHandlerKey(key) && context ? @"descriptor-handler-field" : origin;
                HFAEnqueueOwnershipObject(queue, seen, value, depth + 1,
                                          childPath, childOrigin, context);
            }
            continue;
        }

        if ([object isKindOfClass:NSArray.class]) {
            NSUInteger count = MIN([(NSArray *)object count], 32U);
            for (NSUInteger i = 0; i < count; ++i)
                HFAEnqueueOwnershipObject(queue, seen, [(NSArray *)object objectAtIndex:i], depth + 1,
                    [path stringByAppendingFormat:@"[%lu]", (unsigned long)i], origin, inheritedDescriptor);
            continue;
        }

        if ([object isKindOfClass:NSSet.class]) {
            NSUInteger index = 0;
            for (id value in (NSSet *)object) {
                if (index >= 24) break;
                HFAEnqueueOwnershipObject(queue, seen, value, depth + 1,
                    [path stringByAppendingFormat:@"{set:%lu}", (unsigned long)index++], origin, inheritedDescriptor);
            }
            continue;
        }

        if ([object isKindOfClass:UIView.class]) {
            UIView *view = object;
            if (view.superview)
                HFAEnqueueOwnershipObject(queue, seen, view.superview, depth + 1,
                    [path stringByAppendingString:@".superview"], @"sender-relative", inheritedDescriptor);
            NSUInteger childCount = MIN(view.subviews.count, kHFAHandlerMaxViewRelatives);
            for (NSUInteger i = 0; i < childCount; ++i)
                HFAEnqueueOwnershipObject(queue, seen, view.subviews[i], depth + 1,
                    [path stringByAppendingFormat:@".subviews[%lu]", (unsigned long)i],
                    @"sender-relative", inheritedDescriptor);
            if ([view isKindOfClass:UIControl.class]) {
                UIControl *control = (UIControl *)view;
                NSUInteger targetCount = 0;
                for (id actionTarget in control.allTargets) {
                    if (targetCount++ >= 16) break;
                    HFAEnqueueOwnershipObject(queue, seen, actionTarget, depth + 1,
                        [path stringByAppendingFormat:@".allTargets[%lu]", (unsigned long)(targetCount - 1)],
                        @"control-target", inheritedDescriptor);
                }
            }
        }

        if (!HFAHandlerShouldTraverseIvars(object, menuImage)) continue;
        for (Class cls = object_getClass(object); cls && cls != NSObject.class; cls = class_getSuperclass(cls)) {
            unsigned count = 0;
            Ivar *ivars = class_copyIvarList(cls, &count);
            count = MIN(count, 40U);
            for (unsigned i = 0; ivars && i < count; ++i) {
                const char *type = ivar_getTypeEncoding(ivars[i]);
                const char *name = ivar_getName(ivars[i]);
                if (!type || type[0] != '@' || !name) continue;
                id value = object_getIvar(object, ivars[i]);
                if (!value) continue;
                HFAEnqueueOwnershipObject(queue, seen, value, depth + 1,
                    [path stringByAppendingFormat:@".%s", name], origin, inheritedDescriptor);
            }
            free(ivars);
        }
    }

    [descriptors sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger av = [a[@"associationScore"] integerValue];
        NSInteger bv = [b[@"associationScore"] integerValue];
        if (av > bv) return NSOrderedAscending;
        if (av < bv) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    NSUInteger exactDescriptors = 0, descriptorOwnedBlocks = 0, featureOwnedMethods = 0;
    for (NSDictionary *descriptor in descriptors) if ([descriptor[@"exactLabelMatch"] boolValue]) ++exactDescriptors;
    for (NSDictionary *block in blocks) {
        if ([block[@"descriptorOwned"] boolValue]) ++descriptorOwnedBlocks;
        NSDictionary *semantic = block[@"semantic"];
        if ([block[@"descriptorOwned"] boolValue] && [block[@"exactFeatureLabelMatch"] boolValue] &&
            [semantic[@"classification"] isEqualToString:@"runtime-method"]) ++featureOwnedMethods;
    }

    return @{ @"schema": @"com.hfa.feature-ownership/v1",
              @"label": seedLabel ?: @"",
              @"descriptorCandidates": descriptors,
              @"descriptorCandidateCount": @(descriptors.count),
              @"exactLabelDescriptorCount": @(exactDescriptors),
              @"handlerBlocks": blocks,
              @"handlerBlockCount": @(blocks.count),
              @"descriptorOwnedBlockCount": @(descriptorOwnedBlocks),
              @"featureOwnedRuntimeMethodCandidateCount": @(featureOwnedMethods),
              @"nodesVisited": @(MIN(queue.count, kHFAHandlerMaxNodes)),
              @"maxDepth": @(kHFAHandlerMaxDepth),
              @"associationPolicy": @"exact-ui-action-to-sender-relative-descriptor-handler-object-graph",
              @"analysisOnly": @YES, @"canonicalEligible": @NO,
              @"selectorsInvoked": @NO, @"blocksInvoked": @NO,
              @"hooksInstalled": @NO, @"memoryWritten": @NO };
}

NSDictionary *HFAMapAnalyzeFeatureHandlerSnapshot(NSDictionary *snapshot,
                                                   NSDictionary *candidate) {
    if (!NSThread.isMainThread)
        return @{ @"schema": @"com.hfa.feature-handler-graph/v2", @"status": @"main-thread-required", @"analysisOnly": @YES };
    NSString *menuImage = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : @"";
    if (!menuImage.length)
        return @{ @"schema": @"com.hfa.feature-handler-graph/v2", @"status": @"missing-menu-image", @"analysisOnly": @YES };

    NSMutableArray *records = [NSMutableArray array];
    for (NSDictionary *seed in snapshot[@"actionSeeds"] ?: @[]) {
        if (records.count >= 64) break;
        id target = seed[@"target"];
        NSString *token = seed[@"controlToken"];
        uintptr_t pointer = token.length ? (uintptr_t)strtoull(token.UTF8String, NULL, 0) : 0;
        UIControl *control = pointer ? (__bridge UIControl *)(void *)pointer : nil;
        if (control && ![control isKindOfClass:UIControl.class]) control = nil;

        NSDictionary *ownership = HFAAnalyzeOwnershipGraph(target, control,
            seed[@"label"] ?: @"", menuImage);
        NSArray *blocks = ownership[@"handlerBlocks"] ?: @[];
        NSUInteger methodCandidates = 0, featureOwnedMethodCandidates = 0, correlations = 0;
        for (NSDictionary *block in blocks) {
            NSDictionary *semantic = block[@"semantic"];
            if ([semantic[@"classification"] isEqualToString:@"runtime-method"]) ++methodCandidates;
            if ([block[@"descriptorOwned"] boolValue] && [block[@"exactFeatureLabelMatch"] boolValue] &&
                [semantic[@"classification"] isEqualToString:@"runtime-method"]) ++featureOwnedMethodCandidates;
            correlations += [semantic[@"il2cppCorrelationCount"] unsignedIntegerValue];
        }

        [records addObject:@{ @"label": seed[@"label"] ?: @"",
                              @"selector": seed[@"selector"] ?: @"",
                              @"registeredEvent": seed[@"event"] ?: @"",
                              @"controlToken": token ?: @"",
                              @"controlClass": seed[@"controlClass"] ?: @"",
                              @"targetClass": target ? (NSStringFromClass(object_getClass(target)) ?: @"?") : @"?",
                              @"ownership": ownership ?: @{},
                              @"handlerBlocks": blocks,
                              @"handlerBlockCount": @(blocks.count),
                              @"runtimeMethodCandidateCount": @(methodCandidates),
                              @"featureOwnedRuntimeMethodCandidateCount": @(featureOwnedMethodCandidates),
                              @"il2cppCorrelationCount": @(correlations),
                              @"association": @"exact-action-seed-feature-ownership-graph",
                              @"analysisOnly": @YES, @"canonicalEligible": @NO }];
    }

    NSUInteger totalCandidates = 0, totalOwnedCandidates = 0, totalCorrelations = 0, totalExactDescriptors = 0;
    for (NSDictionary *record in records) {
        totalCandidates += [record[@"runtimeMethodCandidateCount"] unsignedIntegerValue];
        totalOwnedCandidates += [record[@"featureOwnedRuntimeMethodCandidateCount"] unsignedIntegerValue];
        totalCorrelations += [record[@"il2cppCorrelationCount"] unsignedIntegerValue];
        totalExactDescriptors += [record[@"ownership"][@"exactLabelDescriptorCount"] unsignedIntegerValue];
    }

    return @{ @"schema": @"com.hfa.feature-handler-graph/v2",
              @"status": @"complete",
              @"records": records,
              @"recordCount": @(records.count),
              @"runtimeMethodCandidateCount": @(totalCandidates),
              @"featureOwnedRuntimeMethodCandidateCount": @(totalOwnedCandidates),
              @"exactLabelDescriptorCount": @(totalExactDescriptors),
              @"il2cppCorrelationCount": @(totalCorrelations),
              @"policy": @"verify-style-known-feature-ownership-descriptor-to-callback-no-global-method-guessing",
              @"genericity": @"no-sample-name-no-sample-rva-no-known-method-input",
              @"analysisOnly": @YES, @"canonicalEligible": @NO,
              @"selectorsInvoked": @NO, @"blocksInvoked": @NO,
              @"hooksInstalled": @NO, @"memoryWritten": @NO };
}
