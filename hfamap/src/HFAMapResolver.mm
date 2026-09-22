#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapHookSemantic.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <mach/vm_prot.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger kHFAMaxViews = 768, kHFAMaxTargets = 192;
static const NSUInteger kHFAMaxContainers = 256, kHFAMaxItems = 128;
static const NSUInteger kHFAMaxRuntimeMethods = 192, kHFAMaxRuntimeMetadata = 64;
static const uint32_t kHFAMaxLoadedImages = 2048;

static void HFAResolveEvent(NSMutableArray *events, NSString *status, NSDictionary *details) {
    NSMutableDictionary *event = [@{ @"time": @([[NSDate date] timeIntervalSince1970]),
                                      @"stage": @"feature-resolution", @"status": status } mutableCopy];
    if (details) [event addEntriesFromDictionary:details];
    [events addObject:event];
}

static NSData *HFAHexData(NSString *text) {
    if (![text isKindOfClass:NSString.class]) return nil;
    NSString *clean = [[text stringByReplacingOccurrencesOfString:@"0x" withString:@""]
                       stringByReplacingOccurrencesOfString:@" " withString:@""];
    clean = [clean stringByReplacingOccurrencesOfString:@"_" withString:@""];
    if (!clean.length || clean.length % 2 || clean.length > 512) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:clean.length / 2];
    for (NSUInteger i = 0; i < clean.length; i += 2) {
        unsigned value = 0;
        NSScanner *scanner = [NSScanner scannerWithString:[clean substringWithRange:NSMakeRange(i, 2)]];
        if (![scanner scanHexInt:&value] || !scanner.isAtEnd) return nil;
        uint8_t byte = (uint8_t)value; [data appendBytes:&byte length:1];
    }
    return data;
}

static NSData *HFABytesValue(id value) {
    if ([value isKindOfClass:NSData.class]) return value;
    if ([value isKindOfClass:NSString.class]) return HFAHexData(value);
    if (![value isKindOfClass:NSArray.class] || [value count] > 256) return nil;
    NSMutableData *data = [NSMutableData dataWithCapacity:[value count]];
    for (id item in value) {
        if (![item isKindOfClass:NSNumber.class] || [item unsignedIntegerValue] > 255) return nil;
        uint8_t byte = [item unsignedCharValue]; [data appendBytes:&byte length:1];
    }
    return data.length ? data : nil;
}

static NSNumber *HFAOffsetValue(id value) {
    if ([value isKindOfClass:NSNumber.class]) return @([value unsignedLongLongValue]);
    if (![value isKindOfClass:NSString.class]) return nil;
    NSString *text = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    const char *raw = text.UTF8String; if (!raw || !*raw || raw[0] == '-') return nil;
    errno = 0; char *end = NULL; unsigned long long number = strtoull(raw, &end, 0);
    return errno == 0 && end && *end == '\0' ? @(number) : nil;
}

// Secret-wrapper descriptor offsets are hexadecimal addresses. Some families
// include the 0x prefix while others emit bare hexadecimal text such as
// "100813348". The generic field parser above intentionally keeps its existing
// base-0 behavior; only authenticated scratch-copy decrypt output enters here.
static NSNumber *HFADecodedOffsetValue(id value) {
    if (![value isKindOfClass:NSString.class]) return nil;
    NSString *text = [value stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    const char *raw = text.UTF8String;
    if (!raw || !*raw || raw[0] == '-') return nil;
    if (raw[0] == '0' && (raw[1] == 'x' || raw[1] == 'X')) raw += 2;
    if (!*raw) return nil;
    for (const char *cursor = raw; *cursor; ++cursor) {
        BOOL digit = *cursor >= '0' && *cursor <= '9';
        BOOL lower = *cursor >= 'a' && *cursor <= 'f';
        BOOL upper = *cursor >= 'A' && *cursor <= 'F';
        if (!digit && !lower && !upper) return nil;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long number = strtoull(raw, &end, 16);
    return errno == 0 && end && *end == '\0' ? @(number) : nil;
}

static id HFAValueForAliases(NSDictionary *dictionary, NSArray<NSString *> *aliases) {
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class]) continue;
        NSString *lower = [[key lowercaseString] stringByTrimmingCharactersInSet:
                           [NSCharacterSet characterSetWithCharactersInString:@"_"]];
        for (NSString *alias in aliases) if ([lower isEqualToString:alias]) return dictionary[key];
    }
    return nil;
}

static NSArray<NSDictionary *> *HFAReadOnlyDescriptorEvidence(NSDictionary *dictionary, NSString *candidateImage,
                                                               NSArray<NSDictionary *> *execImages);

static NSDictionary *HFARuntimeSemantic(NSDictionary *dictionary, NSString *family,
                                        NSUInteger canonicalCount) {
    if (![family isEqualToString:@"jailpatch"] || canonicalCount) return nil;
    id offsetCandidate = HFAValueForAliases(dictionary,
        @[@"offset", @"patchoffset", @"targetoffset", @"address", @"rva"]);
    id patchCandidate = HFAValueForAliases(dictionary,
        @[@"enabled", @"enabledbytes", @"patch", @"patchbytes", @"bytes", @"instruction"]);
    if (offsetCandidate || patchCandidate) return nil;
    id typeValue = HFAValueForAliases(dictionary, @[@"type"]);
    NSString *type = [typeValue isKindOfClass:NSString.class] ? typeValue : @"unknown";
    NSString *lower = type.lowercaseString;
    NSString *control = @"unknown", *primitive = @"runtimePrimitive";
    NSString *reason = @"jailpatch-config-not-static-bytes";
    if ([lower containsString:@"modtext"] || [lower containsString:@"number"] ||
        [lower containsString:@"slider"] || [lower containsString:@"text"]) {
        control = @"number"; primitive = @"runtimeValue";
        reason = @"runtime-value-not-static-bytes";
    } else if ([lower containsString:@"switch"] || [lower containsString:@"toggle"]) {
        control = @"toggle"; primitive = @"runtimeToggle";
        reason = @"runtime-toggle-not-static-bytes";
    } else if ([lower containsString:@"button"]) {
        control = @"button"; primitive = @"runtimeAction";
        reason = @"runtime-action-not-static-bytes";
    }
    NSMutableDictionary *record = [@{
        @"normalizedControl": control,
        @"normalizedExecutionPrimitive": primitive,
        @"normalizedCanonicalReason": reason,
        @"analysisOnly": @YES,
        @"staticPatchEligible": @NO
    } mutableCopy];
    id defaultValue = HFAValueForAliases(dictionary, @[@"defaultvalue", @"default", @"value"]);
    if ([defaultValue isKindOfClass:NSNumber.class] || [defaultValue isKindOfClass:NSString.class])
        record[@"defaultValue"] = defaultValue;
    id handler = HFAValueForAliases(dictionary, @[@"kbuttontaphandler", @"handler", @"action"]);
    if (handler) record[@"handlerPresent"] = @YES;
    return record;
}

// Read the same label/identifier feature dictionaries used by the device-tested
// family resolver. Only inert scalar metadata enters the exported registry.
static NSDictionary *HFARegistryRecord(NSDictionary *dictionary, NSString *family,
                                       NSString *sourceClass, NSString *candidateImage,
                                       NSArray<NSDictionary *> *execImages) {
    id label = HFAValueForAliases(dictionary, @[@"label", @"title", @"name"]);
    id identifier = HFAValueForAliases(dictionary, @[@"identifier"]);
    if (![label isKindOfClass:NSString.class] || ![identifier isKindOfClass:NSString.class] ||
        ![label length] || ![identifier length]) return nil;
    id type = HFAValueForAliases(dictionary, @[@"type"]);
    NSMutableArray<NSDictionary *> *children = [NSMutableArray array];
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class] || children.count >= 32) continue;
        id value = dictionary[key];
        if ([value isKindOfClass:NSArray.class] && [value count] <= kHFAMaxItems)
            [children addObject:@{ @"field": key, @"kind": @"array", @"count": @([value count]) }];
        else if ([value isKindOfClass:NSDictionary.class])
            [children addObject:@{ @"field": key, @"kind": @"dictionary", @"count": @([value count]) }];
    }
    NSArray *descriptorEvidence = HFAReadOnlyDescriptorEvidence(dictionary, candidateImage, execImages);
    NSUInteger canonicalCount = 0;
    for (NSDictionary *record in descriptorEvidence) if (record[@"canonicalPatch"]) ++canonicalCount;
    NSMutableDictionary *record = [@{ @"name": label, @"identifier": identifier,
              @"type": [type isKindOfClass:NSString.class] ? type : @"unknown",
              @"sourceClass": sourceClass ?: @"?", @"sourceFamily": family ?: @"unknown",
              @"children": children, @"descriptorEvidence": descriptorEvidence,
              @"canonicalEligible": @(canonicalCount > 0), @"canonicalPatchCount": @(canonicalCount),
              @"evidence": @[@"ui-target-reachable", @"same-feature-dictionary"] } mutableCopy];
    NSDictionary *semantic = HFARuntimeSemantic(dictionary, family, canonicalCount);
    if (semantic) {
        [record addEntriesFromDictionary:semantic];
        record[@"evidence"] = @[@"ui-target-reachable", @"same-feature-dictionary",
                                 @"jailpatch-ui-config-schema"];
    }
    return record;
}

static BOOL HFADescriptorSignal(NSDictionary *dictionary) {
    static NSSet<NSString *> *signals; static dispatch_once_t once;
    // This target is compiled under MRC. A convenience-created object stored in a
    // dispatch_once static becomes dangling after the first worker autorelease
    // pool drains, so the second scan can crash while dereferencing `signals`.
    dispatch_once(&once, ^{ signals = [[NSSet alloc] initWithArray:@[
        @"label", @"title", @"name", @"identifier", @"displayname",
        @"offset", @"offsets", @"patchoffset", @"targetoffset", @"address", @"rva",
        @"enabled", @"enabledbytes", @"disabled", @"disabledbytes",
        @"patch", @"patches", @"patchbytes", @"bytes", @"instruction"
    ]]; });
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class]) continue;
        NSString *normalized = [[key lowercaseString] stringByTrimmingCharactersInSet:
                                [NSCharacterSet characterSetWithCharactersInString:@"_"]];
        if ([signals containsObject:normalized]) return YES;
    }
    return NO;
}

static BOOL HFACandidateOwnedObject(id value, NSString *candidateImage) {
    if (!value || !candidateImage.length) return NO;
    const char *path = class_getImageName(object_getClass(value));
    NSString *image = path ? [NSString stringWithUTF8String:path].lastPathComponent : @"";
    return [image isEqualToString:candidateImage];
}

static BOOL HFAPathIsSystemImage(NSString *path) {
    NSString *standard = path.stringByStandardizingPath;
    return [standard hasPrefix:@"/System/Library/"] || [standard hasPrefix:@"/usr/lib/"];
}

static NSString *HFAUUIDForLoadedBase(const void *base) {
    if (!base) return @"unknown";
    for (uint32_t i = 0, n = MIN(_dyld_image_count(), kHFAMaxLoadedImages); i < n; ++i) {
        const struct mach_header_64 *header =
            reinterpret_cast<const struct mach_header_64 *>(_dyld_get_image_header(i));
        if (header != base || !header || header->magic != MH_MAGIC_64 ||
            header->ncmds > 4096 || header->sizeofcmds > 4U * 1024U * 1024U) continue;
        const uint8_t *cursor = reinterpret_cast<const uint8_t *>(header + 1);
        const uint8_t *end = cursor + header->sizeofcmds;
        for (uint32_t c = 0; c < header->ncmds && cursor + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(cursor);
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                const uint8_t *u = reinterpret_cast<const struct uuid_command *>(lc)->uuid;
                return [NSString stringWithFormat:
                    @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];
            }
            cursor += lc->cmdsize;
        }
    }
    return @"unknown";
}

static NSDictionary *HFAImplementationLocation(IMP imp, NSString *menuImage) {
    Dl_info info = {};
    if (!imp || !dladdr(reinterpret_cast<const void *>(imp), &info) ||
        !info.dli_fbase || !info.dli_fname) return nil;
    NSString *path = [NSString stringWithUTF8String:info.dli_fname];
    NSString *image = path.lastPathComponent ?: @"?";
    return @{ @"implementationImage": image,
              @"implementationPath": path ?: @"?",
              @"implementationUUID": HFAUUIDForLoadedBase(info.dli_fbase),
              @"implementationOffsetFromLoadBase":
                  [NSString stringWithFormat:@"0x%llX",
                   (unsigned long long)((uintptr_t)imp - (uintptr_t)info.dli_fbase)],
              @"selectedMenuImage": @([image isEqualToString:menuImage]),
              @"systemImage": @(HFAPathIsSystemImage(path)) };
}

static NSString *HFAObjectToken(id object) {
    if (!object) return @"nil";
    return [NSString stringWithFormat:@"%@:%p", NSStringFromClass(object_getClass(object)) ?: @"?",
                                      (__bridge const void *)object];
}

static NSString *HFAHexPrefix(const uint8_t *bytes, NSUInteger length) {
    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
    for (NSUInteger i = 0; i < length; ++i) [hex appendFormat:@"%02X", bytes[i]];
    return hex;
}

// Read-only, bounded evidence for native pointer ivars. The masked length is only
// a structural candidate observed in matching binaries, never treated as a patch RVA.
static NSDictionary *HFAPointerMemoryEvidence(uintptr_t pointer) {
    NSMutableDictionary *result = [@{
        @"pointerValue": [NSString stringWithFormat:@"0x%llX", (unsigned long long)pointer],
        @"readable": @NO, @"invoked": @NO, @"written": @NO
    } mutableCopy];
    if (!pointer) { result[@"status"] = @"null"; return result; }

    uint8_t bytes[256] = {};
    vm_size_t initial = 40;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)pointer, initial,
                                         (vm_address_t)bytes, &copied);
    if (kr != KERN_SUCCESS || copied < sizeof(uint32_t)) {
        result[@"status"] = @"read-failed"; result[@"readResult"] = @(kr); return result;
    }

    uint32_t word0 = 0; memcpy(&word0, bytes, sizeof(word0));
    uint32_t lengthCandidate = word0 & 0xfffffff0U;
    uint64_t totalCandidate = (uint64_t)lengthCandidate + 40U;
    vm_size_t desired = initial;
    BOOL saneLength = lengthCandidate <= 4096U && totalCandidate >= 40U;
    if (saneLength) desired = MIN((vm_size_t)sizeof(bytes), (vm_size_t)totalCandidate);
    if (desired > copied) {
        vm_size_t secondCopy = 0;
        kr = vm_read_overwrite(mach_task_self(), (vm_address_t)pointer, desired,
                               (vm_address_t)bytes, &secondCopy);
        if (kr == KERN_SUCCESS) copied = secondCopy;
    }
    result[@"status"] = @"captured";
    result[@"readable"] = @YES;
    result[@"headerWord0"] = [NSString stringWithFormat:@"0x%08X", word0];
    result[@"maskedLengthCandidate"] = @(lengthCandidate);
    result[@"lengthCandidateSane"] = @(saneLength);
    result[@"candidateRecordBytes"] = saneLength ? @(totalCandidate) : [NSNull null];
    result[@"capturedBytes"] = @(copied);
    result[@"captureCompleteForCandidate"] = @(saneLength && totalCandidate <= copied);
    result[@"hexPrefix"] = HFAHexPrefix(bytes, (NSUInteger)MIN(copied, (vm_size_t)sizeof(bytes)));
    return result;
}

typedef int (*HFASecretDecryptFn)(void *, void *);

static BOOL HFAReadMemoryExact(uintptr_t address, void *output, size_t length) {
    if (!address || !output || !length || length > 0x12000U) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)address,
                                         (vm_size_t)length, (vm_address_t)output, &copied);
    return kr == KERN_SUCCESS && copied == length;
}

struct HFABlockLiteralHeader {
    uintptr_t isa;
    int32_t flags;
    int32_t reserved;
    uintptr_t invoke;
    uintptr_t descriptor;
};

static int64_t HFASignExtendBits(uint64_t value, unsigned bits) {
    uint64_t sign = 1ULL << (bits - 1U);
    return (int64_t)((value ^ sign) - sign);
}

static BOOL HFADecodeARM64ADRP(uint32_t word, uintptr_t pc, uintptr_t *pageOut,
                               unsigned *registerOut) {
    if ((word & 0x9F000000U) != 0x90000000U) return NO;
    uint64_t immediate = (((uint64_t)word >> 5U) & 0x7FFFFU) << 2U;
    immediate |= ((uint64_t)word >> 29U) & 3U;
    int64_t delta = HFASignExtendBits(immediate, 21) << 12;
    if (pageOut) *pageOut = (uintptr_t)((int64_t)(pc & ~(uintptr_t)0xFFFU) + delta);
    if (registerOut) *registerOut = word & 31U;
    return YES;
}

static BOOL HFADecodeARM64AddImmediate(uint32_t word, unsigned *destinationOut,
                                       unsigned *sourceOut, uint64_t *immediateOut) {
    if ((word & 0xFF000000U) != 0x91000000U) return NO;
    uint64_t immediate = (word >> 10U) & 0xFFFU;
    if ((word >> 22U) & 1U) immediate <<= 12U;
    if (destinationOut) *destinationOut = word & 31U;
    if (sourceOut) *sourceOut = (word >> 5U) & 31U;
    if (immediateOut) *immediateOut = immediate;
    return YES;
}

static BOOL HFADecodeARM64DirectBranch(uint32_t word, uintptr_t pc, uintptr_t *targetOut) {
    if ((word & 0x7C000000U) != 0x14000000U) return NO;
    int64_t delta = HFASignExtendBits(word & 0x03FFFFFFU, 26) << 2;
    if (targetOut) *targetOut = (uintptr_t)((int64_t)pc + delta);
    return YES;
}

static uintptr_t HFAResolveARM64StubTarget(uintptr_t address) {
    uint32_t words[3] = {};
    if (!HFAReadMemoryExact(address, words, sizeof(words))) return 0;
    uintptr_t page = 0;
    unsigned pageRegister = 0;
    if (!HFADecodeARM64ADRP(words[0], address, &page, &pageRegister)) return 0;
    if ((words[1] & 0xFFC00000U) != 0xF9400000U) return 0;
    unsigned targetRegister = words[1] & 31U;
    unsigned baseRegister = (words[1] >> 5U) & 31U;
    uint64_t offset = ((words[1] >> 10U) & 0xFFFU) * 8U;
    if (targetRegister != pageRegister || baseRegister != pageRegister ||
        (words[2] & 0xFFFFFC1FU) != 0xD61F0000U ||
        ((words[2] >> 5U) & 31U) != pageRegister) return 0;
    uintptr_t resolved = 0;
    return HFAReadMemoryExact(page + offset, &resolved, sizeof(resolved)) ? resolved : 0;
}

static NSString *HFASymbolForDirectCall(uintptr_t target) {
    uintptr_t resolved = HFAResolveARM64StubTarget(target);
    Dl_info info = {};
    uintptr_t symbolAddress = resolved ? resolved : target;
    if (dladdr((const void *)symbolAddress, &info) && info.dli_sname)
        return [NSString stringWithUTF8String:info.dli_sname];
    // Some dyld exports resolve through a valid lazy/non-lazy stub but dladdr
    // reports an image without dli_sname on device. Compare the resolved target
    // with dlsym so semantic decoding does not depend on symbol-name retention.
    const char *known[] = { "_dyld_get_image_vmaddr_slide", "dyld_get_image_vmaddr_slide" };
    for (NSUInteger index = 0; index < sizeof(known) / sizeof(known[0]); ++index) {
        void *address = dlsym(RTLD_DEFAULT, known[index]);
        if (address && (uintptr_t)address == symbolAddress)
            return [NSString stringWithUTF8String:known[index]];
    }
    return nil;
}

static NSString *HFAReadConstantCFString(uintptr_t address) {
    struct {
        uintptr_t isa;
        uint32_t flags;
        uint32_t reserved;
        uintptr_t bytes;
        uint64_t length;
    } value = {};
    if (!HFAReadMemoryExact(address, &value, sizeof(value)) || !value.bytes ||
        !value.length || value.length > 256U) return nil;
    uint8_t buffer[256] = {};
    if (!HFAReadMemoryExact(value.bytes, buffer, (size_t)value.length)) return nil;
    return [[[NSString alloc] initWithBytes:buffer length:(NSUInteger)value.length
                                   encoding:NSUTF8StringEncoding] autorelease];
}

static BOOL HFADecodeMoveWide32(uint32_t word, uint32_t values[32], BOOL known[32]) {
    unsigned reg = word & 31U;
    unsigned shift = ((word >> 21U) & 3U) * 16U;
    uint32_t immediate = (word >> 5U) & 0xFFFFU;
    if ((word & 0x7F800000U) == 0x52800000U) {
        values[reg] = immediate << shift;
        known[reg] = YES;
        return YES;
    }
    if ((word & 0x7F800000U) == 0x72800000U && known[reg]) {
        uint32_t mask = 0xFFFFU << shift;
        values[reg] = (values[reg] & ~mask) | (immediate << shift);
        return YES;
    }
    return NO;
}

// Bounded semantic decoding only. It follows at most one nested global Block and
// never invokes the Block, calls an unknown selector, installs a hook, or writes memory.
static NSDictionary *HFAClassifyBlockInvoke(uintptr_t invoke, NSString *menuImage,
                                             BOOL allowNested) {
    uint32_t words[24] = {};
    if (!HFAReadMemoryExact(invoke, words, sizeof(words)))
        return @{ @"semanticClass": @"instruction-window-unreadable",
                  @"analysisOnly": @YES, @"canonicalEligible": @NO };
    uintptr_t registerAddresses[32] = {};
    BOOL registerAddressKnown[32] = {};
    uint32_t registerConstants[32] = {};
    BOOL registerConstantKnown[32] = {};
    NSMutableArray<NSString *> *imports = [NSMutableArray array];
    NSString *constantString = nil;
    uintptr_t nestedBlockAddress = 0;
    BOOL sawDispatch = NO, sawDyldSlide = NO, sawComputedBranch = NO, sawReturn = NO;
    uint32_t computedTargetRVA = 0;
    for (NSUInteger index = 0; index < 24; ++index) {
        uintptr_t pc = invoke + index * 4U;
        uint32_t word = words[index];
        if (word == 0xD65F03C0U) {
            sawReturn = YES;
            break;
        }
        uintptr_t page = 0;
        unsigned reg = 0;
        if (HFADecodeARM64ADRP(word, pc, &page, &reg)) {
            registerAddresses[reg] = page;
            registerAddressKnown[reg] = YES;
            continue;
        }
        unsigned destination = 0, source = 0;
        uint64_t immediate = 0;
        if (HFADecodeARM64AddImmediate(word, &destination, &source, &immediate) &&
            registerAddressKnown[source]) {
            registerAddresses[destination] = registerAddresses[source] + (uintptr_t)immediate;
            registerAddressKnown[destination] = YES;
            continue;
        }
        if (HFADecodeMoveWide32(word, registerConstants, registerConstantKnown)) continue;
        if ((word & 0xFFE0FC00U) == 0x8B000000U) {
            unsigned rm = (word >> 16U) & 31U;
            unsigned rn = (word >> 5U) & 31U;
            unsigned rd = word & 31U;
            if (rd == 0U && rn == 0U && registerConstantKnown[rm] && sawDyldSlide)
                computedTargetRVA = registerConstants[rm];
            continue;
        }
        if ((word & 0xFFFFFC1FU) == 0xD61F0000U) {
            unsigned branchReg = (word >> 5U) & 31U;
            if (branchReg == 0U && computedTargetRVA) sawComputedBranch = YES;
            break;
        }
        uintptr_t branchTarget = 0;
        if (!HFADecodeARM64DirectBranch(word, pc, &branchTarget)) continue;
        NSString *symbol = HFASymbolForDirectCall(branchTarget);
        if (!symbol.length) continue;
        if (![imports containsObject:symbol]) [imports addObject:symbol];
        NSString *lower = symbol.lowercaseString;
        if ([lower containsString:@"nslog"] && registerAddressKnown[0])
            constantString = HFAReadConstantCFString(registerAddresses[0]);
        if ([lower containsString:@"dispatch_async"]) {
            sawDispatch = YES;
            if (registerAddressKnown[1]) nestedBlockAddress = registerAddresses[1];
        }
        if ([lower containsString:@"dyld_get_image_vmaddr_slide"]) sawDyldSlide = YES;
        if ((word & 0xFC000000U) == 0x14000000U) break;
    }
    NSMutableDictionary *result = [@{
        @"semanticClass": @"unresolved-block-semantics",
        @"confidence": @"low",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"imports": imports,
        @"instructionWindowBytes": @(sizeof(words)),
        @"invoked": @NO,
        @"hookInstalled": @NO,
        @"memoryWritten": @NO
    } mutableCopy];
    if (constantString.length) result[@"referencedConstantString"] = constantString;
    BOOL logger = constantString.length && [constantString isEqualToString:@"iGMM Initialized"] &&
                  sawReturn && imports.count == 1;
    if (logger) {
        result[@"semanticClass"] = @"nonsemantic-logging-block";
        result[@"confidence"] = @"high";
        result[@"featureHandlerCandidate"] = @NO;
        result[@"evidence"] = @[@"direct-import-NSLog", @"exact-iGMM-initialized-cfstring",
                                 @"bounded-instruction-decode"];
        return [result autorelease];
    }
    if (sawDyldSlide && sawComputedBranch && computedTargetRVA) {
        result[@"semanticClass"] = @"runtime-action-target-resolved";
        result[@"confidence"] = @"high";
        result[@"featureHandlerCandidate"] = @YES;
        result[@"preferredTargetRVA"] = [NSString stringWithFormat:@"0x%X", computedTargetRVA];
        result[@"preferredTargetRVAValue"] = @(computedTargetRVA);
        result[@"targetAddressSemantics"] = @"image-slide-plus-preferred-vm-rva";
        result[@"evidence"] = @[@"dyld-image-slide-call", @"bounded-move-wide-constant",
                                 @"add-slide-and-tail-branch"];
        return [result autorelease];
    }
    if (sawDispatch && nestedBlockAddress && allowNested) {
        HFABlockLiteralHeader nested = {};
        if (HFAReadMemoryExact(nestedBlockAddress, &nested, sizeof(nested)) && nested.invoke &&
            !(nested.invoke & 3U)) {
            NSMutableDictionary *nestedEvidence = [NSMutableDictionary dictionary];
            nestedEvidence[@"blockPointer"] = [NSString stringWithFormat:@"0x%llX",
                                                  (unsigned long long)nestedBlockAddress];
            nestedEvidence[@"invokePointer"] = [NSString stringWithFormat:@"0x%llX",
                                                   (unsigned long long)nested.invoke];
            NSDictionary *location = HFAImplementationLocation((IMP)nested.invoke, menuImage);
            if (location) [nestedEvidence addEntriesFromDictionary:location];
            NSDictionary *nestedSemantic = HFAClassifyBlockInvoke(nested.invoke, menuImage, NO);
            if (nestedSemantic) [nestedEvidence addEntriesFromDictionary:nestedSemantic];
            result[@"semanticClass"] = @"runtime-action-dispatch-chain";
            result[@"confidence"] = @"high";
            result[@"featureHandlerCandidate"] = @YES;
            result[@"nestedBlock"] = nestedEvidence;
            result[@"evidence"] = @[@"direct-import-dispatch_async", @"x1-global-block-literal",
                                     @"nested-invoke-bounded-decode"];
        }
    }
    return [result autorelease];
}

static BOOL HFAIsBlockObject(id object) {
    if (!object) return NO;
    NSString *name = NSStringFromClass(object_getClass(object)) ?: @"";
    return [name isEqualToString:@"__NSGlobalBlock__"] ||
           [name isEqualToString:@"__NSMallocBlock__"] ||
           [name isEqualToString:@"__NSStackBlock__"] ||
           [name hasSuffix:@"Block"] || [name hasSuffix:@"Block__"];
}

// Apple Block ABI header observation only. Never invoke/copy/release the block,
// parse captured objects, install a hook, or treat the invoke RVA as a game patch.
static NSDictionary *HFAReadOnlyBlockProvenance(id block, id owner, NSString *field,
                                                NSString *label, NSString *menuImage) {
    if (!HFAIsBlockObject(block)) return nil;
    HFABlockLiteralHeader header = {};
    uintptr_t address = (uintptr_t)(__bridge const void *)block;
    NSMutableDictionary *result = [@{
        @"status": @"header-unreadable",
        @"blockClass": NSStringFromClass(object_getClass(block)) ?: @"?",
        @"ownerClass": owner ? (NSStringFromClass(object_getClass(owner)) ?: @"?") : @"?",
        @"ownerToken": HFAObjectToken(owner),
        @"field": field ?: @"?",
        @"labelContext": label ?: @"",
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO,
        @"invoked": @NO,
        @"copied": @NO,
        @"released": @NO,
        @"hookInstalled": @NO,
        @"memoryWritten": @NO,
        @"association": @"same-ui-target-object-graph"
    } mutableCopy];
    Ivar ivar = owner && field.length ? class_getInstanceVariable(object_getClass(owner),
                                                                   field.UTF8String) : NULL;
    if (ivar) result[@"ownerIvarOffset"] = [NSString stringWithFormat:@"0x%tx", ivar_getOffset(ivar)];
    else result[@"ownerIvarOffset"] = @"dictionary-or-unknown";
    if (!HFAReadMemoryExact(address, &header, sizeof(header))) return result;
    result[@"flags"] = [NSString stringWithFormat:@"0x%08X", (uint32_t)header.flags];
    result[@"isGlobal"] = @((header.flags & (1U << 28U)) != 0);
    result[@"needsFree"] = @((header.flags & (1U << 24U)) != 0);
    result[@"hasCopyDispose"] = @((header.flags & (1U << 25U)) != 0);
    result[@"hasSignature"] = @((header.flags & (1U << 30U)) != 0);
    result[@"descriptorPointer"] = [NSString stringWithFormat:@"0x%llX",
                                      (unsigned long long)header.descriptor];
    if (!header.invoke || (header.invoke & 3U)) {
        result[@"status"] = @"invoke-invalid";
        return result;
    }
    NSDictionary *location = HFAImplementationLocation((IMP)header.invoke, menuImage);
    if (!location) {
        result[@"status"] = @"invoke-location-unresolved";
        return result;
    }
    [result addEntriesFromDictionary:location];
    result[@"status"] = [location[@"selectedMenuImage"] boolValue] ? @"menu-invoke-resolved"
                                                                  : @"external-invoke-resolved";
    if ([location[@"selectedMenuImage"] boolValue]) {
        uint8_t prefix[32] = {};
        if (HFAReadMemoryExact(header.invoke, prefix, sizeof(prefix))) {
            result[@"invokeInstructionPrefix"] = HFAHexPrefix(prefix, sizeof(prefix));
            result[@"invokeInstructionBytes"] = @(sizeof(prefix));
        }
        result[@"semanticEvidence"] = HFAClassifyBlockInvoke(header.invoke, menuImage, YES);
    }
    return result;
}

static BOOL HFATextRangeForLoadedBase(const void *base, uintptr_t *startOut, uintptr_t *endOut) {
    for (uint32_t i = 0, count = MIN(_dyld_image_count(), kHFAMaxLoadedImages); i < count; ++i) {
        const struct mach_header_64 *header =
            reinterpret_cast<const struct mach_header_64 *>(_dyld_get_image_header(i));
        if ((const void *)header != base || !header || header->magic != MH_MAGIC_64 ||
            header->ncmds > 4096 || header->sizeofcmds > 4U * 1024U * 1024U) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *cursor = reinterpret_cast<const uint8_t *>(header + 1);
        const uint8_t *end = cursor + header->sizeofcmds;
        for (uint32_t c = 0; c < header->ncmds && cursor + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(cursor);
            if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return NO;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *segment =
                    reinterpret_cast<const struct segment_command_64 *>(cursor);
                if (sizeof(*segment) + (uint64_t)segment->nsects * sizeof(struct section_64) > lc->cmdsize)
                    return NO;
                const struct section_64 *sections =
                    reinterpret_cast<const struct section_64 *>(segment + 1);
                for (uint32_t s = 0; s < segment->nsects; ++s) {
                    if (strncmp(sections[s].sectname, "__text", 16) != 0) continue;
                    uintptr_t start = (uintptr_t)slide + (uintptr_t)sections[s].addr;
                    uintptr_t size = (uintptr_t)sections[s].size;
                    if (!size || size > 64U * 1024U * 1024U || UINTPTR_MAX - start < size) return NO;
                    if (startOut) *startOut = start;
                    if (endOut) *endOut = start + size;
                    return YES;
                }
            }
            cursor += lc->cmdsize;
        }
    }
    return NO;
}

static NSDictionary *HFAUniqueDecryptCandidateForIMP(IMP getter) {
    Dl_info info = {};
    if (!getter || !dladdr(reinterpret_cast<const void *>(getter), &info) ||
        !info.dli_fbase || !info.dli_fname)
        return @{ @"status": @"getter-owner-unresolved", @"matchCount": @0 };
    static NSMutableDictionary<NSString *, NSDictionary *> *cache;
    static dispatch_once_t once;
    // Keep the process-lifetime cache alive under both MRC and ARC. The former
    // convenience constructor left a dangling static after scan one.
    dispatch_once(&once, ^{ cache = [[NSMutableDictionary alloc] init]; });
    NSString *key = [NSString stringWithFormat:@"%p", info.dli_fbase];
    NSDictionary *cached = cache[key];
    if (cached) return cached;

    uintptr_t start = 0, end = 0;
    if (!HFATextRangeForLoadedBase(info.dli_fbase, &start, &end)) {
        NSDictionary *result = @{ @"status": @"text-range-unresolved", @"matchCount": @0 };
        cache[key] = result; return result;
    }
    uintptr_t candidate = 0; NSUInteger matches = 0;
    const uint32_t insn0 = 0xD105C3FFU, insn30 = 0xB9400408U, insn40 = 0x53187D00U;
    for (uintptr_t address = start; address <= end && end - address >= 0x44U; address += 4U) {
        uint32_t a = 0, b = 0, c = 0;
        memcpy(&a, reinterpret_cast<const void *>(address), sizeof(a));
        if (a != insn0) continue;
        memcpy(&b, reinterpret_cast<const void *>(address + 0x30U), sizeof(b));
        memcpy(&c, reinterpret_cast<const void *>(address + 0x40U), sizeof(c));
        if (b != insn30 || c != insn40) continue;
        candidate = address; ++matches;
        if (matches > 1) break;
    }
    NSString *image = [[NSString stringWithUTF8String:info.dli_fname] lastPathComponent] ?: @"?";
    NSMutableDictionary *result = [@{ @"status": matches == 1 ? @"unique" :
                                                (matches ? @"ambiguous" : @"not-found"),
                                        @"matchCount": @(matches), @"image": image,
                                        @"imageUUID": HFAUUIDForLoadedBase(info.dli_fbase) } mutableCopy];
    if (matches == 1) {
        result[@"address"] = @(candidate);
        result[@"rva"] = [NSString stringWithFormat:@"0x%llX",
                           (unsigned long long)(candidate - (uintptr_t)info.dli_fbase)];
    }
    cache[key] = result;
    return result;
}

static uintptr_t HFAWrapperSecretPointer(id wrapper, NSString **reason) {
    if (!wrapper) { if (reason) *reason = @"nil-wrapper"; return 0; }
    uintptr_t found = 0; NSUInteger pointerIvars = 0;
    for (Class cls = object_getClass(wrapper); cls && cls != NSObject.class; cls = class_getSuperclass(cls)) {
        unsigned count = 0; Ivar *ivars = class_copyIvarList(cls, &count);
        for (unsigned i = 0; ivars && i < MIN(count, 64U); ++i) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            if (!type || type[0] != '^' || offset < 0 ||
                (size_t)offset + sizeof(uintptr_t) > class_getInstanceSize(object_getClass(wrapper))) continue;
            uintptr_t value = 0;
            const uint8_t *address = reinterpret_cast<const uint8_t *>((__bridge const void *)wrapper) + offset;
            memcpy(&value, address, sizeof(value));
            found = value; ++pointerIvars;
        }
        free(ivars);
    }
    if (pointerIvars != 1) { if (reason) *reason = pointerIvars ? @"ambiguous-pointer-ivars" : @"pointer-ivar-missing"; return 0; }
    if (!found) { if (reason) *reason = @"secret-null"; return 0; }
    return found;
}

static NSDictionary *HFADecodeSecretWrapper(id wrapper, NSString *role) {
    NSMutableDictionary *result = [@{ @"status": @"unresolved", @"role": role ?: @"?",
                                       @"wrapperClass": wrapper ? (NSStringFromClass(object_getClass(wrapper)) ?: @"?") : @"nil",
                                       @"wrapperToken": HFAObjectToken(wrapper), @"targetMemoryWritten": @NO } mutableCopy];
    NSString *reason = nil; uintptr_t secret = HFAWrapperSecretPointer(wrapper, &reason);
    if (!secret) { result[@"reason"] = reason ?: @"secret-unresolved"; return result; }
    result[@"secretPointer"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)secret];
    uint32_t header[2] = {};
    if (!HFAReadMemoryExact(secret, header, sizeof(header))) { result[@"reason"] = @"secret-header-unreadable"; return result; }
    uint32_t length = header[0], flags = header[1];
    size_t blobSize = (size_t)(length & ~0xFU) + 0x28U;
    result[@"secretLength"] = @(length);
    result[@"secretFlags"] = [NSString stringWithFormat:@"0x%08X", flags];
    result[@"blobSize"] = @(blobSize);
    if (!length || length > 0x10000U || blobSize > 0x11000U) {
        result[@"reason"] = @"secret-length-out-of-range"; return result;
    }
    Method method = class_getInstanceMethod(object_getClass(wrapper), sel_registerName("secret"));
    if (!method || method_getNumberOfArguments(method) != 2) { result[@"reason"] = @"secret-getter-missing"; return result; }
    NSDictionary *candidate = HFAUniqueDecryptCandidateForIMP(method_getImplementation(method));
    result[@"decryptEvidence"] = candidate;
    if (![candidate[@"status"] isEqualToString:@"unique"]) { result[@"reason"] = @"decrypt-candidate-not-unique"; return result; }

    void *copy = malloc(blobSize); void *plain = calloc(1, (size_t)length + 0x20U);
    if (!copy || !plain) { free(copy); free(plain); result[@"reason"] = @"allocation-failed"; return result; }
    if (!HFAReadMemoryExact(secret, copy, blobSize)) {
        free(copy); free(plain); result[@"reason"] = @"secret-blob-unreadable"; return result;
    }
    int rc = ((HFASecretDecryptFn)(uintptr_t)[candidate[@"address"] unsignedLongLongValue])(copy, plain);
    result[@"decryptResult"] = @(rc);
    if (rc == 0) {
        const uint8_t *bytes = static_cast<const uint8_t *>(plain);
        size_t textLength = 0;
        while (textLength < length && bytes[textLength]) ++textLength;
        BOOL printable = textLength > 0;
        for (size_t i = 0; i < textLength; ++i)
            if (bytes[i] < 0x20 || bytes[i] > 0x7E) { printable = NO; break; }
        result[@"plaintextPrefixHex"] = HFAHexPrefix(bytes, MIN((size_t)32, (size_t)length));
        if (printable) {
            NSString *text = [[NSString alloc] initWithBytes:bytes length:textLength encoding:NSUTF8StringEncoding];
            if (text) { result[@"status"] = @"decoded"; result[@"plaintext"] = text; }
            else result[@"reason"] = @"plaintext-not-utf8";
        } else result[@"reason"] = @"plaintext-not-printable-ascii";
    } else result[@"reason"] = @"decrypt-call-failed";
    free(plain); free(copy);
    return result;
}

static NSUInteger HFADescriptorSelectorFingerprint(Class cls) {
    static const char *names[] = {"identifier", "type", "architecture", "active", "offset",
                                  "signature", "range", "searchDirection", "setActive:"};
    NSUInteger count = 0;
    for (NSUInteger i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        if (class_getInstanceMethod(cls, sel_registerName(names[i]))) ++count;
    return count;
}

static NSString *HFAMatchingExecutableImage(NSString *value, NSArray<NSDictionary *> *execImages) {
    if (!value.length) return nil;
    NSString *base = value.lastPathComponent;
    NSMutableSet<NSString *> *matches = [NSMutableSet set];
    for (NSDictionary *image in execImages) {
        NSString *name = image[@"image"];
        if ([base isEqualToString:name] ||
            [base.stringByDeletingPathExtension isEqualToString:name.stringByDeletingPathExtension])
            [matches addObject:name];
    }
    return matches.count == 1 ? matches.anyObject : nil;
}

static NSDictionary *HFAExecutableImageResolutionForDecoded(NSDictionary *offsetDecode,
                                                              NSDictionary *patchDecode,
                                                              NSArray<NSDictionary *> *execImages) {
    NSNumber *offset = HFADecodedOffsetValue(offsetDecode[@"plaintext"]);
    NSData *patch = HFABytesValue(patchDecode[@"plaintext"]);
    NSMutableDictionary *evidence = [@{
        @"source": @"decoded-offset-executable-range",
        @"offsetSemantics": @"preferred-mach-o-vmaddr",
        @"matchCount": @0
    } mutableCopy];
    if (!offset) { evidence[@"status"] = @"invalid-decoded-offset"; return evidence; }
    if (!patch.length || patch.length > 256) {
        evidence[@"status"] = @"invalid-decoded-patch";
        return evidence;
    }

    uint64_t preferredAddress = offset.unsignedLongLongValue;
    evidence[@"offset"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)preferredAddress];
    NSMutableArray<NSDictionary *> *matches = [NSMutableArray array];
    for (NSDictionary *image in execImages) {
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue];
        uint64_t size = [image[@"vmsize"] unsignedLongLongValue];
        if (preferredAddress < vmaddr) continue;
        uint64_t delta = preferredAddress - vmaddr;
        if (delta > size || patch.length > size - delta) continue;
        [matches addObject:image];
    }
    evidence[@"matchCount"] = @(matches.count);
    if (matches.count != 1) {
        evidence[@"status"] = matches.count ? @"ambiguous" : @"no-match";
        return evidence;
    }

    NSDictionary *image = matches.firstObject;
    evidence[@"status"] = @"unique";
    evidence[@"resolution"] = @"unique-offset-executable-range";
    evidence[@"targetImage"] = image[@"image"] ?: @"unknown";
    evidence[@"targetUUID"] = image[@"uuid"] ?: @"unknown";
    evidence[@"targetPath"] = image[@"path"] ?: @"unknown";
    evidence[@"targetVMAddr"] = image[@"vmaddr"] ?: @0;
    evidence[@"targetVMSize"] = image[@"vmsize"] ?: @0;
    return evidence;
}

static NSDictionary *HFACanonicalPatchFromDecoded(NSString *name, NSString *targetImage,
                                                   NSDictionary *offsetDecode, NSDictionary *patchDecode,
                                                   NSArray<NSDictionary *> *execImages) {
    NSString *offsetText = offsetDecode[@"plaintext"], *patchText = patchDecode[@"plaintext"];
    NSNumber *offset = HFADecodedOffsetValue(offsetText); NSData *patch = HFABytesValue(patchText);
    if (!offset || !patch.length || patch.length > 256 || !targetImage.length) return nil;
    uint64_t rva = offset.unsignedLongLongValue;
    NSMutableArray *matches = [NSMutableArray array];
    for (NSDictionary *image in execImages) {
        if (![image[@"image"] isEqualToString:targetImage]) continue;
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue];
        uint64_t size = [image[@"vmsize"] unsignedLongLongValue];
        if (rva >= vmaddr && rva - vmaddr <= size && patch.length <= size - (rva - vmaddr))
            [matches addObject:image];
    }
    if (matches.count != 1) return nil;
    NSDictionary *image = matches.firstObject;
    uintptr_t address = (uintptr_t)(rva + [image[@"slide"] longLongValue]);
    NSMutableData *original = [NSMutableData dataWithLength:patch.length];
    if (!HFAReadMemoryExact(address, original.mutableBytes, original.length) || [original isEqualToData:patch]) return nil;
    return @{ @"name": name ?: @"?", @"targetImage": targetImage,
              @"targetUUID": image[@"uuid"] ?: @"unknown",
              @"offset": [NSString stringWithFormat:@"0x%llX", (unsigned long long)rva],
              @"offsetSemantics": @"preferred-mach-o-vmaddr",
              @"original": HFAHexPrefix(static_cast<const uint8_t *>(original.bytes), original.length),
              @"patch": HFAHexPrefix(static_cast<const uint8_t *>(patch.bytes), patch.length),
              @"canonicalEligible": @YES, @"confidence": @"byte-validated",
              @"evidence": @[@"same-container-descriptor", @"unique-current-image-decrypt-fingerprint",
                               @"decoded-offset-hex-normalized", @"unique-target-image",
                               @"executable-range", @"live-original-bytes-captured-before-mutation"] };
}

static NSInteger HFAJailpatchMethodScore(NSString *selector, NSMutableArray<NSString *> *reasons) {
    NSString *lower = selector.lowercaseString;
    NSInteger score = 0;
    NSArray *rules = @[
        @[@"config", @40], @[@"policy", @35], @[@"offset", @30], @[@"instruction", @30],
        @[@"patch", @30], @[@"decrypt", @25], @[@"decode", @20], @[@"parse", @15],
        @[@"json", @15], @[@"plist", @15], @[@"load", @10], @[@"save", @8]
    ];
    for (NSArray *rule in rules) {
        if (![lower containsString:rule[0]]) continue;
        score += [rule[1] integerValue];
        [reasons addObject:[@"selector-token:" stringByAppendingString:rule[0]]];
    }
    if ([selector isEqualToString:@"loadConfig:"] || [selector isEqualToString:@"loadPolicies"]) {
        score += 100; [reasons addObject:@"known-exact-selector"];
    }
    return score;
}

static void HFAAppendJailpatchMethods(Class owner, NSString *kind, NSUInteger depth,
                                      NSString *menuImage, NSMutableArray *inventory,
                                      NSMutableArray *candidates, NSMutableArray *exactMethods) {
    if (!owner || inventory.count >= kHFAMaxRuntimeMethods) return;
    unsigned count = 0;
    Method *methods = class_copyMethodList(owner, &count);
    count = MIN(count, (unsigned)(kHFAMaxRuntimeMethods - inventory.count));
    for (unsigned i = 0; methods && i < count; ++i) {
        Method method = methods[i];
        SEL sel = method_getName(method);
        NSString *selector = sel ? NSStringFromSelector(sel) : @"?";
        NSDictionary *location = HFAImplementationLocation(method_getImplementation(method), menuImage);
        if (!location) continue;
        NSMutableArray<NSString *> *reasons = [NSMutableArray array];
        NSInteger score = HFAJailpatchMethodScore(selector, reasons);
        NSMutableDictionary *record = [location mutableCopy];
        record[@"selector"] = selector;
        record[@"methodKind"] = kind;
        record[@"declaringClass"] = NSStringFromClass(owner) ?: @"?";
        record[@"inheritanceDepth"] = @(depth);
        record[@"typeEncoding"] = [NSString stringWithUTF8String:method_getTypeEncoding(method) ?: "?"];
        record[@"argumentCount"] = @(method_getNumberOfArguments(method));
        char *returnType = method_copyReturnType(method);
        record[@"returnType"] = returnType ? [NSString stringWithUTF8String:returnType] : @"?";
        free(returnType);
        record[@"candidateScore"] = @(score);
        record[@"candidateReasons"] = reasons;
        record[@"invoked"] = @NO;
        record[@"hookInstalled"] = @NO;
        [inventory addObject:record];
        if (score > 0 && candidates.count < kHFAMaxRuntimeMetadata) [candidates addObject:record];
        if ([reasons containsObject:@"known-exact-selector"] && exactMethods.count < 8)
            [exactMethods addObject:record];
    }
    free(methods);
}

static NSArray<NSDictionary *> *HFAJailpatchIvarMetadata(Class cls) {
    NSMutableArray *result = [NSMutableArray array];
    for (Class owner = cls; owner && owner != NSObject.class && result.count < kHFAMaxRuntimeMetadata;
         owner = class_getSuperclass(owner)) {
        unsigned count = 0; Ivar *ivars = class_copyIvarList(owner, &count);
        count = MIN(count, (unsigned)(kHFAMaxRuntimeMetadata - result.count));
        for (unsigned i = 0; ivars && i < count; ++i) {
            const char *name = ivar_getName(ivars[i]);
            const char *type = ivar_getTypeEncoding(ivars[i]);
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            if (!name || !type || offset < 0) continue;
            [result addObject:@{ @"declaringClass": NSStringFromClass(owner) ?: @"?",
                                 @"name": [NSString stringWithUTF8String:name],
                                 @"typeEncoding": [NSString stringWithUTF8String:type],
                                 @"ivarOffset": [NSString stringWithFormat:@"0x%tx", offset],
                                 @"offsetSemantics": @"objc-instance-ivar-only" }];
        }
        free(ivars);
    }
    return result;
}

static NSArray<NSDictionary *> *HFAJailpatchPropertyMetadata(Class cls) {
    NSMutableArray *result = [NSMutableArray array];
    for (Class owner = cls; owner && owner != NSObject.class && result.count < kHFAMaxRuntimeMetadata;
         owner = class_getSuperclass(owner)) {
        unsigned count = 0; objc_property_t *properties = class_copyPropertyList(owner, &count);
        count = MIN(count, (unsigned)(kHFAMaxRuntimeMetadata - result.count));
        for (unsigned i = 0; properties && i < count; ++i) {
            const char *name = property_getName(properties[i]);
            const char *attributes = property_getAttributes(properties[i]);
            if (!name) continue;
            [result addObject:@{ @"declaringClass": NSStringFromClass(owner) ?: @"?",
                                 @"name": [NSString stringWithUTF8String:name],
                                 @"attributes": attributes ? [NSString stringWithUTF8String:attributes] : @"?" }];
        }
        free(properties);
    }
    return result;
}

static NSDictionary *HFAJailpatchRuntimeOwnerEvidence(NSString *menuImage) {
    Class cls = objc_getClass("C4M0Manager");
    if (!cls) return @{ @"class": @"C4M0Manager", @"status": @"class-not-loaded",
                        @"invoked": @NO, @"written": @NO, @"hookInstalled": @NO };
    const char *classPathRaw = class_getImageName(cls);
    NSString *classPath = classPathRaw ? [NSString stringWithUTF8String:classPathRaw] : @"?";
    NSMutableArray *inventory = [NSMutableArray array], *candidates = [NSMutableArray array];
    NSMutableArray *exactMethods = [NSMutableArray array];
    NSUInteger depth = 0;
    for (Class owner = cls; owner && owner != NSObject.class && inventory.count < kHFAMaxRuntimeMethods;
         owner = class_getSuperclass(owner), ++depth) {
        HFAAppendJailpatchMethods(owner, @"instance", depth, menuImage,
                                  inventory, candidates, exactMethods);
        Class meta = object_getClass((id)owner);
        HFAAppendJailpatchMethods(meta, @"class", depth, menuImage,
                                  inventory, candidates, exactMethods);
    }
    [candidates sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger lhs = [a[@"candidateScore"] integerValue], rhs = [b[@"candidateScore"] integerValue];
        if (lhs != rhs) return lhs > rhs ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"selector"] compare:b[@"selector"]];
    }];
    NSString *status = exactMethods.count ? @"located-exact-methods" :
                       (inventory.count ? @"inventoried-no-exact-methods" : @"method-inventory-empty");
    return @{ @"class": @"C4M0Manager", @"status": status,
              @"classImage": classPath.lastPathComponent ?: @"?", @"classPath": classPath,
              @"instanceSize": @(class_getInstanceSize(cls)),
              @"methods": exactMethods, @"methodInventory": inventory,
              @"candidateMethods": candidates, @"ivars": HFAJailpatchIvarMetadata(cls),
              @"properties": HFAJailpatchPropertyMetadata(cls),
              @"inventoryTruncated": @(inventory.count >= kHFAMaxRuntimeMethods),
              @"invoked": @NO, @"written": @NO, @"hookInstalled": @NO,
              @"safetyPolicy": @"metadata-only-no-selector-invocation-no-hook-no-memory-write" };
}

static NSArray<NSDictionary *> *HFARawIvarEvidence(id object) {
    NSMutableArray<NSDictionary *> *result = [NSMutableArray array];
    if (!object) return result;
    Class cls = object_getClass(object);
    if (!cls || class_getInstanceSize(cls) > 1024) return result;
    for (NSUInteger depth = 0; cls && depth < 8 && cls != NSObject.class && result.count < 48;
         ++depth, cls = class_getSuperclass(cls)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cls, &count);
        count = MIN(count, 64U);
        for (unsigned i = 0; ivars && i < count && result.count < 48; ++i) {
            const char *rawName = ivar_getName(ivars[i]);
            const char *type = ivar_getTypeEncoding(ivars[i]);
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            if (!rawName || !type || offset < 0) continue;
            NSMutableDictionary *entry = [@{
                @"field": [NSString stringWithUTF8String:rawName],
                @"encoding": [NSString stringWithUTF8String:type],
                @"ivarOffset": [NSString stringWithFormat:@"0x%tx", offset]
            } mutableCopy];
            if (type[0] == '@') {
                id value = nil;
                @try { value = object_getIvar(object, ivars[i]); } @catch (...) {}
                entry[@"valueClass"] = value ? (NSStringFromClass(object_getClass(value)) ?: @"?") : @"nil";
                if ([value isKindOfClass:NSString.class]) {
                    NSString *text = value;
                    entry[@"value"] = text.length > 160 ? [text substringToIndex:160] : text;
                    entry[@"truncated"] = @(text.length > 160);
                } else if ([value isKindOfClass:NSNumber.class]) {
                    entry[@"value"] = value;
                } else if ([value isKindOfClass:NSData.class]) {
                    NSData *data = value;
                    NSUInteger length = MIN(data.length, 32U);
                    const uint8_t *bytes = static_cast<const uint8_t *>(data.bytes);
                    NSMutableString *hex = [NSMutableString stringWithCapacity:length * 2];
                    for (NSUInteger j = 0; j < length; ++j) [hex appendFormat:@"%02X", bytes[j]];
                    entry[@"hexPrefix"] = hex;
                    entry[@"byteLength"] = @(data.length);
                }
            } else if (type[0] == '^') {
                size_t instanceSize = class_getInstanceSize(object_getClass(object));
                if ((size_t)offset + sizeof(uintptr_t) <= instanceSize) {
                    uintptr_t pointer = 0;
                    const uint8_t *address =
                        reinterpret_cast<const uint8_t *>((__bridge const void *)object) + offset;
                    memcpy(&pointer, address, sizeof(pointer));
                    entry[@"pointerMemoryEvidence"] = HFAPointerMemoryEvidence(pointer);
                }
            } else {
                size_t width = 0;
                switch (type[0]) {
                    case 'B': case 'c': case 'C': width = 1; break;
                    case 's': case 'S': width = 2; break;
                    case 'i': case 'I': case 'l': case 'L': width = 4; break;
                    case 'q': case 'Q': width = 8; break;
                    default: break;
                }
                size_t instanceSize = class_getInstanceSize(object_getClass(object));
                if (width && (size_t)offset + width <= instanceSize) {
                    unsigned long long scalar = 0;
                    const uint8_t *address =
                        reinterpret_cast<const uint8_t *>((__bridge const void *)object) + offset;
                    memcpy(&scalar, address, width);
                    entry[@"rawUnsignedValue"] = @(scalar);
                    entry[@"byteWidth"] = @(width);
                }
            }
            [result addObject:entry];
        }
        free(ivars);
    }
    return result;
}

// Inspect only implementation metadata belonging to the selected menu image.
// In particular, never send `secret` to an arbitrary game-owned object here.
static NSArray<NSDictionary *> *HFAWrapperMethodEvidence(id wrapper, NSString *menuImage) {
    NSMutableArray<NSDictionary *> *result = [NSMutableArray array];
    if (!wrapper) return result;
    Class cls = object_getClass(wrapper);
    const char *classPathRaw = class_getImageName(cls);
    NSString *classPath = classPathRaw ? [NSString stringWithUTF8String:classPathRaw] : @"?";
    static const char *names[] = {"secret", "offset", "signature", "data", "intValue"};
    for (NSUInteger i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Method method = class_getInstanceMethod(cls, sel_registerName(names[i]));
        if (!method || method_getNumberOfArguments(method) != 2) continue;
        IMP imp = method_getImplementation(method);
        NSDictionary *location = HFAImplementationLocation(imp, menuImage);
        if (!location) continue;
        char *returnType = method_copyReturnType(method);
        NSMutableDictionary *entry = [location mutableCopy];
        entry[@"selector"] = [NSString stringWithUTF8String:names[i]];
        entry[@"wrapperClass"] = NSStringFromClass(cls) ?: @"?";
        entry[@"wrapperClassImage"] = classPath.lastPathComponent ?: @"?";
        entry[@"wrapperClassPath"] = classPath;
        entry[@"returnType"] = returnType ? [NSString stringWithUTF8String:returnType] : @"?";
        entry[@"invoked"] = @NO;
        [result addObject:entry];
        free(returnType);
    }
    return result;
}

static NSArray *HFAChildClassSummary(NSDictionary *dictionary) {
    NSMutableArray *result = [NSMutableArray array];
    for (id key in dictionary) {
        if (result.count >= 64) break;
        id value = dictionary[key];
        NSString *keyName = [key isKindOfClass:NSString.class] ? key : @"<non-string-key>";
        NSString *className = value ? NSStringFromClass(object_getClass(value)) : @"nil";
        [result addObject:@{ @"field": keyName, @"valueClass": className ?: @"?" }];
    }
    return result;
}

static NSDictionary *HFADictionaryFromObject(id object) {
    if (!object) return nil;
    if ([object isKindOfClass:NSDictionary.class]) return object;
    NSMutableDictionary *values = [NSMutableDictionary dictionary];
    Class cursor = object_getClass(object);
    for (NSUInteger depth = 0; cursor && depth < 12 && cursor != NSObject.class;
         ++depth, cursor = class_getSuperclass(cursor)) {
        unsigned count = 0; Ivar *ivars = class_copyIvarList(cursor, &count); count = MIN(count, 64U);
        for (unsigned i = 0; ivars && i < count; ++i) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            const char *name = ivar_getName(ivars[i]);
            if (!type || !name) continue;
            NSString *key = [NSString stringWithUTF8String:name];
            if (type[0] == '@') {
                id value = nil; @try { value = object_getIvar(object, ivars[i]); } @catch (...) {}
                if (value) values[key] = value;
                continue;
            }
            ptrdiff_t offset = ivar_getOffset(ivars[i]);
            size_t instanceSize = class_getInstanceSize(cursor);
            unsigned long long scalar = 0; size_t width = 0;
            switch (type[0]) {
                case 'B': case 'c': case 'C': width = 1; break;
                case 's': case 'S': width = 2; break;
                case 'i': case 'I': case 'l': case 'L': width = 4; break;
                case 'q': case 'Q': width = 8; break;
                default: break;
            }
            if (offset < 0 || !width || (size_t)offset + width > instanceSize) continue;
            const uint8_t *address = (const uint8_t *)(__bridge const void *)object + offset;
            memcpy(&scalar, address, width); values[key] = @(scalar);
        }
        free(ivars);
    }
    return values.count ? values : nil;
}

// Descriptor traversal does not invoke target-owned selectors or mutate target memory.
// A validated decrypt function may run only against a scratch copy of a bounded secret blob.
// An ivar offset describes the Objective-C object layout, never a game patch RVA.
static NSArray<NSDictionary *> *HFAReadOnlyDescriptorEvidence(NSDictionary *dictionary, NSString *candidateImage,
                                                               NSArray<NSDictionary *> *execImages) {
    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    if (!candidateImage.length) return records;
    for (id key in dictionary) {
        if (![key isKindOfClass:NSString.class] || records.count >= 16) continue;
        id array = dictionary[key];
        if (![array isKindOfClass:NSArray.class] || [array count] > kHFAMaxItems) continue;
        NSUInteger index = 0;
        for (id object in array) {
            if (records.count >= 16) break;
            if (!HFACandidateOwnedObject(object, candidateImage)) { ++index; continue; }
            Class cls = object_getClass(object);
            size_t size = class_getInstanceSize(cls);
            if (size > 1024) { ++index; continue; }
            BOOL descriptorFingerprint = size == 0xA0 && HFADescriptorSelectorFingerprint(cls) >= 8;
            NSDictionary *fields = HFADictionaryFromObject(object);
            NSMutableArray<NSDictionary *> *values = [NSMutableArray array];
            id offsetWrapper = nil, patchWrapper = nil;
            NSString *targetImage = nil;
            NSArray *names = [[fields.allKeys filteredArrayUsingPredicate:
                [NSPredicate predicateWithBlock:^BOOL(id value, __unused NSDictionary *bindings) {
                    return [value isKindOfClass:NSString.class];
                }]] sortedArrayUsingSelector:@selector(compare:)];
            for (NSString *field in names) {
                if (values.count >= 48) break;
                id value = fields[field];
                Ivar ivar = class_getInstanceVariable(cls, field.UTF8String);
                const char *encoding = ivar ? ivar_getTypeEncoding(ivar) : NULL;
                ptrdiff_t ivarOffset = ivar ? ivar_getOffset(ivar) : -1;
                NSMutableDictionary *entry = [@{
                    @"field": field,
                    @"valueClass": NSStringFromClass(object_getClass(value)) ?: @"?",
                    @"ivarOffset": ivarOffset >= 0 ? [NSString stringWithFormat:@"0x%tx", ivarOffset] : @"unknown",
                    @"encoding": encoding ? [NSString stringWithUTF8String:encoding] : @"unknown"
                } mutableCopy];
                if ([value isKindOfClass:NSString.class]) {
                    entry[@"value"] = [value length] > 160 ? [value substringToIndex:160] : value;
                    entry[@"truncated"] = @([value length] > 160);
                    NSString *matchedImage = HFAMatchingExecutableImage(value, execImages);
                    if (matchedImage.length) targetImage = matchedImage;
                } else if ([value isKindOfClass:NSNumber.class]) {
                    entry[@"value"] = value;
                } else if ([value isKindOfClass:NSData.class]) {
                    NSData *data = value;
                    NSUInteger count = MIN(data.length, 32U);
                    const uint8_t *bytes = static_cast<const uint8_t *>(data.bytes);
                    NSMutableString *hex = [NSMutableString stringWithCapacity:count * 2];
                    for (NSUInteger i = 0; i < count; ++i) [hex appendFormat:@"%02X", bytes[i]];
                    entry[@"hexPrefix"] = hex;
                    entry[@"byteLength"] = @(data.length);
                } else if (encoding && encoding[0] == '@' && value) {
                    const char *nestedPathRaw = class_getImageName(object_getClass(value));
                    NSString *nestedPath = nestedPathRaw ? [NSString stringWithUTF8String:nestedPathRaw] : @"?";
                    if (!HFAPathIsSystemImage(nestedPath)) {
                        entry[@"methodEvidence"] = HFAWrapperMethodEvidence(value, candidateImage);
                        entry[@"rawIvarEvidence"] = HFARawIvarEvidence(value);
                        entry[@"valueObjectToken"] = HFAObjectToken(value);
                        entry[@"decodedValueStatus"] = @"not-observed";
                        BOOL secretMethod = class_getInstanceMethod(object_getClass(value), sel_registerName("secret")) != NULL;
                        NSString *typeName = encoding ? [NSString stringWithUTF8String:encoding] : @"";
                        if (secretMethod && ([typeName containsString:@"IGSecretInt"] ||
                                             (descriptorFingerprint && ivarOffset == 0x48)))
                            offsetWrapper = value;
                        if (secretMethod && ([typeName containsString:@"IGSecretData"] ||
                                             (descriptorFingerprint && ivarOffset == 0x40)))
                            patchWrapper = value;
                    }
                }
                [values addObject:entry];
            }
            NSMutableDictionary *record = [@{ @"arrayField": key, @"index": @(index),
                                               @"class": NSStringFromClass(cls) ?: @"?",
                                               @"objectToken": HFAObjectToken(object),
                                               @"instanceSize": @(size),
                                               @"descriptorSelectorFingerprint": @(HFADescriptorSelectorFingerprint(cls)),
                                               @"offsetSemantics": @"objc-instance-ivar-only",
                                               @"fields": values } mutableCopy];
            if (offsetWrapper || patchWrapper) {
                NSDictionary *offsetDecode = HFADecodeSecretWrapper(offsetWrapper, @"offset");
                NSDictionary *patchDecode = HFADecodeSecretWrapper(patchWrapper, @"patchData");
                NSDictionary *targetResolution = nil;
                if (!targetImage.length) {
                    targetResolution = HFAExecutableImageResolutionForDecoded(offsetDecode, patchDecode,
                                                                               execImages);
                    if ([targetResolution[@"status"] isEqualToString:@"unique"])
                        targetImage = targetResolution[@"targetImage"];
                } else {
                    targetResolution = @{ @"status": @"declared",
                                          @"source": @"descriptor-string",
                                          @"targetImage": targetImage };
                }
                record[@"decodeEvidence"] = @{ @"offset": offsetDecode, @"patchData": patchDecode,
                                                 @"targetImage": targetImage ?: @"unresolved",
                                                 @"targetResolution": targetResolution ?: @{} };
                id featureNameValue = HFAValueForAliases(dictionary, @[@"label", @"title", @"name"]);
                NSString *featureName = [featureNameValue isKindOfClass:NSString.class] ? featureNameValue : @"?";
                NSDictionary *canonical = HFACanonicalPatchFromDecoded(featureName, targetImage,
                                                                        offsetDecode, patchDecode, execImages);
                if (canonical) record[@"canonicalPatch"] = canonical;
            }
            [records addObject:record];
            ++index;
        }
    }
    return records;
}

static NSString *HFALabelForControl(UIControl *control) {
    if ([control isKindOfClass:UIButton.class]) {
        NSString *title = [(UIButton *)control titleForState:UIControlStateNormal];
        if (title.length) return title;
    }
    if (control.accessibilityLabel.length) return control.accessibilityLabel;
    UIView *scope = control;
    for (NSUInteger depth = 0; scope && depth < 3; ++depth, scope = scope.superview) {
        NSMutableArray<UIView *> *queue = [NSMutableArray arrayWithObject:scope];
        for (NSUInteger i = 0; i < queue.count && i < 32; ++i) {
            UIView *view = queue[i];
            if ([view isKindOfClass:UILabel.class] && [(UILabel *)view text].length)
                return [(UILabel *)view text];
            for (UIView *child in view.subviews) if (queue.count < 32) [queue addObject:child];
        }
    }
    return nil;
}

static NSArray *HFACollectRoots(NSTimeInterval deadline) {
    NSMutableArray *roots = [NSMutableArray array], *queue = [NSMutableArray array];
    for (UIWindow *window in UIApplication.sharedApplication.windows) if (window) [queue addObject:window];
    NSHashTable *seen = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    while (queue.count && roots.count < kHFAMaxViews && [NSDate.date timeIntervalSince1970] <= deadline) {
        UIView *view = queue.firstObject; [queue removeObjectAtIndex:0];
        if ([seen containsObject:view]) continue; [seen addObject:view]; [roots addObject:view];
        for (UIView *child in view.subviews) if (queue.count + roots.count < kHFAMaxViews) [queue addObject:child];
    }
    return roots;
}

static NSArray<NSDictionary *> *HFAExecutableImages(void) {
    NSMutableArray *images = [NSMutableArray array];
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    for (uint32_t i = 0, n = MIN(_dyld_image_count(), kHFAMaxLoadedImages); i < n; ++i) {
        const char *raw = _dyld_get_image_name(i);
        const struct mach_header_64 *h = reinterpret_cast<const struct mach_header_64 *>(_dyld_get_image_header(i));
        if (!raw || !h || h->magic != MH_MAGIC_64) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        NSString *standard = path.stringByStandardizingPath;
        if (![standard isEqualToString:NSBundle.mainBundle.executablePath.stringByStandardizingPath] &&
            ![standard hasPrefix:[bundle stringByAppendingString:@"/"]]) continue;
        if (h->ncmds > 4096 || h->sizeofcmds > 4U * 1024U * 1024U) continue;
        const uint8_t *p = (const uint8_t *)(h + 1), *end = p + h->sizeofcmds;
        NSString *uuid = @"unknown";
        const uint8_t *uuidCursor = p;
        for (uint32_t c = 0; c < h->ncmds && uuidCursor + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(uuidCursor);
            if (lc->cmdsize < sizeof(*lc) || uuidCursor + lc->cmdsize > end) break;
            if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                const uint8_t *u = reinterpret_cast<const struct uuid_command *>(lc)->uuid;
                uuid = [NSString stringWithFormat:
                    @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];
                break;
            }
            uuidCursor += lc->cmdsize;
        }
        for (uint32_t c = 0; c < h->ncmds && p + sizeof(struct load_command) <= end; ++c) {
            const struct load_command *lc = reinterpret_cast<const struct load_command *>(p);
            if (lc->cmdsize < sizeof(*lc) || p + lc->cmdsize > end) break;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = reinterpret_cast<const struct segment_command_64 *>(p);
                if ((seg->initprot & VM_PROT_EXECUTE) && (seg->initprot & VM_PROT_READ) && seg->vmsize)
                    [images addObject:@{ @"image": path.lastPathComponent, @"path": path,
                                         @"uuid": uuid, @"filetype": @(h->filetype),
                                         @"isMain": @(h->filetype == MH_EXECUTE),
                                         @"vmaddr": @(seg->vmaddr), @"vmsize": @(seg->vmsize),
                                         @"slide": @(_dyld_get_image_vmaddr_slide(i)) }];
            }
            p += lc->cmdsize;
        }
    }
    return images;
}

static NSDictionary *HFAValidatedFeature(NSDictionary *source, NSString *fallbackLabel,
                                         NSArray<NSDictionary *> *execImages, NSString **reason) {
    id labelValue = HFAValueForAliases(source, @[@"label",@"title",@"name",@"identifier",@"displayname"]);
    NSString *label = [labelValue isKindOfClass:NSString.class] ? labelValue : fallbackLabel;
    NSNumber *offset = HFAOffsetValue(HFAValueForAliases(source, @[@"offset",@"patchoffset",@"targetoffset",@"address",@"rva"]));
    id patchValue = HFAValueForAliases(source, @[@"enabled",@"enabledbytes",@"patch",@"patchbytes",@"bytes",@"instruction"]);
    NSData *patch = HFABytesValue(patchValue);
    id declaredImageValue = HFAValueForAliases(source, @[@"image",@"targetimage",@"module",@"binary"]);
    NSString *declaredImage = [declaredImageValue isKindOfClass:NSString.class] ?
        [(NSString *)declaredImageValue lastPathComponent] : nil;
    if (!label.length) { if (reason) *reason = @"missing-label"; return nil; }
    if (!offset) { if (reason) *reason = @"missing-offset"; return nil; }
    if (!patch.length || patch.length > 256) { if (reason) *reason = @"missing-or-invalid-patch"; return nil; }
    if (!declaredImage.length) { if (reason) *reason = @"target-image-missing"; return nil; }
    id originalValue = HFAValueForAliases(source, @[@"original",@"originalbytes",@"disabled",@"disabledbytes"]);
    NSData *original = HFABytesValue(originalValue);
    if (original.length != patch.length) { if (reason) *reason = @"original-bytes-missing-or-length-mismatch"; return nil; }
    NSMutableArray *matches = [NSMutableArray array]; uint64_t rva = offset.unsignedLongLongValue;
    for (NSDictionary *image in execImages) {
        BOOL declaredMain = [declaredImage isEqualToString:@"main"];
        if (declaredMain && ![image[@"isMain"] boolValue]) continue;
        if (!declaredMain && declaredImage.length && ![declaredImage isEqualToString:image[@"image"]] &&
            ![declaredImage.stringByDeletingPathExtension
              isEqualToString:[image[@"image"] stringByDeletingPathExtension]]) continue;
        uint64_t vmaddr = [image[@"vmaddr"] unsignedLongLongValue], size = [image[@"vmsize"] unsignedLongLongValue];
        if (rva >= vmaddr && rva - vmaddr <= size && patch.length <= size - (rva - vmaddr))
            [matches addObject:image];
    }
    if (matches.count != 1) { if (reason) *reason = matches.count ? @"ambiguous-target-image" : @"offset-outside-executable-range"; return nil; }
    NSDictionary *image = matches.firstObject;
    uintptr_t address = (uintptr_t)(rva + [image[@"slide"] longLongValue]);
    NSData *current = [NSData dataWithBytes:(const void *)address length:patch.length];
    if (![current isEqualToData:original]) { if (reason) *reason = @"original-bytes-do-not-match-live-image"; return nil; }
    NSString *(^hex)(NSData *) = ^NSString *(NSData *data) {
        const uint8_t *b = static_cast<const uint8_t *>(data.bytes);
        NSMutableString *s = [NSMutableString stringWithCapacity:data.length * 2];
        for (NSUInteger i=0;i<data.length;i++) [s appendFormat:@"%02X",b[i]]; return s;
    };
    NSMutableDictionary *result = [@{ @"name": label, @"offset": [NSString stringWithFormat:@"0x%llX", rva],
              @"patch": hex(patch), @"currentBytes": hex(current), @"targetImage": image[@"image"],
              @"targetUUID": image[@"uuid"] ?: @"unknown",
              @"offsetSemantics": @"preferred-mach-o-vmaddr",
              @"canonicalEligible": @YES, @"confidence": @"byte-validated",
              @"evidence": @[@"same-descriptor", @"executable-range", @"live-original-bytes-match"] } mutableCopy];
    result[@"original"] = hex(original);
    return result;
}

NSDictionary *HFAMapCaptureFeatureSeeds(NSDictionary *candidate, NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events) {
    HFAResolveEvent(events, @"snapshot-start", @{ @"image": candidate[@"image"] ?: @"" });
    NSArray *views = HFACollectRoots(deadline);
    NSHashTable *seenTargets = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *seeds = [NSMutableArray array];
    NSMutableArray *actionSeeds = [NSMutableArray array];
    NSMutableSet *actionKeys = [NSMutableSet set];
    for (UIView *view in views) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        if (![view isKindOfClass:UIControl.class]) continue;
        UIControl *control = (UIControl *)view;
        NSString *label = HFALabelForControl(control);
        for (id target in control.allTargets) {
            const char *ownerPath = class_getImageName(object_getClass(target));
            NSString *ownerImage = ownerPath ? [NSString stringWithUTF8String:ownerPath].lastPathComponent : @"";
            if (![ownerImage isEqualToString:candidate[@"image"]]) continue;
            if (![seenTargets containsObject:target] && seenTargets.count < kHFAMaxTargets) {
                [seenTargets addObject:target];
                [seeds addObject:@{ @"value": target, @"label": label ?: @"",
                                    @"class": NSStringFromClass(object_getClass(target)) ?: @"?" }];
                HFADiagnosticsLog(@"ui-target", @"captured", @{
                    @"label": label ?: @"", @"class": NSStringFromClass(object_getClass(target)) ?: @"?",
                    @"image": ownerImage
                });
            }
            NSArray *eventSets = @[
                @{ @"event": @"touch-up-inside", @"actions":
                       [control actionsForTarget:target forControlEvent:UIControlEventTouchUpInside] ?: @[] },
                @{ @"event": @"value-changed", @"actions":
                       [control actionsForTarget:target forControlEvent:UIControlEventValueChanged] ?: @[] }
            ];
            for (NSDictionary *eventSet in eventSets) {
                for (NSString *action in eventSet[@"actions"]) {
                    if (actionSeeds.count >= kHFAMaxTargets) break;
                    NSString *key = [NSString stringWithFormat:@"%p:%@:%@:%@", target, action,
                                     eventSet[@"event"], label ?: @""];
                    if ([actionKeys containsObject:key]) continue;
                    [actionKeys addObject:key];
                    [actionSeeds addObject:@{ @"target": target, @"selector": action,
                                              @"event": eventSet[@"event"], @"label": label ?: @"",
                                              @"controlClass": NSStringFromClass(object_getClass(control)) ?: @"?",
                                              @"controlToken": [NSString stringWithFormat:@"%p", control] }];
                }
            }
        }
    }
    NSString *status = NSDate.date.timeIntervalSince1970 > deadline ? @"timeout" : @"complete";
    NSDictionary *metrics = @{ @"views": @(views.count), @"targets": @(seenTargets.count),
                                @"seedCount": @(seeds.count), @"actionSeedCount": @(actionSeeds.count),
                                @"budgetMs": @350 };
    HFAResolveEvent(events, [@"snapshot-" stringByAppendingString:status], metrics);
    return @{ @"seeds": seeds, @"actionSeeds": actionSeeds,
              @"metrics": metrics, @"status": status };
}

NSDictionary *HFAMapResolveFeatureSeeds(NSDictionary *candidate, NSDictionary *snapshot,
                                        NSTimeInterval deadline,
                                        NSMutableArray<NSDictionary *> *events) {
    HFAResolveEvent(events, @"start", @{ @"image": candidate[@"image"] ?: @"" });
    NSArray *execImages = HFAExecutableImages();
    HFADiagnosticsLog(@"target-images", @"observed", @{
        @"images": [execImages subarrayWithRange:NSMakeRange(0, MIN(execImages.count, 64U))],
        @"totalExecutableSegments": @(execImages.count)
    });
    NSDictionary *runtimeEvidence = @{};
    if ([candidate[@"family"] isEqualToString:@"jailpatch"]) {
        runtimeEvidence = HFAJailpatchRuntimeOwnerEvidence(candidate[@"image"] ?: @"");
        HFADiagnosticsLog(@"jailpatch-runtime-owner", runtimeEvidence[@"status"] ?: @"observed",
                          runtimeEvidence);
    }
    NSMutableArray *features = [NSMutableArray array], *unresolved = [NSMutableArray array], *registry = [NSMutableArray array];
    NSMutableArray *runtimeRecords = [NSMutableArray array], *blockProvenance = [NSMutableArray array];
    NSMutableArray *actionProvenance = [NSMutableArray array];
    NSMutableSet *featureKeys = [NSMutableSet set], *unresolvedKeys = [NSMutableSet set], *registryKeys = [NSMutableSet set];
    NSMutableSet *blockKeys = [NSMutableSet set];
    for (NSDictionary *seed in snapshot[@"actionSeeds"] ?: @[]) {
        if ([NSDate.date timeIntervalSince1970] > deadline || actionProvenance.count >= kHFAMaxTargets) break;
        id target = seed[@"target"];
        NSString *selectorName = seed[@"selector"];
        SEL selector = selectorName.length ? NSSelectorFromString(selectorName) : NULL;
        Method method = target && selector ? class_getInstanceMethod(object_getClass(target), selector) : NULL;
        IMP implementation = method ? method_getImplementation(method) : NULL;
        NSMutableDictionary *evidence = [@{
            @"status": implementation ? @"action-entry-resolved" : @"action-entry-unresolved",
            @"labelContext": seed[@"label"] ?: @"", @"selector": selectorName ?: @"?",
            @"registeredControlEvent": seed[@"event"] ?: @"?",
            @"controlClass": seed[@"controlClass"] ?: @"?",
            @"controlToken": seed[@"controlToken"] ?: @"?",
            @"targetClass": target ? (NSStringFromClass(object_getClass(target)) ?: @"?") : @"?",
            @"targetToken": HFAObjectToken(target),
            @"association": @"exact-control-target-action",
            @"analysisOnly": @YES, @"canonicalEligible": @NO,
            @"selectorInvokedByAnalyzer": @NO, @"impReplaced": @NO,
            @"hookInstalled": @NO, @"memoryWritten": @NO
        } mutableCopy];
        const char *types = method ? method_getTypeEncoding(method) : NULL;
        if (types) evidence[@"typeEncoding"] = [NSString stringWithUTF8String:types];
        NSDictionary *location = implementation ? HFAImplementationLocation(implementation,
                                                                              candidate[@"image"] ?: @"") : nil;
        if (location) {
            [evidence addEntriesFromDictionary:location];
            evidence[@"status"] = [location[@"selectedMenuImage"] boolValue] ?
                @"selected-menu-action-entry" : @"external-action-entry";
            if ([location[@"selectedMenuImage"] boolValue]) {
                NSDictionary *semantic = HFAClassifyBlockInvoke((uintptr_t)implementation,
                                                                  candidate[@"image"] ?: @"", YES);
                evidence[@"semanticEvidence"] = semantic;
                NSString *semanticClass = semantic[@"semanticClass"] ?: @"unresolved-block-semantics";
                if ([semanticClass isEqualToString:@"nonsemantic-logging-block"])
                    evidence[@"actionSinkClass"] = @"nonsemantic-ui-or-initialization";
                else if ([semanticClass isEqualToString:@"runtime-action-target-resolved"])
                    evidence[@"actionSinkClass"] = @"runtime-target-resolved";
                else if ([semanticClass isEqualToString:@"runtime-action-dispatch-chain"])
                    evidence[@"actionSinkClass"] = @"deferred-runtime-action";
                else
                    evidence[@"actionSinkClass"] = @"unresolved-action-sink";
            } else {
                evidence[@"actionSinkClass"] = @"external-action-entry";
            }
        }
        [actionProvenance addObject:evidence];
        HFADiagnosticsLog(@"action-entry", evidence[@"status"] ?: @"observed", evidence);
        [evidence release];
    }
    NSHashTable *seenContainers = [NSHashTable hashTableWithOptions:NSPointerFunctionsObjectPointerPersonality];
    NSMutableArray *containers = [NSMutableArray arrayWithArray:snapshot[@"seeds"] ?: @[]];
    for (NSUInteger cursor = 0; cursor < containers.count && cursor < kHFAMaxContainers; ++cursor) {
        if ([NSDate.date timeIntervalSince1970] > deadline) break;
        id object = containers[cursor][@"value"]; NSString *label = containers[cursor][@"label"];
        if ([seenContainers containsObject:object]) continue; [seenContainers addObject:object];
        NSDictionary *dictionary = HFADictionaryFromObject(object); if (!dictionary) continue;
        NSString *className = NSStringFromClass(object_getClass(object)) ?: @"?";
        NSArray *blockFields = [[dictionary.allKeys filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(id key, __unused NSDictionary *bindings) {
                return [key isKindOfClass:NSString.class] && HFAIsBlockObject(dictionary[key]);
            }]] sortedArrayUsingSelector:@selector(compare:)];
        for (NSString *blockField in blockFields) {
            if (blockProvenance.count >= 32) break;
            NSDictionary *evidence = HFAReadOnlyBlockProvenance(dictionary[blockField], object,
                                                                 blockField, label,
                                                                 candidate[@"image"] ?: @"");
            if (!evidence) continue;
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@", evidence[@"ownerToken"],
                             evidence[@"field"], evidence[@"implementationOffsetFromLoadBase"] ?: @"?"];
            if ([blockKeys containsObject:key]) continue;
            [blockKeys addObject:key];
            [blockProvenance addObject:evidence];
            HFADiagnosticsLog(@"missing-offset-block", evidence[@"status"] ?: @"observed", evidence);
        }
        NSDictionary *registryRecord = HFARegistryRecord(dictionary, candidate[@"family"],
                                                         className, candidate[@"image"], execImages);
        BOOL descriptorCanonical = NO;
        for (NSDictionary *descriptor in registryRecord[@"descriptorEvidence"] ?: @[]) {
            NSDictionary *canonical = descriptor[@"canonicalPatch"];
            if (!canonical) continue;
            descriptorCanonical = YES;
            NSMutableDictionary *enriched = [canonical mutableCopy];
            enriched[@"identifier"] = registryRecord[@"identifier"] ?: @"?";
            enriched[@"sourceFamily"] = candidate[@"family"] ?: @"unknown";
            enriched[@"descriptorClass"] = descriptor[@"class"] ?: @"?";
            NSString *featureKey = [NSString stringWithFormat:@"%@:%@:%@:%@",
                                    enriched[@"identifier"], enriched[@"targetImage"],
                                    enriched[@"offset"], enriched[@"patch"]];
            if (![featureKeys containsObject:featureKey]) {
                [featureKeys addObject:featureKey]; [features addObject:enriched];
                HFADiagnosticsLog(@"feature", @"accepted-decoded-descriptor", enriched);
            }
        }
        if (registryRecord && registry.count < kHFAMaxItems) {
            NSString *registryKey = [NSString stringWithFormat:@"%@:%@", registryRecord[@"identifier"], registryRecord[@"name"]];
            if (![registryKeys containsObject:registryKey]) {
                [registryKeys addObject:registryKey]; [registry addObject:registryRecord];
                if ([registryRecord[@"analysisOnly"] boolValue] && runtimeRecords.count < kHFAMaxItems) {
                    [runtimeRecords addObject:registryRecord];
                    HFADiagnosticsLog(@"runtime-feature", @"classified", registryRecord);
                }
                HFADiagnosticsLog(@"feature-registry", @"observed", registryRecord);
            }
        }
        NSString *featureLabel = registryRecord[@"name"] ?: label;
        NSArray *fieldNames = [[dictionary.allKeys filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(id key, __unused NSDictionary *bindings) {
                return [key isKindOfClass:NSString.class];
            }]] sortedArrayUsingSelector:@selector(compare:)];
        HFADiagnosticsLog(@"container", @"inspected", @{
            @"cursor": @(cursor), @"label": label ?: @"",
            @"class": NSStringFromClass(object_getClass(object)) ?: @"?",
            @"instanceSize": @(class_getInstanceSize(object_getClass(object))),
            @"descriptorSignal": @(HFADescriptorSignal(dictionary)),
            @"fieldNames": [fieldNames subarrayWithRange:NSMakeRange(0, MIN(fieldNames.count, 64U))],
            @"children": HFAChildClassSummary(dictionary)
        });
        NSString *reason = nil; NSDictionary *feature = HFAValidatedFeature(dictionary, featureLabel, execImages, &reason);
        if (feature) {
            NSMutableDictionary *enriched = [feature mutableCopy];
            enriched[@"descriptorClass"] = NSStringFromClass(object_getClass(object)) ?: @"?";
            enriched[@"descriptorInstanceSize"] = @(class_getInstanceSize(object_getClass(object)));
            enriched[@"sourceFamily"] = candidate[@"family"] ?: @"unknown";
            enriched[@"identifier"] = registryRecord[@"identifier"] ?: featureLabel ?: @"?";
            feature = enriched;
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@:%@", feature[@"identifier"],
                             feature[@"targetImage"], feature[@"offset"], feature[@"patch"]];
            if (![featureKeys containsObject:key]) {
                [featureKeys addObject:key]; [features addObject:feature];
                HFADiagnosticsLog(@"feature", @"accepted", feature);
            }
        } else if (!descriptorCanonical && featureLabel.length && HFADescriptorSignal(dictionary)) {
            NSString *semanticReason = registryRecord[@"normalizedCanonicalReason"];
            if (semanticReason.length) reason = semanticReason;
            NSString *className = NSStringFromClass(object_getClass(object)) ?: @"?";
            NSString *key = [NSString stringWithFormat:@"%@:%@:%@", featureLabel, reason ?: @"no-static-descriptor", className];
            if (![unresolvedKeys containsObject:key]) { [unresolvedKeys addObject:key];
                NSDictionary *record = @{ @"name": featureLabel,
                                           @"identifier": registryRecord[@"identifier"] ?: @"",
                                           @"reason": reason ?: @"no-static-descriptor",
                                           @"canonicalEligible": @NO, @"class": className,
                                           @"instanceSize": @(class_getInstanceSize(object_getClass(object))),
                                           @"fieldNames": [fieldNames subarrayWithRange:
                                               NSMakeRange(0, MIN(fieldNames.count, 64U))],
                                           @"sourceFamily": candidate[@"family"] ?: @"unknown" };
                [unresolved addObject:record];
                HFADiagnosticsLog(@"feature", @"rejected", record);
            }
        }
        for (id value in dictionary.allValues) {
            if (containers.count >= kHFAMaxContainers) break;
            if ([value isKindOfClass:NSArray.class]) {
                for (id item in [(NSArray *)value subarrayWithRange:NSMakeRange(0, MIN([value count], kHFAMaxItems))])
                    if ([item isKindOfClass:NSDictionary.class] || [item isKindOfClass:NSArray.class] ||
                        HFACandidateOwnedObject(item, candidate[@"image"]))
                        [containers addObject:@{ @"value": item, @"label": featureLabel ?: @"" }];
            } else if ([value isKindOfClass:NSDictionary.class]) {
                [containers addObject:@{ @"value": value, @"label": featureLabel ?: @"" }];
            } else if (![value isKindOfClass:NSString.class] && ![value isKindOfClass:NSNumber.class] &&
                       ![value isKindOfClass:NSData.class]) {
                if (HFACandidateOwnedObject(value, candidate[@"image"]))
                    [containers addObject:@{ @"value": value, @"label": featureLabel ?: @"" }];
            }
        }
    }
    NSDictionary *hookSemantic = HFAMapResolveHookSemanticFeatures(candidate, registry, execImages,
                                                                    deadline);
    NSArray *hookFeatures = hookSemantic[@"features"] ?: @[];
    NSMutableSet<NSString *> *hookResolved = [NSMutableSet setWithArray:
                                               hookSemantic[@"resolvedIdentifiers"] ?: @[]];
    for (NSDictionary *hookFeature in hookFeatures) {
        NSString *key = [NSString stringWithFormat:@"%@:%@:%@:%@", hookFeature[@"identifier"],
                         hookFeature[@"targetImage"], hookFeature[@"offset"], hookFeature[@"patch"]];
        if ([featureKeys containsObject:key]) continue;
        [featureKeys addObject:key];
        [features addObject:hookFeature];
        HFADiagnosticsLog(@"feature", @"accepted-menu-hook-semantic", hookFeature);
    }
    NSMutableDictionary<NSString *, NSDictionary *> *hookResolutionByIdentifier = [NSMutableDictionary dictionary];
    for (NSDictionary *resolution in hookSemantic[@"resolutions"] ?: @[]) {
        NSString *identifier = resolution[@"identifier"];
        if (identifier.length) hookResolutionByIdentifier[identifier] = resolution;
    }
    NSMutableArray *remainingUnresolved = [NSMutableArray array];
    for (NSDictionary *record in unresolved) {
        NSString *identifier = record[@"identifier"];
        if (identifier.length && [hookResolved containsObject:identifier]) continue;
        NSDictionary *hookResolution = identifier.length ? hookResolutionByIdentifier[identifier] : nil;
        if (hookResolution) {
            NSMutableDictionary *enriched = [record mutableCopy];
            enriched[@"hookSemanticEvidence"] = hookResolution;
            NSString *hookStatus = hookResolution[@"status"];
            if (hookStatus.length && ![hookStatus isEqualToString:@"menu-field-mapping"])
                enriched[@"reason"] = [@"menu-hook-semantic-" stringByAppendingString:hookStatus];
            [remainingUnresolved addObject:enriched];
        } else {
            [remainingUnresolved addObject:record];
        }
    }
    unresolved = remainingUnresolved;
    HFADiagnosticsLog(@"menu-hook-semantic", hookSemantic[@"status"] ?: @"unknown", hookSemantic);

    NSString *status = [NSDate.date timeIntervalSince1970] > deadline ? @"timeout" : @"complete";
    NSDictionary *snapshotMetrics = snapshot[@"metrics"] ?: @{};
    HFAResolveEvent(events, status, @{ @"views": snapshotMetrics[@"views"] ?: @0,
                                      @"targets": snapshotMetrics[@"targets"] ?: @0,
                                      @"containers": @(MIN(containers.count,kHFAMaxContainers)),
                                      @"validated": @(features.count), @"unresolved": @(unresolved.count) });
    NSUInteger menuBlockInvokes = 0;
    for (NSDictionary *evidence in blockProvenance)
        if ([evidence[@"status"] isEqualToString:@"menu-invoke-resolved"]) ++menuBlockInvokes;
    NSDictionary *metrics = @{ @"views": snapshotMetrics[@"views"] ?: @0,
                                @"targets": snapshotMetrics[@"targets"] ?: @0,
                                @"containers": @(MIN(containers.count,kHFAMaxContainers)),
                                @"executableSegments": @(execImages.count),
                                @"validated": @(features.count), @"registry": @(registry.count),
                                @"runtimeRecords": @(runtimeRecords.count),
                                @"blockProvenanceRecords": @(blockProvenance.count),
                                @"actionProvenanceRecords": @(actionProvenance.count),
                                @"menuBlockInvokes": @(menuBlockInvokes),
                                @"unresolved": @(unresolved.count),
                                @"hookSemanticValidated": @(hookFeatures.count),
                                @"hookSemanticScannedBytes": hookSemantic[@"metrics"][@"scannedBytes"] ?: @0 };
    HFADiagnosticsLog(@"feature-resolution", status, metrics);
    return @{ @"status": status, @"features": features, @"registry": registry,
              @"runtimeRecords": runtimeRecords, @"unresolved": unresolved,
              @"runtimeEvidence": runtimeEvidence, @"hookSemanticEvidence": hookSemantic,
              @"blockProvenanceEvidence": blockProvenance,
              @"actionProvenanceEvidence": actionProvenance,
              @"metrics": metrics };
}
