#import "HFAMapSecretWrapperEvidenceResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger kHFASecretMaxWrappers = 128;
static const NSUInteger kHFASecretMaxPointerIvars = 32;
static const NSUInteger kHFASecretMaxBlobPrefix = 512;
static const NSUInteger kHFASecretMaxCodeBytes = 768;
static const NSUInteger kHFASecretMaxTextScanBytes = 32 * 1024 * 1024;

static NSString *HFASecretImageForClass(Class cls) {
    const char *p = cls ? class_getImageName(cls) : NULL;
    return p ? [NSString stringWithUTF8String:p].lastPathComponent : @"";
}

static NSString *HFASecretToken(id object) {
    return object ? [NSString stringWithFormat:@"%p", object] : @"";
}

static BOOL HFASecretRead(uint64_t address, void *buffer, size_t size) {
    if (!address || !buffer || !size) return NO;
    vm_size_t copied = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                                         (vm_address_t)address,
                                         (vm_size_t)size,
                                         (vm_address_t)buffer,
                                         &copied);
    return kr == KERN_SUCCESS && copied == (vm_size_t)size;
}

static NSString *HFASecretHex(const uint8_t *bytes, size_t size) {
    if (!bytes || !size) return @"";
    NSMutableString *s = [NSMutableString stringWithCapacity:size * 2];
    for (size_t i = 0; i < size; ++i) [s appendFormat:@"%02X", bytes[i]];
    return s;
}

static NSString *HFASecretReadHex(uint64_t address, size_t size) {
    if (!address || !size || size > kHFASecretMaxCodeBytes) return @"";
    uint8_t *buffer = (uint8_t *)calloc(1, size);
    if (!buffer) return @"";
    BOOL ok = HFASecretRead(address, buffer, size);
    NSString *hex = ok ? HFASecretHex(buffer, size) : @"";
    free(buffer);
    return hex;
}

static uintptr_t HFASecretParseToken(NSString *token) {
    if (![token isKindOfClass:NSString.class] || !token.length) return 0;
    const char *s = token.UTF8String;
    if (!s) return 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 0);
    return (end && end != s) ? (uintptr_t)value : 0;
}

static BOOL HFASecretTextRangeForBase(const void *base, uintptr_t *startOut, uintptr_t *endOut) {
    if (!base || !startOut || !endOut) return NO;
    uint32_t count = _dyld_image_count();
    const struct mach_header *header = NULL;
    intptr_t slide = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (_dyld_get_image_header(i) == base) {
            header = _dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }
    if (!header || header->magic != MH_MAGIC_64) return NO;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)header;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize || lc->cmdsize > 0x10000u) return NO;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; ++j) {
                if (strncmp(sec[j].segname, "__TEXT", 16) == 0 &&
                    strncmp(sec[j].sectname, "__text", 16) == 0) {
                    uintptr_t start = (uintptr_t)(sec[j].addr + (uint64_t)slide);
                    uintptr_t end = start + (uintptr_t)sec[j].size;
                    if (end <= start || sec[j].size > kHFASecretMaxTextScanBytes) return NO;
                    *startOut = start;
                    *endOut = end;
                    return YES;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return NO;
}

static BOOL HFASecretDecryptFingerprintAt(const uint8_t *bytes, size_t available) {
    if (!bytes || available < 0x44u) return NO;
    uint32_t a = 0, b = 0, c = 0;
    memcpy(&a, bytes, 4);
    memcpy(&b, bytes + 0x30u, 4);
    memcpy(&c, bytes + 0x40u, 4);
    return a == 0xD105C3FFu && b == 0xB9400408u && c == 0x53187D00u;
}

static NSDictionary *HFASecretDecryptEvidence(IMP getter) {
    if (!getter) return @{};
    Dl_info info = {0};
    if (!dladdr((const void *)getter, &info) || !info.dli_fbase || !info.dli_fname) return @{};
    uintptr_t base = (uintptr_t)info.dli_fbase;
    uintptr_t getterAddress = (uintptr_t)getter;
    NSMutableDictionary *result = [@{
        @"getterRuntimeVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)getterAddress],
        @"getterLoadBaseDelta": @(getterAddress - base),
        @"getterLoadBaseDeltaHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(getterAddress - base)],
        @"image": [NSString stringWithUTF8String:info.dli_fname].lastPathComponent ?: @"",
        @"getterCodeHex": HFASecretReadHex(getterAddress, 256),
        @"fingerprint": @"D105C3FF@+0,B9400408@+0x30,53187D00@+0x40",
        @"fingerprintVerifiedAlgorithm": @NO
    } mutableCopy];

    NSMutableArray *matches = [NSMutableArray array];
    uintptr_t legacy = getterAddress + 0xD00u;
    uint8_t legacyBytes[0x44] = {0};
    if (HFASecretRead(legacy, legacyBytes, sizeof(legacyBytes)) && HFASecretDecryptFingerprintAt(legacyBytes, sizeof(legacyBytes))) {
        [matches addObject:@{
            @"runtimeVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)legacy],
            @"loadBaseDelta": @(legacy - base),
            @"loadBaseDeltaHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(legacy - base)],
            @"source": @"historical-relative-fingerprint"
        }];
    }

    uintptr_t textStart = 0, textEnd = 0;
    if (HFASecretTextRangeForBase(info.dli_fbase, &textStart, &textEnd)) {
        size_t textSize = (size_t)(textEnd - textStart);
        uint8_t *text = (uint8_t *)malloc(textSize);
        if (text && HFASecretRead(textStart, text, textSize)) {
            for (size_t off = 0; off + 0x44u <= textSize; off += 4u) {
                if (!HFASecretDecryptFingerprintAt(text + off, textSize - off)) continue;
                uintptr_t address = textStart + off;
                BOOL duplicate = NO;
                for (NSDictionary *m in matches)
                    if ([m[@"runtimeVA"] isEqualToString:[NSString stringWithFormat:@"0x%llX", (unsigned long long)address]]) duplicate = YES;
                if (!duplicate && matches.count < 16) {
                    [matches addObject:@{
                        @"runtimeVA": [NSString stringWithFormat:@"0x%llX", (unsigned long long)address],
                        @"loadBaseDelta": @(address - base),
                        @"loadBaseDeltaHex": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(address - base)],
                        @"source": @"text-fingerprint"
                    }];
                }
            }
        }
        if (text) free(text);
        result[@"textStart"] = [NSString stringWithFormat:@"0x%llX", (unsigned long long)textStart];
        result[@"textSize"] = @(textSize);
    }

    result[@"candidateCount"] = @(matches.count);
    result[@"candidates"] = matches;
    if (matches.count == 1) {
        uintptr_t address = HFASecretParseToken(matches[0][@"runtimeVA"]);
        result[@"uniqueCandidate"] = @YES;
        result[@"candidateCodeHex"] = HFASecretReadHex(address, kHFASecretMaxCodeBytes);
        result[@"candidateCodeBytes"] = @(kHFASecretMaxCodeBytes);
    } else {
        result[@"uniqueCandidate"] = @NO;
    }
    return [result autorelease];
}

static NSDictionary *HFASecretBlobEvidenceForWrapper(id wrapper, NSString *menuImage) {
    if (!wrapper) return nil;
    Class cls = object_getClass(wrapper);
    if (![[HFASecretImageForClass(cls) lowercaseString] isEqualToString:[menuImage lowercaseString]]) return nil;

    NSMutableArray *pointerIvars = [NSMutableArray array];
    NSUInteger countBudget = kHFASecretMaxPointerIvars;
    for (Class cur = cls; cur && countBudget; cur = class_getSuperclass(cur)) {
        if (![[HFASecretImageForClass(cur) lowercaseString] isEqualToString:[menuImage lowercaseString]]) continue;
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(cur, &count);
        for (unsigned i = 0; ivars && i < count && countBudget; ++i) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type) continue;
            while (*type && strchr("rnNoORV", *type)) ++type;
            if (*type != '^') continue;
            --countBudget;
            ptrdiff_t off = ivar_getOffset(ivars[i]);
            uintptr_t pointer = 0;
            if (off < 0 || !HFASecretRead((uint64_t)(uintptr_t)wrapper + (uint64_t)off, &pointer, sizeof(pointer)) || !pointer) continue;
            uint32_t header[2] = {0};
            if (!HFASecretRead(pointer, header, sizeof(header))) continue;
            uint32_t length = header[0], flags = header[1];
            BOOL plausible = length > 0 && length <= 0x10000u;
            NSMutableDictionary *entry = [@{
                @"ownerClass": NSStringFromClass(cur) ?: @"",
                @"ivar": ivar_getName(ivars[i]) ? [NSString stringWithUTF8String:ivar_getName(ivars[i])] : @"",
                @"ivarOffset": @(off),
                @"ivarOffsetHex": [NSString stringWithFormat:@"0x%tx", off],
                @"typeEncoding": [NSString stringWithUTF8String:ivar_getTypeEncoding(ivars[i])] ?: @"",
                @"pointer": [NSString stringWithFormat:@"0x%llX", (unsigned long long)pointer],
                @"length": @(length), @"flags": @(flags),
                @"flagsHex": [NSString stringWithFormat:@"0x%08X", flags],
                @"keyFamilyCandidate": @((flags >> 24) & 0xFFu),
                @"plausibleSecretBlob": @(plausible),
                @"historicalBlobSizeCandidate": @((length & ~0xFu) + 0x28u),
                @"alignedBlobSizeCandidate": @(((length + 0xFu) & ~0xFu) + 0x28u)
            } mutableCopy];
            if (plausible) {
                size_t want = MIN((size_t)(((length + 0xFu) & ~0xFu) + 0x28u), (size_t)kHFASecretMaxBlobPrefix);
                if (want < 8) want = 8;
                uint8_t *bytes = (uint8_t *)calloc(1, want);
                if (bytes && HFASecretRead(pointer, bytes, want)) {
                    entry[@"blobPrefixBytes"] = @(want);
                    entry[@"blobPrefixHex"] = HFASecretHex(bytes, want);
                    if (want > 8) entry[@"cipherPrefixHex"] = HFASecretHex(bytes + 8, MIN(want - 8, (size_t)128));
                }
                if (bytes) free(bytes);
            }
            [pointerIvars addObject:entry];
            [entry release];
        }
        if (ivars) free(ivars);
    }

    SEL secretSel = sel_registerName("secret");
    Method secretMethod = class_getInstanceMethod(cls, secretSel);
    IMP getter = secretMethod ? method_getImplementation(secretMethod) : NULL;
    NSMutableDictionary *result = [@{
        @"wrapperToken": HFASecretToken(wrapper),
        @"wrapperClass": NSStringFromClass(cls) ?: @"",
        @"wrapperImage": HFASecretImageForClass(cls),
        @"pointerIvars": pointerIvars,
        @"pointerIvarCount": @(pointerIvars.count),
        @"secretSelectorPresent": @(secretMethod != NULL),
        @"secretSelectorInvoked": @NO
    } mutableCopy];
    if (secretMethod) {
        const char *types = method_getTypeEncoding(secretMethod);
        result[@"secretTypeEncoding"] = types ? [NSString stringWithUTF8String:types] : @"";
        result[@"decryptEvidence"] = HFASecretDecryptEvidence(getter);
    }
    return [result autorelease];
}

static NSDictionary *HFAResolveSecretWrapperEvidenceInternal(NSString *path, NSDictionary *directed, NSError **error) {
    NSString *menuImage = path.lastPathComponent ?: @"";
    if (!menuImage.length) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.secret-wrapper-evidence" code:1
                                             userInfo:@{NSLocalizedDescriptionKey:@"missing-menu-image"}];
        return nil;
    }

    NSArray *descriptors = directed[@"graph"][@"descriptorCandidates"] ?: @[];
    NSMutableArray *records = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    for (NSDictionary *descriptor in descriptors) {
        if (records.count >= kHFASecretMaxWrappers) break;
        NSArray *identifierStrings = descriptor[@"identifierStrings"] ?: @[];
        for (NSDictionary *field in descriptor[@"fields"] ?: @[]) {
            NSString *role = field[@"role"] ?: @"";
            if (!([role isEqualToString:@"address-field"] ||
                  [role isEqualToString:@"patch-field"] ||
                  [role isEqualToString:@"signature-field"])) continue;
            NSString *token = field[@"valueToken"] ?: @"";
            if (!token.length || [seen containsObject:token]) continue;
            uintptr_t raw = HFASecretParseToken(token);
            if (!raw) continue;
            id wrapper = (id)raw;
            NSDictionary *evidence = HFASecretBlobEvidenceForWrapper(wrapper, menuImage);
            if (!evidence) continue;
            [seen addObject:token];
            [records addObject:@{
                @"descriptorToken": descriptor[@"token"] ?: @"",
                @"descriptorClass": descriptor[@"class"] ?: @"",
                @"identifierStrings": identifierStrings,
                @"fieldName": field[@"name"] ?: @"",
                @"fieldRole": role,
                @"wrapper": evidence
            }];
        }
    }

    NSDictionary *result = @{
        @"schema": @"com.hfa.secret-wrapper-evidence/v1",
        @"buildVersion": @"2.5.11-dev",
        @"componentVersion": @"2.5.11-dev-secret-wrapper-static-evidence",
        @"policy": @"UNIVERSAL-SECRET-WRAPPER-READ-ONLY-NO-INTERNAL-CALLS",
        @"menuImage": menuImage, @"menuPath": path ?: @"",
        @"wrapperEvidenceCount": @(records.count),
        @"wrapperEvidence": records,
        @"upstream": @{
            @"directedFeatureCount": @([directed[@"featureResolutions"] count]),
            @"descriptorCandidateCount": @(descriptors.count)
        },
        @"safety": @{
            @"unknownSelectorInvoked": @NO,
            @"secretGetterInvoked": @NO,
            @"decryptRoutineInvoked": @NO,
            @"impReplaced": @NO,
            @"inlineHookInstalled": @NO,
            @"memoryWritten": @NO,
            @"gameStateWritten": @NO,
            @"boundedMemoryReadOnly": @YES
        }
    };
    HFADiagnosticsLog(@"secret-wrapper-evidence", @"complete", @{
        @"menuImage": menuImage,
        @"descriptorCandidateCount": @(descriptors.count),
        @"wrapperEvidenceCount": @(records.count)
    });
    return result;
}

NSDictionary *HFAMapResolveSecretWrapperEvidence(NSString *loadedMenuPath,
                                                   NSDictionary *directedDescriptors,
                                                   NSError **error) {
    return HFAResolveSecretWrapperEvidenceInternal(loadedMenuPath, directedDescriptors ?: @{}, error);
}

BOOL HFAMapPersistSecretWrapperEvidence(NSDictionary *result, NSError **error) {
    if (!result) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"SecretWrapperEvidence.json")];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}
