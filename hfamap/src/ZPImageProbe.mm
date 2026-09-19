#import "ZPImageProbe.h"
#import "HFAMapDiagnostics.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#include <string.h>

static const uint32_t kZPMaxImages = 2048;
static const uint64_t kZPMaxScanBytes = 32ULL * 1024ULL * 1024ULL;

static NSString *ZPUUIDString(const uint8_t uuid[16]) {
    return [NSString stringWithFormat:@"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
            uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]];
}

static BOOL ZPAppOwnedPath(NSString *path) {
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    return bundle.length && [path.stringByStandardizingPath hasPrefix:[bundle stringByAppendingString:@"/"]];
}

static BOOL ZPExcludedImage(NSString *path) {
    NSString *base = path.lastPathComponent.lowercaseString;
    NSString *main = NSBundle.mainBundle.executablePath.lastPathComponent.lowercaseString;
    return [base isEqualToString:main] || [base isEqualToString:@"unityframework"] ||
           [base containsString:@"zpatchig"] || [base containsString:@"hfamapuniversal"] ||
           [base containsString:@"substrate"] || [base containsString:@"ellekit"];
}

static BOOL ZPContains(const uint8_t *bytes, size_t length, const char *token) {
    size_t n = token ? strlen(token) : 0;
    if (!bytes || !n || n > length) return NO;
    for (size_t i = 0; i + n <= length; ++i)
        if (bytes[i] == (uint8_t)token[0] && memcmp(bytes + i, token, n) == 0) return YES;
    return NO;
}

static unsigned ZPDescriptorSelectorCount(Class cls) {
    if (!cls) return 0;
    static const char *selectors[] = {
        "identifier", "setIdentifier:", "active", "setActive:",
        "offset", "setOffset:", "signature", "setSignature:",
        "range", "setRange:", "type", "architecture", "searchDirection"
    };
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(selectors)/sizeof(selectors[0]); ++i)
        if (class_getInstanceMethod(cls, sel_registerName(selectors[i]))) ++count;
    return count;
}

static NSString *ZPIvarTypeAtOffset(Class cls, ptrdiff_t wanted) {
    if (!cls) return @"";
    unsigned count = 0;
    Ivar *ivars = class_copyIvarList(cls, &count);
    NSString *result = @"";
    for (unsigned i = 0; ivars && i < count; ++i) {
        if (ivar_getOffset(ivars[i]) != wanted) continue;
        const char *type = ivar_getTypeEncoding(ivars[i]);
        if (type) result = [NSString stringWithUTF8String:type] ?: @"";
        break;
    }
    free(ivars);
    return result;
}

static BOOL ZPTypeContains(NSString *type, NSString *needle) {
    return type.length && needle.length && [type rangeOfString:needle].location != NSNotFound;
}

static BOOL ZPTypeIsErasedObject(NSString *type) {
    return [type isEqualToString:@"@\"?\""] || [type isEqualToString:@"@"];
}

static NSDictionary *ZPObjCFingerprint(NSString *path) {
    unsigned classCount = 0;
    const char **names = objc_copyClassNamesForImage(path.fileSystemRepresentation, &classCount);
    unsigned descriptorIndex = UINT_MAX;
    NSString *descriptorClass = @"";
    unsigned descriptorSelectors = 0;
    Class descriptorCls = Nil;
    const unsigned bounded = MIN(classCount, 512U);
    for (unsigned i = 0; names && i < bounded; ++i) {
        Class cls = objc_getClass(names[i]);
        if (!cls || class_getInstanceSize(cls) != 0xA0) continue;
        unsigned selectorCount = ZPDescriptorSelectorCount(cls);
        if (selectorCount > descriptorSelectors) {
            descriptorSelectors = selectorCount;
            descriptorIndex = i;
            descriptorClass = NSStringFromClass(cls) ?: @"";
            descriptorCls = cls;
        }
    }
    free(names);

    NSString *t40 = ZPIvarTypeAtOffset(descriptorCls, 0x40);
    NSString *t48 = ZPIvarTypeAtOffset(descriptorCls, 0x48);
    NSString *t58 = ZPIvarTypeAtOffset(descriptorCls, 0x58);
    NSString *t70 = ZPIvarTypeAtOffset(descriptorCls, 0x70);
    NSString *t98 = ZPIvarTypeAtOffset(descriptorCls, 0x98);

    BOOL legacyABI = ZPTypeContains(t48, @"IGSecretInt") &&
                     ZPTypeContains(t58, @"IGSecretString") &&
                     ZPTypeContains(t98, @"APSubpatchManager");
    BOOL legacyExtendedABI = legacyABI &&
                             ZPTypeContains(t40, @"IGSecretData") &&
                             ZPTypeContains(t70, @"APColorModifier");
    BOOL c4m0ErasedABI = ZPTypeIsErasedObject(t48) &&
                         ZPTypeIsErasedObject(t58) &&
                         ZPTypeIsErasedObject(t98);

    return @{
        @"objcClassCount": @(classCount),
        @"inspectedClassCount": @(bounded),
        @"descriptorClass": descriptorClass,
        @"descriptorClassIndex": descriptorIndex == UINT_MAX ? [NSNull null] : @(descriptorIndex),
        @"descriptorInstanceSize": descriptorIndex == UINT_MAX ? @0 : @0xA0,
        @"descriptorSelectorCount": @(descriptorSelectors),
        @"descriptorStrongMatch": @(descriptorIndex != UINT_MAX && descriptorSelectors >= 10),
        @"descriptorType40": t40 ?: @"",
        @"descriptorType48": t48 ?: @"",
        @"descriptorType58": t58 ?: @"",
        @"descriptorType70": t70 ?: @"",
        @"descriptorType98": t98 ?: @"",
        @"legacyABIMatch": @(legacyABI),
        @"legacyExtendedABIMatch": @(legacyExtendedABI),
        @"c4m0ErasedABIMatch": @(c4m0ErasedABI)
    };
}

static NSDictionary *ZPFingerprintImage(const struct mach_header_64 *mh, intptr_t slide,
                                        NSString *path, NSTimeInterval deadline) {
    if (!mh || mh->magic != MH_MAGIC_64 || mh->ncmds > 4096 || mh->sizeofcmds > 4U*1024U*1024U)
        return nil;
    const uint8_t *cursor = (const uint8_t *)(mh + 1);
    const uint8_t *end = cursor + mh->sizeofcmds;
    NSString *uuid = @"";
    int cryptid = -1;
    BOOL hasLegacy = NO, hasC4M0 = NO, hasMenu = NO;
    uint64_t scanned = 0;
    NSMutableArray *evidence = [NSMutableArray array];
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        if (cursor + sizeof(struct load_command) > end) return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return nil;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            uuid = ZPUUIDString(((const struct uuid_command *)cursor)->uuid);
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 && lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            cryptid = ((const struct encryption_info_command_64 *)cursor)->cryptid;
        } else if (lc->cmd == LC_ENCRYPTION_INFO && lc->cmdsize >= sizeof(struct encryption_info_command)) {
            cryptid = ((const struct encryption_info_command *)cursor)->cryptid;
        } else if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize) return nil;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t s = 0; s < seg->nsects && scanned < kZPMaxScanBytes; ++s) {
                if (strncmp(sects[s].sectname, "__cstring", 16) &&
                    strncmp(sects[s].sectname, "__objc_methname", 16) &&
                    strncmp(sects[s].sectname, "__const", 16)) continue;
                uint64_t size = MIN(sects[s].size, kZPMaxScanBytes - scanned);
                if (sects[s].addr < seg->vmaddr || size > seg->vmsize ||
                    sects[s].addr - seg->vmaddr > seg->vmsize - size) continue;
                const uint8_t *bytes = (const uint8_t *)(uintptr_t)(sects[s].addr + slide);
                scanned += size;
                if (!hasLegacy && (ZPContains(bytes,(size_t)size,"APPatchItem") ||
                                   ZPContains(bytes,(size_t)size,"APSubpatchManager") ||
                                   ZPContains(bytes,(size_t)size,"IGSecretInt") ||
                                   ZPContains(bytes,(size_t)size,"IGSecretString"))) {
                    hasLegacy = YES; [evidence addObject:@"legacy-ap-strings"];
                }
                if (!hasC4M0 && (ZPContains(bytes,(size_t)size,"C4M0Manager") ||
                                 ZPContains(bytes,(size_t)size,"Jailpatch runtime patch section is missing") ||
                                 ZPContains(bytes,(size_t)size,"JailpatchConfigValidator"))) {
                    hasC4M0 = YES; [evidence addObject:@"c4m0-runtime-strings"];
                }
                if (!hasMenu && ZPContains(bytes,(size_t)size,"setIdentifier:") &&
                    ZPContains(bytes,(size_t)size,"setOffset:") &&
                    ZPContains(bytes,(size_t)size,"setSignature:") &&
                    ZPContains(bytes,(size_t)size,"setRange:")) {
                    hasMenu = YES; [evidence addObject:@"descriptor-selectors"];
                }
            }
        }
        cursor += lc->cmdsize;
    }

    NSDictionary *objc = ZPObjCFingerprint(path);
    BOOL descriptor = [objc[@"descriptorStrongMatch"] boolValue];
    BOOL legacyABI = [objc[@"legacyABIMatch"] boolValue];
    BOOL legacyExtendedABI = [objc[@"legacyExtendedABIMatch"] boolValue];
    BOOL erasedABI = [objc[@"c4m0ErasedABIMatch"] boolValue];
    NSNumber *idxNumber = [objc[@"descriptorClassIndex"] isKindOfClass:[NSNumber class]] ? objc[@"descriptorClassIndex"] : nil;
    unsigned idx = idxNumber ? idxNumber.unsignedIntValue : UINT_MAX;

    NSString *family = @"unknown";
    NSString *familyConfidence = @"low";
    NSString *classificationBasis = @"insufficient-evidence";

    // Strong ABI evidence wins over runtime strings. Real device logs showed
    // Legacy images can also contain C4M0/iGameGod runtime markers.
    if (descriptor && legacyABI) {
        family = @"legacy-ap";
        familyConfidence = legacyExtendedABI ? @"high" : @"high";
        classificationBasis = legacyExtendedABI ? @"legacy-typed-abi-extended" : @"legacy-typed-abi";
        [evidence addObject:@"legacy-descriptor-abi"];
    } else if (descriptor && erasedABI && idx == 173U) {
        family = @"c4m0";
        familyConfidence = @"high";
        classificationBasis = @"c4m0-erased-abi-index173";
        [evidence addObject:@"c4m0-descriptor-abi"];
    } else if (descriptor && idx == 15U && hasLegacy) {
        family = @"legacy-ap";
        familyConfidence = @"medium";
        classificationBasis = @"legacy-index15-plus-marker";
    } else if (descriptor && idx == 173U && hasC4M0) {
        family = @"c4m0";
        familyConfidence = @"medium";
        classificationBasis = @"c4m0-index173-plus-marker";
    } else if (descriptor && hasLegacy && hasC4M0) {
        family = @"ambiguous";
        familyConfidence = @"low";
        classificationBasis = @"conflicting-runtime-strings-no-abi-tiebreak";
    } else if (descriptor && hasLegacy) {
        family = @"legacy-ap";
        familyConfidence = @"low";
        classificationBasis = @"legacy-marker-only";
    } else if (descriptor && hasC4M0) {
        family = @"c4m0";
        familyConfidence = @"low";
        classificationBasis = @"c4m0-marker-only";
    } else if (descriptor && hasMenu) {
        family = @"descriptor-family";
        familyConfidence = @"low";
        classificationBasis = @"descriptor-only";
    }

    unsigned score = 0;
    if (descriptor) score += 60;
    if (legacyABI || (erasedABI && idx == 173U)) score += 30;
    else if (hasLegacy || hasC4M0) score += 20;
    if ([objc[@"objcClassCount"] unsignedIntValue] == 199) score += 10;

    NSMutableDictionary *record = [@{
        @"path": path,
        @"image": path.lastPathComponent ?: @"?",
        @"family": family,
        @"familyConfidence": familyConfidence,
        @"classificationBasis": classificationBasis,
        @"score": @(MIN(score, 100U)),
        @"uuid": uuid,
        @"cryptid": @(cryptid),
        @"filetype": @(mh->filetype),
        @"cpuType": @(mh->cputype),
        @"slide": @((long long)slide),
        @"scannedBytes": @(scanned),
        @"hasLegacyMarkers": @(hasLegacy),
        @"hasC4M0RuntimeMarkers": @(hasC4M0),
        @"hasDescriptorSelectorStrings": @(hasMenu),
        @"evidence": evidence
    } mutableCopy];
    [record addEntriesFromDictionary:objc];
    return record;
}

NSArray<NSDictionary *> *ZPDiscoverMenuImages(NSTimeInterval deadline,
                                                NSMutableArray<NSDictionary *> *events) {
    NSMutableArray *out = [NSMutableArray array];
    uint32_t total = _dyld_image_count();
    uint32_t count = MIN(total, kZPMaxImages);
    unsigned appOwned = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (NSDate.date.timeIntervalSince1970 > deadline) break;
        const char *raw = _dyld_get_image_name(i);
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!raw || !h) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if (!ZPAppOwnedPath(path) || ZPExcludedImage(path)) continue;
        ++appOwned;
        NSDictionary *r = ZPFingerprintImage((const struct mach_header_64 *)h,
                                             _dyld_get_image_vmaddr_slide(i), path, deadline);
        if ([r[@"score"] unsignedIntValue] >= 60) {
            [out addObject:r];
            HFADiagnosticsLog(@"image-candidate", @"matched", r);
        }
    }
    [out sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger x=[a[@"score"] integerValue], y=[b[@"score"] integerValue];
        if (x != y) return x > y ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"image"] compare:b[@"image"]];
    }];
    [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"image-discovery",
                         @"status": out.count ? @"pass" : @"no-candidate", @"totalLoadedImages": @(total),
                         @"inspectedImages": @(count), @"appOwnedImages": @(appOwned),
                         @"candidateCount": @(out.count), @"hitImageLimit": @(total > kZPMaxImages) }];
    return out;
}
