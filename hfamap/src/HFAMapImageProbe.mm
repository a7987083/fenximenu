#import "HFAMapImageProbe.h"
#import "HFAMapDiagnostics.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#include <string.h>

static const uint64_t kHFAMaxStringSection = 32ULL * 1024ULL * 1024ULL;
static const uint32_t kHFAMaxImages = 2048;

static NSDictionary *HFAObjectiveCFingerprint(NSString *path) {
    unsigned classCount = 0;
    const char **names = objc_copyClassNamesForImage(path.fileSystemRepresentation, &classCount);
    const unsigned boundedCount = MIN(classCount, 512U);
    unsigned descriptorCount = 0, bestSelectorCount = 0;
    NSArray<NSString *> *selectors = @[@"identifier", @"setIdentifier:", @"active", @"setActive:",
                                       @"offset", @"setOffset:", @"signature", @"setSignature:",
                                       @"range", @"setRange:"];
    NSMutableArray *descriptorClasses = [NSMutableArray array];
    for (unsigned i = 0; names && i < boundedCount; ++i) {
        Class cls = objc_getClass(names[i]);
        if (!cls || class_getInstanceSize(cls) != 160) continue;
        unsigned selectorCount = 0;
        for (NSString *name in selectors)
            if (class_getInstanceMethod(cls, NSSelectorFromString(name))) ++selectorCount;
        bestSelectorCount = MAX(bestSelectorCount, selectorCount);
        if (selectorCount >= 8) {
            ++descriptorCount;
            if (descriptorClasses.count < 8)
                [descriptorClasses addObject:NSStringFromClass(cls) ?: @"?"];
        }
    }
    free(names);
    unsigned structureScore = 0;
    if (classCount >= 180 && classCount <= 220) structureScore += 25;
    if (descriptorCount) structureScore += 50;
    return @{ @"objcClassCount": @(classCount), @"inspectedClassCount": @(boundedCount),
              @"descriptor160Count": @(descriptorCount), @"descriptorSelectorCount": @(bestSelectorCount),
              @"descriptorClasses": descriptorClasses, @"structureScore": @(structureScore) };
}

static BOOL HFAContains(const uint8_t *bytes, size_t length, const char *token) {
    const size_t n = strlen(token);
    if (!bytes || !n || n > length) return NO;
    for (size_t i = 0; i + n <= length; ++i)
        if (bytes[i] == (uint8_t)token[0] && memcmp(bytes + i, token, n) == 0) return YES;
    return NO;
}

static void HFAEvent(NSMutableArray *events, NSString *stage, NSString *status,
                     NSDictionary *details) {
    NSMutableDictionary *event = [@{ @"time": @([[NSDate date] timeIntervalSince1970]),
                                      @"stage": stage ?: @"?", @"status": status ?: @"?" }
                                    mutableCopy];
    if (details) [event addEntriesFromDictionary:details];
    [events addObject:event];
}

static BOOL HFAAppOwnedPath(NSString *path) {
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    return bundle.length && [path.stringByStandardizingPath hasPrefix:[bundle stringByAppendingString:@"/"]];
}

static BOOL HFAExcludedImage(NSString *path) {
    NSString *base = path.lastPathComponent.lowercaseString;
    return [base isEqualToString:NSBundle.mainBundle.executablePath.lastPathComponent.lowercaseString] ||
           [base isEqualToString:@"unityframework"] || [base containsString:@"hfamapuniversal"] ||
           [base containsString:@"substrate"] || [base containsString:@"ellekit"];
}

static NSDictionary *HFAFingerprintImage(const struct mach_header_64 *header,
                                         intptr_t slide, NSString *path,
                                         NSTimeInterval deadline) {
    if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 4096 ||
        header->sizeofcmds > 4U * 1024U * 1024U) return nil;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *commandEnd = cursor + header->sizeofcmds;
    unsigned ui = 0, legacy = 0, jail = 0;
    uint64_t scanned = 0;
    NSMutableArray *hits = [NSMutableArray array];
    struct Hit { const char *token; unsigned weight; unsigned group; };
    static const struct Hit rules[] = {
        {"addButtonWithTitle:",22,0},{"customSwitch",20,0},{"iOSGods",12,0},
        {"IGMenu 1.0",12,0},{"APMenuControl",18,0},
        {"APPatchItem",30,1},{"APSubpatchManager",24,1},{"IGSecretInt",16,1},
        {"IGSecretData",16,1},{"IGCodePatch",18,1},
        {"JailpatchConfigValidator",32,2},{"Jailpatch runtime table",28,2},
        {"OffsetInstruction",18,2},{"OffsetType",14,2},{".app-key-metadata-",24,2},
    };
    BOOL found[sizeof(rules) / sizeof(rules[0])] = {};
    for (uint32_t commandIndex = 0; commandIndex < header->ncmds; ++commandIndex) {
        if ([[NSDate date] timeIntervalSince1970] > deadline) break;
        if (cursor + sizeof(struct load_command) > commandEnd) return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > commandEnd) return nil;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize) return nil;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t i = 0; i < seg->nsects && scanned < kHFAMaxStringSection; ++i) {
                if (strncmp(sects[i].sectname, "__cstring", 16) &&
                    strncmp(sects[i].sectname, "__objc_methname", 16) &&
                    strncmp(sects[i].sectname, "__const", 16)) continue;
                uint64_t size = MIN(sects[i].size, kHFAMaxStringSection - scanned);
                if (sects[i].addr < seg->vmaddr || size > seg->vmsize ||
                    sects[i].addr - seg->vmaddr > seg->vmsize - size) continue;
                const uint8_t *bytes = (const uint8_t *)(uintptr_t)(sects[i].addr + slide);
                scanned += size;
                for (NSUInteger r = 0; r < sizeof(rules) / sizeof(rules[0]); ++r) {
                    if (found[r] || !HFAContains(bytes, (size_t)size, rules[r].token)) continue;
                    found[r] = YES;
                    if (rules[r].group == 0) ui += rules[r].weight;
                    else if (rules[r].group == 1) legacy += rules[r].weight;
                    else jail += rules[r].weight;
                    [hits addObject:[NSString stringWithUTF8String:rules[r].token]];
                }
            }
        }
        cursor += lc->cmdsize;
    }
    NSDictionary *objc = HFAObjectiveCFingerprint(path);
    unsigned structure = [objc[@"structureScore"] unsignedIntValue];
    NSString *family = @"unknown";
    if (ui >= 30 && legacy >= 30 && legacy > jail) family = @"legacy-ap";
    else if (ui >= 30 && jail >= 28) family = @"jailpatch";
    else if (ui >= 30 || (ui >= 20 && structure >= 50)) family = @"runtime-menu";
    unsigned score = [family isEqualToString:@"unknown"] ? 0U
        : MIN(100U, ui + MIN(MAX(legacy, jail), 35U) + MIN(structure, 25U));
    NSMutableDictionary *record = [@{ @"path": path, @"image": path.lastPathComponent ?: @"?", @"family": family,
              @"score": @(score), @"menuScore": @(ui), @"legacyScore": @(legacy),
              @"jailpatchScore": @(jail), @"evidence": hits, @"scannedBytes": @(scanned) } mutableCopy];
    [record addEntriesFromDictionary:objc];
    return record;
}

NSArray<NSDictionary *> *HFAMapDiscoverMenuImages(NSTimeInterval deadline,
                                                    NSMutableArray<NSDictionary *> *events) {
    NSMutableArray *found = [NSMutableArray array];
    NSUInteger appOwnedCount = 0, fingerprintedCount = 0;
    uint32_t totalCount = _dyld_image_count();
    uint32_t count = MIN(totalCount, kHFAMaxImages);
    HFAEvent(events, @"image-discovery", @"start",
             @{ @"totalLoadedImages": @(totalCount), @"inspectedImages": @(count) });
    for (uint32_t i = 0; i < count; ++i) {
        if ([[NSDate date] timeIntervalSince1970] > deadline) {
            HFAEvent(events, @"image-discovery", @"timeout", @{ @"processed": @(i) });
            break;
        }
        const char *raw = _dyld_get_image_name(i);
        const struct mach_header *rawHeader = _dyld_get_image_header(i);
        if (!raw || !rawHeader) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if (!HFAAppOwnedPath(path) || HFAExcludedImage(path)) continue;
        ++appOwnedCount;
        NSDictionary *record = HFAFingerprintImage((const struct mach_header_64 *)rawHeader,
                                                    _dyld_get_image_vmaddr_slide(i), path, deadline);
        if (record) ++fingerprintedCount;
        if ([record[@"score"] unsignedIntValue] >= 30) {
            [found addObject:record];
            HFADiagnosticsLog(@"image-candidate", @"matched", record);
        }
    }
    [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger x = [a[@"score"] integerValue], y = [b[@"score"] integerValue];
        if (x != y) return x > y ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"image"] compare:b[@"image"]];
    }];
    HFAEvent(events, @"image-discovery", found.count ? @"pass" : @"no-candidate",
             @{ @"candidateCount": @(found.count), @"topCandidate": found.firstObject[@"image"] ?: @"",
                @"appOwnedImages": @(appOwnedCount), @"fingerprintedImages": @(fingerprintedCount),
                @"hitImageLimit": @(totalCount > count) });
    return found;
}
