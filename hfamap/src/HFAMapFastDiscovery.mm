#import "HFAMapFastDiscovery.h"
#import "HFAMapDiagnostics.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#include <string.h>

static const uint32_t kHFAFastMaxImages = 2048;
static const uint64_t kHFAFastMaxBytesPerImage = 16ULL * 1024ULL * 1024ULL;

static BOOL HFAFastAppOwnedPath(NSString *path) {
    NSString *bundle = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    return bundle.length && [path.stringByStandardizingPath hasPrefix:[bundle stringByAppendingString:@"/"]];
}

static BOOL HFAFastExcludedImage(NSString *path) {
    NSString *base = path.lastPathComponent.lowercaseString;
    return [base isEqualToString:NSBundle.mainBundle.executablePath.lastPathComponent.lowercaseString] ||
           [base isEqualToString:@"unityframework"] || [base containsString:@"hfamapuniversal"] ||
           [base containsString:@"substrate"] || [base containsString:@"ellekit"];
}

static BOOL HFAFastContains(const uint8_t *bytes, size_t length, const char *token) {
    size_t n = strlen(token);
    if (!bytes || !n || n > length) return NO;
    for (size_t i = 0; i + n <= length; ++i)
        if (bytes[i] == (uint8_t)token[0] && memcmp(bytes + i, token, n) == 0) return YES;
    return NO;
}

static void HFAFastEvent(NSMutableArray *events, NSString *status, NSDictionary *details) {
    NSMutableDictionary *event = [@{ @"time": @([[NSDate date] timeIntervalSince1970]),
                                      @"stage": @"fast-menu-discovery",
                                      @"status": status ?: @"?" } mutableCopy];
    if (details) [event addEntriesFromDictionary:details];
    [events addObject:event];
}

static NSDictionary *HFAFastFingerprint(const struct mach_header_64 *header, intptr_t slide, NSString *path) {
    if (!header || header->magic != MH_MAGIC_64 || header->ncmds > 4096 ||
        header->sizeofcmds > 4U * 1024U * 1024U) return nil;

    unsigned ui = 0, legacy = 0, jail = 0, patch = 0;
    uint64_t scanned = 0;
    NSString *uuidValue = nil;
    NSMutableArray *hits = [NSMutableArray array];
    struct Rule { const char *token; unsigned weight; unsigned group; };
    static const struct Rule rules[] = {
        {"addButtonWithTitle:",24,0},{"customSwitch",20,0},{"iOSGods",14,0},
        {"IGMenu 1.0",14,0},{"APMenuControl",20,0},{"callback:",8,0},
        {"initialValue:minValue:maxValue",10,0},{"onEnabled:",8,0},{"onDisabled:",8,0},
        {"APPatchItem",30,1},{"APSubpatchManager",24,1},{"IGSecretInt",16,1},
        {"IGSecretData",16,1},{"IGCodePatch",18,1},{"offset:patch:",12,1},
        {"JailpatchConfigValidator",32,2},{"Jailpatch runtime table",28,2},
        {"OffsetInstruction",18,2},{"OffsetType",14,2},{".app-key-metadata-",24,2},
        {"MemoryPatch",24,3},{"createWithHex",18,3},{"createWithBytes",18,3},
        {"createWithAsm",18,3},{"CodePatch",16,3},{"ActiveCodePatch offset:",22,3},
        {"machoPath",10,3},{"findHexFirst",8,3},{"findIdaPatternFirst",8,3},
        {"findSymbol",8,3},{"get_OrigBytes",8,3},{"get_PatchBytes",8,3}
    };
    BOOL found[sizeof(rules)/sizeof(rules[0])] = {};

    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t ci = 0; ci < header->ncmds; ++ci) {
        if (cursor + sizeof(struct load_command) > end) return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return nil;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid = (const struct uuid_command *)cursor;
            const uint8_t *u = uuid->uuid;
            uuidValue = [NSString stringWithFormat:
                @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]];
        }
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (sizeof(*seg) + (uint64_t)seg->nsects * sizeof(struct section_64) > lc->cmdsize) return nil;
            const struct section_64 *sects = (const struct section_64 *)(seg + 1);
            for (uint32_t si = 0; si < seg->nsects && scanned < kHFAFastMaxBytesPerImage; ++si) {
                if (strncmp(sects[si].sectname, "__cstring", 16) &&
                    strncmp(sects[si].sectname, "__objc_methname", 16) &&
                    strncmp(sects[si].sectname, "__const", 16)) continue;
                uint64_t size = MIN(sects[si].size, kHFAFastMaxBytesPerImage - scanned);
                if (!size || sects[si].addr < seg->vmaddr || size > seg->vmsize ||
                    sects[si].addr - seg->vmaddr > seg->vmsize - size) continue;
                const uint8_t *bytes = (const uint8_t *)(uintptr_t)(sects[si].addr + slide);
                scanned += size;
                for (NSUInteger r = 0; r < sizeof(rules)/sizeof(rules[0]); ++r) {
                    if (found[r] || !HFAFastContains(bytes, (size_t)size, rules[r].token)) continue;
                    found[r] = YES;
                    if (rules[r].group == 0) ui += rules[r].weight;
                    else if (rules[r].group == 1) legacy += rules[r].weight;
                    else if (rules[r].group == 2) jail += rules[r].weight;
                    else patch += rules[r].weight;
                    [hits addObject:[NSString stringWithUTF8String:rules[r].token]];
                }
            }
        }
        cursor += lc->cmdsize;
    }

    unsigned classCount = 0;
    const char **classNames = objc_copyClassNamesForImage(path.fileSystemRepresentation, &classCount);
    free(classNames);
    unsigned structure = (classCount >= 150 && classCount <= 260) ? 20U : (classCount >= 32 ? 8U : 0U);

    NSString *menuFamily = @"unknown";
    if (ui >= 24 && legacy >= 24 && legacy > jail) menuFamily = @"legacy-ap";
    else if (ui >= 24 && jail >= 24) menuFamily = @"jailpatch";
    else if (ui >= 24 || ((legacy || jail || patch) && structure)) menuFamily = @"runtime-menu";

    unsigned strongest = MAX(MAX(legacy, jail), patch);
    unsigned score = [menuFamily isEqualToString:@"unknown"] ? MIN(45U, ui + MIN(strongest, 20U) + structure)
                                                              : MIN(100U, ui + MIN(strongest, 45U) + structure);
    NSMutableDictionary *record = [@{
        @"schema": @"com.hfa.fast-menu-discovery/v1",
        @"path": path,
        @"image": path.lastPathComponent ?: @"?",
        @"family": menuFamily,
        @"menuFamily": menuFamily,
        @"score": @(score),
        @"menuScore": @(ui),
        @"legacyScore": @(legacy),
        @"jailpatchScore": @(jail),
        @"patchPrimitiveScore": @(patch),
        @"objcClassCount": @(classCount),
        @"scannedBytes": @(scanned),
        @"evidence": hits,
        @"discoveryOnly": @YES,
        @"deepAnalysisPerformed": @NO,
        @"analysisOnly": @YES,
        @"canonicalEligible": @NO
    } mutableCopy];
    if (uuidValue.length) record[@"menuUUID"] = uuidValue;
    return record;
}

NSArray<NSDictionary *> *HFAMapFastDiscoverMenuImages(NSMutableArray<NSDictionary *> *events) {
    NSMutableArray *appImages = [NSMutableArray array];
    uint32_t total = _dyld_image_count();
    uint32_t count = MIN(total, kHFAFastMaxImages);
    HFAFastEvent(events, @"start", @{ @"totalLoadedImages": @(total), @"inspectedImages": @(count),
                                       @"mode": @"full-list-first-no-deep-analysis" });

    // Phase A: enumerate the entire loaded-image list first. No time deadline is allowed
    // to make a later-loaded menu dylib disappear merely because of dyld ordering.
    for (uint32_t i = 0; i < count; ++i) {
        const char *raw = _dyld_get_image_name(i);
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!raw || !header) continue;
        NSString *path = [NSString stringWithUTF8String:raw] ?: @"";
        if (!HFAFastAppOwnedPath(path) || HFAFastExcludedImage(path)) continue;
        [appImages addObject:@{ @"index": @(i), @"path": path }];
    }

    // Phase B: lightweight fingerprints only. No CFG, no ObjC method inventory,
    // no IL2CPP MethodIndex, and no runtime action analysis in discovery.
    NSMutableArray *found = [NSMutableArray array];
    NSUInteger fingerprinted = 0;
    for (NSDictionary *item in appImages) {
        uint32_t i = [item[@"index"] unsignedIntValue];
        const struct mach_header *rawHeader = _dyld_get_image_header(i);
        if (!rawHeader) continue;
        NSDictionary *record = HFAFastFingerprint((const struct mach_header_64 *)rawHeader,
                                                   _dyld_get_image_vmaddr_slide(i), item[@"path"]);
        if (!record) continue;
        ++fingerprinted;
        if ([record[@"score"] unsignedIntValue] >= 24) {
            [found addObject:record];
            HFADiagnosticsLog(@"fast-image-candidate", @"matched", record);
        }
    }
    [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSInteger x = [a[@"score"] integerValue], y = [b[@"score"] integerValue];
        if (x != y) return x > y ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"image"] compare:b[@"image"]];
    }];
    HFAFastEvent(events, found.count ? @"pass" : @"no-candidate", @{
        @"candidateCount": @(found.count), @"topCandidate": found.firstObject[@"image"] ?: @"",
        @"appOwnedImages": @(appImages.count), @"fingerprintedImages": @(fingerprinted),
        @"processedFullImageList": @(count), @"hitImageLimit": @(total > count),
        @"deepAnalysisPerformed": @NO
    });
    return found;
}
