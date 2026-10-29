#import "HFAMapFastDiscovery.h"
#import "HFAMapDiagnostics.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <objc/runtime.h>
#include <string.h>

static const uint32_t kHFAFastMaxImages = 2048;
static const uint64_t kHFAFastMaxBytesPerImage = 16ULL * 1024ULL * 1024ULL;

static NSString *HFAFastComparablePath(NSString *path) {
    if (!path.length) return @"";
    NSString *standardized = path.stringByStandardizingPath;
    return standardized.stringByResolvingSymlinksInPath;
}

// Select exactly one analysis target by bundle layout. If UnityFramework.framework
// exists but its binary is absent or not loaded, fail closed instead of silently
// scanning the main executable or an unrelated injected/framework image.
static NSString *HFAFastPreferredTargetPath(NSString **targetKind,
                                            NSString **targetReason,
                                            BOOL *unityFrameworkBundleExists) {
    NSString *bundlePath = NSBundle.mainBundle.bundlePath.stringByStandardizingPath;
    NSString *frameworkBundle = [bundlePath stringByAppendingPathComponent:
                                 @"Frameworks/UnityFramework.framework"];
    BOOL isDirectory = NO;
    BOOL hasUnityFramework = bundlePath.length &&
        [[NSFileManager defaultManager] fileExistsAtPath:frameworkBundle isDirectory:&isDirectory] &&
        isDirectory;

    if (unityFrameworkBundleExists) *unityFrameworkBundleExists = hasUnityFramework;
    if (hasUnityFramework) {
        if (targetKind) *targetKind = @"unity-framework";
        if (targetReason) *targetReason = @"unity-framework-present";
        return HFAFastComparablePath([frameworkBundle stringByAppendingPathComponent:@"UnityFramework"]);
    }

    if (targetKind) *targetKind = @"main-executable";
    if (targetReason) *targetReason = @"unity-framework-absent-main-executable-fallback";
    return HFAFastComparablePath(NSBundle.mainBundle.executablePath ?: @"");
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
    NSString *targetKind = nil;
    NSString *targetReason = nil;
    BOOL unityFrameworkBundleExists = NO;
    NSString *targetPath = HFAFastPreferredTargetPath(&targetKind, &targetReason,
                                                       &unityFrameworkBundleExists);
    NSFileManager *manager = NSFileManager.defaultManager;
    BOOL targetFileExists = targetPath.length && [manager fileExistsAtPath:targetPath];

    uint32_t total = _dyld_image_count();
    uint32_t count = MIN(total, kHFAFastMaxImages);
    HFAFastEvent(events, @"start", @{
        @"totalLoadedImages": @(total),
        @"inspectedImages": @(count),
        @"mode": @"preferred-image-path-lightweight-only",
        @"targetPath": targetPath ?: @"",
        @"targetKind": targetKind ?: @"unknown",
        @"targetSelectionReason": targetReason ?: @"",
        @"unityFrameworkBundleExists": @(unityFrameworkBundleExists),
        @"targetFileExists": @(targetFileExists)
    });

    if (!targetPath.length || !targetFileExists) {
        NSString *failure = unityFrameworkBundleExists
            ? @"unity-framework-binary-missing" : @"main-executable-missing";
        HFAFastEvent(events, @"target-file-missing", @{
            @"reason": failure,
            @"targetPath": targetPath ?: @"",
            @"targetKind": targetKind ?: @"unknown"
        });
        HFAFastEvent(events, @"no-candidate", @{
            @"candidateCount": @0,
            @"targetPath": targetPath ?: @"",
            @"targetKind": targetKind ?: @"unknown",
            @"deepAnalysisPerformed": @NO
        });
        return @[];
    }

    // Resolve the preferred on-disk path against dyld's loaded-image list.
    // The scan never substitutes an unrelated image when this target is absent.
    uint32_t targetIndex = UINT32_MAX;
    NSString *loadedTargetPath = nil;
    for (uint32_t i = 0; i < count; ++i) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *imagePath = [NSString stringWithUTF8String:raw] ?: @"";
        if (![HFAFastComparablePath(imagePath) isEqualToString:targetPath]) continue;
        targetIndex = i;
        loadedTargetPath = imagePath;
        break;
    }

    if (targetIndex == UINT32_MAX) {
        HFAFastEvent(events, @"target-not-loaded", @{
            @"reason": @"preferred-target-not-loaded",
            @"targetPath": targetPath,
            @"targetKind": targetKind ?: @"unknown",
            @"unityFrameworkBundleExists": @(unityFrameworkBundleExists),
            @"processedFullImageList": @(count),
            @"hitImageLimit": @(total > count)
        });
        HFAFastEvent(events, @"no-candidate", @{
            @"candidateCount": @0,
            @"targetPath": targetPath,
            @"targetKind": targetKind ?: @"unknown",
            @"deepAnalysisPerformed": @NO
        });
        return @[];
    }

    const struct mach_header *rawHeader = _dyld_get_image_header(targetIndex);
    if (!rawHeader || rawHeader->magic != MH_MAGIC_64) {
        HFAFastEvent(events, @"invalid-target-macho", @{
            @"reason": @"target-header-missing-or-not-64-bit",
            @"targetPath": loadedTargetPath ?: targetPath,
            @"targetKind": targetKind ?: @"unknown",
            @"targetIndex": @(targetIndex)
        });
        return @[];
    }

    NSDictionary *record = HFAFastFingerprint((const struct mach_header_64 *)rawHeader,
                                               _dyld_get_image_vmaddr_slide(targetIndex),
                                               loadedTargetPath ?: targetPath);
    if (!record) {
        HFAFastEvent(events, @"invalid-target-macho", @{
            @"reason": @"target-fingerprint-rejected",
            @"targetPath": loadedTargetPath ?: targetPath,
            @"targetKind": targetKind ?: @"unknown",
            @"targetIndex": @(targetIndex)
        });
        return @[];
    }

    NSMutableDictionary *targetRecord = [record mutableCopy];
    [record release];
    targetRecord[@"targetSelectedByPath"] = @YES;
    targetRecord[@"targetKind"] = targetKind ?: @"unknown";
    targetRecord[@"targetSelectionReason"] = targetReason ?: @"preferred-target-path";
    targetRecord[@"targetSelectionPolicy"] = @"unity-framework-first-else-main-executable";
    targetRecord[@"targetPath"] = loadedTargetPath ?: targetPath;
    targetRecord[@"canonicalEligible"] = @NO;

    // A path-resolved target is an analysis target even when its fingerprint is
    // weak. Keep the score as evidence; do not let that score choose another image.
    NSMutableArray *found = [NSMutableArray arrayWithObject:targetRecord];
    HFAFastEvent(events, @"target-fingerprinted", targetRecord);
    [targetRecord release];

    HFAFastEvent(events, @"pass", @{
        @"candidateCount": @(found.count),
        @"topCandidate": found.firstObject[@"image"] ?: @"",
        @"appOwnedImages": @1,
        @"fingerprintedImages": @1,
        @"processedFullImageList": @(count),
        @"hitImageLimit": @(total > count),
        @"targetPath": targetPath,
        @"targetKind": targetKind ?: @"unknown",
        @"targetSelectionPolicy": @"unity-framework-first-else-main-executable",
        @"deepAnalysisPerformed": @NO
    });
    return found;
}
