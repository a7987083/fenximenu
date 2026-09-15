#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void HFACyberUIAppendLog(NSString *text);

static NSMutableArray<NSDictionary *> *gHFAAppLocalCandidates;
static char gHFAAppLocalPrimaryImage[512];

static NSString *HFAAppLocalBase(const char *path) {
    if (!path) return @"";
    const char *slash = strrchr(path, '/');
    return [NSString stringWithUTF8String:slash ? slash + 1 : path] ?: @"";
}

static void HFAAppLocalLog(NSString *line) {
    if (!line.length) return;
    @autoreleasepool {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f = fopen(path.fileSystemRepresentation, "a");
        if (f) {
            fprintf(f, "%s\n", line.UTF8String ?: "[APPLOCAL]");
            fflush(f);
            fclose(f);
        }
        HFACyberUIAppendLog(line);
    }
}

static BOOL HFAAppLocalDataHas(NSData *data, const char *needle) {
    if (!data.length || !needle || !*needle) return NO;
    NSData *token = [NSData dataWithBytes:needle length:strlen(needle)];
    if (!token.length || token.length > data.length) return NO;
    return [data rangeOfData:token options:0 range:NSMakeRange(0, data.length)].location != NSNotFound;
}

static BOOL HFAAppLocalIsMachOData(NSData *data) {
    if (data.length < sizeof(uint32_t)) return NO;
    uint32_t magic = 0;
    [data getBytes:&magic length:sizeof(magic)];
    return magic == MH_MAGIC || magic == MH_CIGAM ||
           magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
           magic == FAT_MAGIC || magic == FAT_CIGAM;
}

static NSData *HFAAppLocalMappedData(NSString *path) {
    if (!path.length) return nil;
    NSError *error = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&error];
    if (!data && error)
        HFAAppLocalLog([NSString stringWithFormat:@"[READ-FAIL] %@ reason=%@", path.lastPathComponent, error.localizedDescription ?: @"?"]);
    return data;
}

static int HFAAppLocalLoadedIndex(NSString *candidatePath) {
    if (!candidatePath.length) return -1;
    NSString *standard = candidatePath.stringByStandardizingPath;
    NSString *base = candidatePath.lastPathComponent;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if ([path.stringByStandardizingPath isEqualToString:standard]) return (int)i;
    }
    for (uint32_t i = 0; i < count; i++) {
        const char *raw = _dyld_get_image_name(i);
        if (!raw) continue;
        NSString *path = [NSString stringWithUTF8String:raw];
        if ([path.lastPathComponent isEqualToString:base]) return (int)i;
    }
    return -1;
}

static NSDictionary *HFAAppLocalFingerprint(NSString *path, NSData *data) {
    NSMutableArray<NSString *> *evidence = [NSMutableArray array];
    unsigned runtimeScore = 0, legacyScore = 0, jailScore = 0;

    struct Token { const char *value; unsigned weight; };
    const struct Token runtimeTokens[] = {
        {"customSwitch", 20}, {"modtext", 20}, {"kTypeButton", 24},
        {"buttonBlock", 12}, {"numericRuntimeModifier", 12},
        {"Made by Laxus for iOSGods.com!", 18}, {"Made for iOSGods.com", 12}
    };
    const struct Token legacyTokens[] = {
        {"APPatchItem", 32}, {"IGSecretInt", 20}, {"IGSecretData", 20},
        {"IGSecretString", 10}, {"APSubpatchManager", 18}, {"IGCodePatch", 16}
    };
    const struct Token jailTokens[] = {
        {".app-key-metadata-", 32}, {"JailpatchConfigValidator", 28},
        {"Jailpatch runtime table", 28}, {"jailpatch", 10}
    };

    for (unsigned i = 0; i < sizeof(runtimeTokens) / sizeof(runtimeTokens[0]); i++) {
        if (!HFAAppLocalDataHas(data, runtimeTokens[i].value)) continue;
        runtimeScore += runtimeTokens[i].weight;
        [evidence addObject:[NSString stringWithFormat:@"runtime:%s", runtimeTokens[i].value]];
    }
    for (unsigned i = 0; i < sizeof(legacyTokens) / sizeof(legacyTokens[0]); i++) {
        if (!HFAAppLocalDataHas(data, legacyTokens[i].value)) continue;
        legacyScore += legacyTokens[i].weight;
        [evidence addObject:[NSString stringWithFormat:@"legacy:%s", legacyTokens[i].value]];
    }
    for (unsigned i = 0; i < sizeof(jailTokens) / sizeof(jailTokens[0]); i++) {
        if (!HFAAppLocalDataHas(data, jailTokens[i].value)) continue;
        jailScore += jailTokens[i].weight;
        [evidence addObject:[NSString stringWithFormat:@"jail:%s", jailTokens[i].value]];
    }

    NSString *family = @"unknown";
    unsigned score = 0;
    if (legacyScore >= runtimeScore && legacyScore >= jailScore && legacyScore >= 30) {
        family = @"legacy-15mb";
        score = legacyScore;
    } else if (runtimeScore >= legacyScore && runtimeScore >= jailScore && runtimeScore >= 30) {
        family = @"runtime-5mb";
        score = runtimeScore;
    } else if (jailScore >= 30) {
        family = @"jailpatch-v2";
        score = jailScore;
    }
    if (score > 100) score = 100;
    int loadedIndex = HFAAppLocalLoadedIndex(path);
    unsigned long long bytes = data.length;
    return @{
        @"path": path,
        @"image": path.lastPathComponent ?: @"?",
        @"family": family,
        @"score": @(score),
        @"runtimeScore": @(runtimeScore),
        @"legacyScore": @(legacyScore),
        @"jailScore": @(jailScore),
        @"size": @(bytes),
        @"loaded": @(loadedIndex >= 0),
        @"loadedIndex": @(loadedIndex),
        @"evidence": evidence
    };
}

static void HFAAppLocalAddMachO(NSMutableArray<NSString *> *paths, NSString *path) {
    if (!path.length || [path.lastPathComponent containsString:@"HFAMapUniversal"]) return;
    NSData *head = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
    if (!HFAAppLocalIsMachOData(head)) return;
    if (![paths containsObject:path]) [paths addObject:path];
}

static NSArray<NSString *> *HFAAppLocalEnumerateBundleMachOs(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bundle = NSBundle.mainBundle.bundlePath;
    NSString *mainExecutable = NSBundle.mainBundle.executablePath.stringByStandardizingPath;
    NSMutableArray<NSString *> *paths = [NSMutableArray array];

    NSArray<NSString *> *root = [fm contentsOfDirectoryAtPath:bundle error:nil] ?: @[];
    for (NSString *name in root) {
        NSString *path = [bundle stringByAppendingPathComponent:name];
        BOOL directory = NO;
        if (![fm fileExistsAtPath:path isDirectory:&directory] || directory) continue;
        if ([path.stringByStandardizingPath isEqualToString:mainExecutable]) continue;
        HFAAppLocalAddMachO(paths, path);
    }

    NSString *frameworks = [bundle stringByAppendingPathComponent:@"Frameworks"];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:frameworks];
    for (NSString *relative in enumerator) {
        if ([relative containsString:@"/_CodeSignature/"] || [relative hasSuffix:@".plist"] ||
            [relative hasSuffix:@".strings"] || [relative hasSuffix:@".car"]) continue;
        NSString *path = [frameworks stringByAppendingPathComponent:relative];
        BOOL directory = NO;
        if (![fm fileExistsAtPath:path isDirectory:&directory] || directory) continue;
        HFAAppLocalAddMachO(paths, path);
    }
    return paths;
}

static void HFAAppLocalWriteIndex(NSArray<NSDictionary *> *candidates, NSUInteger scannedCount) {
    NSDictionary *root = @{
        @"schema": @"com.hfa.app-local-candidates/v1",
        @"analyzer": @"HFAMapUniversal v1.9.36.7 AppLocalMenuResolver",
        @"bundleIdentifier": NSBundle.mainBundle.bundleIdentifier ?: @"?",
        @"scannedMachOCount": @(scannedCount),
        @"candidateCount": @(candidates.count),
        @"candidates": candidates
    };
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_AppLocalCandidates.json"];
    if (json && [json writeToFile:path options:NSDataWritingAtomic error:&error])
        HFAAppLocalLog([NSString stringWithFormat:@"[INDEX] %@ candidates=%lu", path.lastPathComponent, (unsigned long)candidates.count]);
    else
        HFAAppLocalLog([NSString stringWithFormat:@"[INDEX-FAIL] %@", error.localizedDescription ?: @"json"]);
}

unsigned HFAAppLocalScanCandidates(void) {
    @autoreleasepool {
        NSArray<NSString *> *machOs = HFAAppLocalEnumerateBundleMachOs();
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] bundle=%@", NSBundle.mainBundle.bundlePath.lastPathComponent]);
        HFAAppLocalLog([NSString stringWithFormat:@"[DISCOVERY] app-local Mach-O=%lu", (unsigned long)machOs.count]);
        NSMutableArray<NSDictionary *> *found = [NSMutableArray array];
        for (NSString *path in machOs) {
            NSData *data = HFAAppLocalMappedData(path);
            if (!data.length) continue;
            NSDictionary *record = HFAAppLocalFingerprint(path, data);
            unsigned score = [record[@"score"] unsignedIntValue];
            double mb = [record[@"size"] unsignedLongLongValue] / (1024.0 * 1024.0);
            if (!score) {
                HFAAppLocalLog([NSString stringWithFormat:@"[SKIP] %@ size=%.2fMB reason=no-menu-fingerprint", record[@"image"], mb]);
                continue;
            }
            HFAAppLocalLog([NSString stringWithFormat:@"[CANDIDATE] %@ family=%@ score=%u size=%.2fMB loaded=%@", record[@"image"], record[@"family"], score, mb, [record[@"loaded"] boolValue] ? @"yes" : @"no"]);
            for (NSString *hit in record[@"evidence"])
                HFAAppLocalLog([NSString stringWithFormat:@"  [HIT] %@", hit]);
            [found addObject:record];
        }
        [found sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSInteger sa = [a[@"score"] integerValue], sb = [b[@"score"] integerValue];
            if (sa > sb) return NSOrderedAscending;
            if (sa < sb) return NSOrderedDescending;
            return [a[@"image"] compare:b[@"image"]];
        }];
        @synchronized([NSObject class]) {
            gHFAAppLocalCandidates = [found mutableCopy];
            gHFAAppLocalPrimaryImage[0] = 0;
            if (found.count) {
                NSString *image = found.firstObject[@"image"];
                snprintf(gHFAAppLocalPrimaryImage, sizeof(gHFAAppLocalPrimaryImage), "%s", image.UTF8String ?: "");
            }
        }
        HFAAppLocalWriteIndex(found, machOs.count);
        if (found.count)
            HFAAppLocalLog([NSString stringWithFormat:@"[SELECT] primary=%@ family=%@ score=%@", found.firstObject[@"image"], found.firstObject[@"family"], found.firstObject[@"score"]]);
        else
            HFAAppLocalLog(@"[SELECT] no menu candidate found");
        return (unsigned)found.count;
    }
}

const char *HFAAppLocalPrimaryImage(void) {
    return gHFAAppLocalPrimaryImage[0] ? gHFAAppLocalPrimaryImage : NULL;
}

unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity) {
    if (!image || !*image || !buffer || !capacity) return 0;
    int index = -1;
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        NSString *base = HFAAppLocalBase(path);
        if ([base isEqualToString:[NSString stringWithUTF8String:image]]) { index = (int)i; break; }
    }
    if (index < 0) return 0;
    const struct mach_header *mh = _dyld_get_image_header((uint32_t)index);
    if (!mh || mh->magic != MH_MAGIC_64) return 0;
    const struct mach_header_64 *header = (const struct mach_header_64 *)mh;
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)index);
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    unsigned out = 0;
    for (uint32_t i = 0; i < header->ncmds && out < capacity; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (!lc->cmdsize) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            const struct section_64 *sec = (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects && out < capacity; j++, sec++) {
                if (strncmp(sec->sectname, "__objc_classlist", 16) != 0 &&
                    strncmp(sec->sectname, "__objc_nlclslist", 16) != 0) continue;
                uintptr_t address = (uintptr_t)slide + (uintptr_t)sec->addr;
                NSUInteger count = (NSUInteger)(sec->size / sizeof(Class));
                if (count > 4096) count = 4096;
                Class *classes = (Class *)address;
                for (NSUInteger k = 0; k < count && out < capacity; k++) {
                    Class cls = classes[k];
                    if (!cls) continue;
                    BOOL duplicate = NO;
                    for (unsigned q = 0; q < out; q++) if (buffer[q] == cls) { duplicate = YES; break; }
                    if (!duplicate) buffer[out++] = cls;
                }
            }
        }
        cursor += lc->cmdsize;
    }
    return out;
}

static unsigned HFAAppLocalDescriptorScore(Class cls) {
    if (!cls) return 0;
    unsigned score = 0;
    for (Class current = cls; current && current != [NSObject class]; current = class_getSuperclass(current)) {
        unsigned count = 0;
        Ivar *ivars = class_copyIvarList(current, &count);
        for (unsigned i = 0; ivars && i < count; i++) {
            const char *type = ivar_getTypeEncoding(ivars[i]);
            if (!type) continue;
            if (strstr(type, "IGSecretInt")) score += 25;
            if (strstr(type, "IGSecretData")) score += 25;
            if (strstr(type, "IGSecretString")) score += 10;
            if (strstr(type, "APSubpatchManager")) score += 15;
            if (strstr(type, "IGCodePatch")) score += 10;
        }
        free(ivars);
    }
    return score;
}

static BOOL HFAAppLocalPatchLike(Class cls) {
    return cls && class_getInstanceMethod(cls, sel_registerName("identifier")) &&
           class_getInstanceMethod(cls, sel_registerName("type")) &&
           class_getInstanceMethod(cls, sel_registerName("currentState")) &&
           class_getInstanceMethod(cls, sel_registerName("setCurrentState:"));
}

unsigned HFAAppLocalInspectCandidates(void) {
    @autoreleasepool {
        NSArray<NSDictionary *> *snapshot = nil;
        @synchronized([NSObject class]) { snapshot = [gHFAAppLocalCandidates copy]; }
        if (!snapshot.count) {
            HFAAppLocalScanCandidates();
            @synchronized([NSObject class]) { snapshot = [gHFAAppLocalCandidates copy]; }
        }
        unsigned inspected = 0;
        for (NSDictionary *candidate in snapshot) {
            if (![candidate[@"loaded"] boolValue]) {
                HFAAppLocalLog([NSString stringWithFormat:@"[IMAGE-LOCAL] %@ not loaded; open original menu and scan again", candidate[@"image"]]);
                continue;
            }
            NSString *image = candidate[@"image"];
            Class classes[512] = {0};
            unsigned classCount = HFAAppLocalCopyClassesForImage(image.UTF8String, classes, 512);
            unsigned patchLike = 0, descriptors = 0, emitted = 0;
            for (unsigned i = 0; i < classCount; i++) {
                Class cls = classes[i];
                BOOL patch = HFAAppLocalPatchLike(cls);
                unsigned descriptor = HFAAppLocalDescriptorScore(cls);
                if (patch) patchLike++;
                if (descriptor >= 25) descriptors++;
                if ((patch || descriptor >= 25) && emitted < 24) {
                    HFAAppLocalLog([NSString stringWithFormat:@"  [CLASS] %s patchItem=%@ descriptorScore=%u", class_getName(cls) ?: "?", patch ? @"yes" : @"no", descriptor]);
                    emitted++;
                }
            }
            HFAAppLocalLog([NSString stringWithFormat:@"[IMAGE-LOCAL] %@ family=%@ classes=%u patchItems=%u descriptors=%u", image, candidate[@"family"], classCount, patchLike, descriptors]);
            inspected++;
        }
        return inspected;
    }
}
