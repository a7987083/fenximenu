#import "HFAMapPatchV1.h"
#import <mach-o/dyld.h>
#import <mach/machine.h>
#include <limits.h>

static NSString *HFAString(id value) {
    return [value isKindOfClass:NSString.class] && [value length] ? value : nil;
}

static BOOL HFAValidHexDigits(NSString *value, BOOL requireWholeBytes) {
    if (!value.length || (requireWholeBytes && (value.length & 1U))) return NO;
    static NSCharacterSet *invalid;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        invalid = [[[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet] copy];
    });
    return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static BOOL HFAValidOffset(NSString *value) {
    if (value.length <= 2 || ![value hasPrefix:@"0x"]) return NO;
    return HFAValidHexDigits([value substringFromIndex:2], NO);
}

static BOOL HFAParseOffset(NSString *value, unsigned long long *result) {
    if (!HFAValidOffset(value)) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:[value substringFromIndex:2]];
    unsigned long long parsed = 0;
    if (![scanner scanHexLongLong:&parsed] || !scanner.isAtEnd) return NO;
    if (result) *result = parsed;
    return YES;
}

static unsigned char HFAHexNibble(unichar character) {
    if (character >= '0' && character <= '9') return (unsigned char)(character - '0');
    if (character >= 'a' && character <= 'f') return (unsigned char)(character - 'a' + 10);
    return (unsigned char)(character - 'A' + 10);
}

static unsigned char HFAHexByteAt(NSString *value, NSUInteger byteIndex) {
    NSUInteger index = byteIndex * 2;
    return (unsigned char)((HFAHexNibble([value characterAtIndex:index]) << 4) |
                           HFAHexNibble([value characterAtIndex:index + 1]));
}

static BOOL HFARangesOverlap(NSDictionary *a, NSDictionary *b,
                             unsigned long long *start, unsigned long long *end) {
    unsigned long long aStart = [a[@"offsetValue"] unsignedLongLongValue];
    unsigned long long bStart = [b[@"offsetValue"] unsignedLongLongValue];
    unsigned long long aEnd = aStart + [a[@"length"] unsignedLongLongValue];
    unsigned long long bEnd = bStart + [b[@"length"] unsignedLongLongValue];
    unsigned long long overlapStart = MAX(aStart, bStart);
    unsigned long long overlapEnd = MIN(aEnd, bEnd);
    if (overlapStart >= overlapEnd) return NO;
    if (start) *start = overlapStart;
    if (end) *end = overlapEnd;
    return YES;
}

static BOOL HFAOriginalsAgreeInOverlap(NSDictionary *a, NSDictionary *b,
                                       unsigned long long start, unsigned long long end) {
    unsigned long long aStart = [a[@"offsetValue"] unsignedLongLongValue];
    unsigned long long bStart = [b[@"offsetValue"] unsignedLongLongValue];
    NSString *aOriginal = a[@"original"];
    NSString *bOriginal = b[@"original"];
    for (unsigned long long address = start; address < end; ++address) {
        if (HFAHexByteAt(aOriginal, (NSUInteger)(address - aStart)) !=
            HFAHexByteAt(bOriginal, (NSUInteger)(address - bStart))) return NO;
    }
    return YES;
}

static NSString *HFARuntimeArchitecture(void) {
    const struct mach_header *header = _dyld_image_count() ? _dyld_get_image_header(0) : NULL;
    if (!header) return @"unknown";
    if (header->cputype == CPU_TYPE_ARM64) {
        cpu_subtype_t subtype = header->cpusubtype & ~CPU_SUBTYPE_MASK;
#ifdef CPU_SUBTYPE_ARM64E
        if (subtype == CPU_SUBTYPE_ARM64E) return @"arm64e";
#endif
        return @"arm64";
    }
    return [NSString stringWithFormat:@"cpu-%d-%d", header->cputype,
                                      header->cpusubtype & ~CPU_SUBTYPE_MASK];
}

NSDictionary *HFAMapBuildPatchV1PackageWithReport(NSArray<NSDictionary *> *features,
                                                   NSString **reason,
                                                   NSDictionary **report) {
    if (reason) *reason = nil;
    if (report) *report = nil;
    NSDictionary *info = NSBundle.mainBundle.infoDictionary ?: @{};
    NSString *bundleID = HFAString(NSBundle.mainBundle.bundleIdentifier) ?: @"unknown.bundle";
    NSString *shortVersion = HFAString(info[@"CFBundleShortVersionString"]) ?: @"0";
    NSString *buildVersion = HFAString(info[@"CFBundleVersion"]) ?: @"0";

    NSMutableArray<NSDictionary *> *records = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *rejectedRecords = [NSMutableArray array];
    NSMutableArray<NSDictionary *> *sharedPatchSites = [NSMutableArray array];

    for (NSDictionary *feature in features ?: @[]) {
        if (![feature isKindOfClass:NSDictionary.class] || ![feature[@"canonicalEligible"] boolValue] ||
            ![feature[@"confidence"] isEqualToString:@"byte-validated"]) continue;
        NSString *identifier = HFAString(feature[@"identifier"]);
        NSString *title = HFAString(feature[@"name"]);
        NSString *target = HFAString(feature[@"targetImage"]);
        NSString *offset = HFAString(feature[@"offset"]);
        NSString *original = HFAString(feature[@"original"]);
        NSString *enabled = HFAString(feature[@"patch"]);
        unsigned long long offsetValue = 0;
        if (!identifier || !title || !target || !HFAParseOffset(offset, &offsetValue) ||
            !HFAValidHexDigits(original, YES) || !HFAValidHexDigits(enabled, YES) ||
            original.length != enabled.length || !original.length ||
            offsetValue > ULLONG_MAX - (original.length / 2)) {
            if (reason) *reason = @"invalid-canonical-feature";
            if (report) *report = @{ @"schema": @"com.hfa.patch-export-report/v1",
                                      @"status": @"rejected",
                                      @"reason": @"invalid-canonical-feature" };
            return nil;
        }
        NSString *groupKey = [NSString stringWithFormat:@"%@\n%@", identifier, title];
        [records addObject:@{ @"groupKey": groupKey, @"identifier": identifier,
                              @"title": title, @"target": target, @"offset": offset,
                              @"offsetValue": @(offsetValue), @"original": original,
                              @"enabled": enabled, @"length": @(original.length / 2) }];
    }

    NSMutableIndexSet *rejected = [NSMutableIndexSet indexSet];
    for (NSUInteger i = 0; i < records.count; ++i) {
        NSDictionary *a = records[i];
        for (NSUInteger j = i + 1; j < records.count; ++j) {
            NSDictionary *b = records[j];
            if (![a[@"target"] isEqualToString:b[@"target"]]) continue;
            unsigned long long start = 0, end = 0;
            if (!HFARangesOverlap(a, b, &start, &end)) continue;
            if (!HFAOriginalsAgreeInOverlap(a, b, start, end)) {
                [rejected addIndex:i];
                [rejected addIndex:j];
            }
        }
    }

    [rejected enumerateIndexesUsingBlock:^(NSUInteger index, BOOL *stop) {
        (void)stop;
        NSDictionary *record = records[index];
        [rejectedRecords addObject:@{ @"reason": @"inconsistent-original-overlap",
                                      @"featureId": record[@"identifier"],
                                      @"title": record[@"title"], @"target": record[@"target"],
                                      @"offset": record[@"offset"], @"original": record[@"original"],
                                      @"enabled": record[@"enabled"] }];
    }];

    for (NSUInteger i = 0; i < records.count; ++i) {
        if ([rejected containsIndex:i]) continue;
        NSDictionary *a = records[i];
        for (NSUInteger j = i + 1; j < records.count; ++j) {
            if ([rejected containsIndex:j]) continue;
            NSDictionary *b = records[j];
            if ([a[@"groupKey"] isEqualToString:b[@"groupKey"]] ||
                ![a[@"target"] isEqualToString:b[@"target"]]) continue;
            unsigned long long start = 0, end = 0;
            if (!HFARangesOverlap(a, b, &start, &end)) continue;
            [sharedPatchSites addObject:@{
                @"target": a[@"target"],
                @"relation": [a[@"offsetValue"] isEqual:b[@"offsetValue"]]
                    ? @"same-offset" : @"overlapping-range",
                @"overlapOffset": [NSString stringWithFormat:@"0x%llX", start],
                @"overlapLength": @(end - start),
                @"features": @[
                    @{ @"id": a[@"identifier"], @"title": a[@"title"],
                       @"offset": a[@"offset"], @"length": a[@"length"],
                       @"enabled": a[@"enabled"] },
                    @{ @"id": b[@"identifier"], @"title": b[@"title"],
                       @"offset": b[@"offset"], @"length": b[@"length"],
                       @"enabled": b[@"enabled"] }
                ]
            }];
        }
    }

    NSMutableDictionary<NSString *, NSMutableDictionary *> *groups = [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSMutableSet<NSString *> *> *groupSignatures = [NSMutableDictionary dictionary];
    NSMutableArray<NSMutableDictionary *> *orderedGroups = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSDictionary *> *targets = [NSMutableDictionary dictionary];
    NSUInteger deduplicatedCount = 0;
    NSUInteger emittedPatchCount = 0;

    for (NSUInteger index = 0; index < records.count; ++index) {
        if ([rejected containsIndex:index]) continue;
        NSDictionary *record = records[index];
        NSString *groupKey = record[@"groupKey"];
        NSMutableDictionary *group = groups[groupKey];
        if (!group) {
            group = [@{ @"group": @"Imported", @"id": record[@"identifier"],
                        @"title": record[@"title"],
                        @"defaultEnabled": @NO, @"patches": [NSMutableArray array] } mutableCopy];
            groups[groupKey] = group;
            groupSignatures[groupKey] = [NSMutableSet set];
            [orderedGroups addObject:group];
        }

        NSString *signature = [NSString stringWithFormat:@"%@:%@:%@",
                               record[@"target"], record[@"offset"], record[@"enabled"]];
        NSMutableSet<NSString *> *signatures = groupSignatures[groupKey];
        if ([signatures containsObject:signature]) {
            ++deduplicatedCount;
            continue;
        }
        [signatures addObject:signature];
        [group[@"patches"] addObject:@{ @"original": record[@"original"],
                                         @"enabled": record[@"enabled"],
                                         @"offset": record[@"offset"],
                                         @"target": record[@"target"] }];
        targets[record[@"target"]] = @{ @"image": record[@"target"] };
        ++emittedPatchCount;
    }

    if (report) *report = @{ @"schema": @"com.hfa.patch-export-report/v1",
                              @"status": rejected.count ? @"partial" : @"complete",
                              @"inputRecordCount": @(records.count),
                              @"emittedPatchCount": @(emittedPatchCount),
                              @"deduplicatedCount": @(deduplicatedCount),
                              @"rejectedRecords": rejectedRecords,
                              @"sharedPatchSites": sharedPatchSites };

    return @{ @"package": @{ @"shortVersion": shortVersion,
                               @"buildVersion": buildVersion,
                               @"architectures": @[HFARuntimeArchitecture()],
                               @"bundleIdentifier": bundleID },
              @"targets": targets,
              @"features": orderedGroups,
              @"schema": @"com.hfa.patch/v1",
              @"name": [NSString stringWithFormat:@"%@ %@", bundleID, shortVersion] };
}

NSDictionary *HFAMapBuildPatchV1Package(NSArray<NSDictionary *> *features, NSString **reason) {
    return HFAMapBuildPatchV1PackageWithReport(features, reason, NULL);
}
