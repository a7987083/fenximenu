#import "HFAMapDescriptorStaticCallbackResolver.h"
#import "HFAMapStaticCatalog.h"

#include <stdint.h>
#include <vector>
#include <algorithm>

// v2.5.4 generic descriptor -> static callback provenance.
// Evidence tiers:
//  1) exact descriptor token appears in exactly one static method record (high), or
//  2) exact descriptors occupy one ordered runtime-feature collection and the
//     static method callbacks occupy one unique ordered pointer-site cluster (medium).
// Both paths are fail-closed and analysis-only.
static const NSUInteger kHFADSCMaxFeatures = 64;
static const NSUInteger kHFADSCMaxMethods = 128;
static const NSUInteger kHFADSCMaxPointerSitesPerMethod = 8;
static const uint64_t kHFADSCMaxClusterSpan = 0x800;

typedef struct {
    NSUInteger methodIndex;
    uint64_t fileOffset;
} HFADSCPointerSite;

static NSString *HFADSCNormalize(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return @"";
    NSMutableString *out = [NSMutableString stringWithCapacity:value.length];
    NSCharacterSet *allowed = [NSCharacterSet alphanumericCharacterSet];
    NSString *lower = value.lowercaseString;
    for (NSUInteger i = 0; i < lower.length; ++i) {
        unichar c = [lower characterAtIndex:i];
        if ([allowed characterIsMember:c]) [out appendFormat:@"%C", c];
    }
    return out;
}

static NSDictionary *HFADSCExactDescriptor(NSDictionary *record) {
    NSArray *candidates = [record valueForKeyPath:@"ownership.descriptorCandidates"];
    NSMutableArray *exact = [NSMutableArray array];
    for (NSDictionary *candidate in candidates ?: @[]) {
        if ([candidate[@"exactLabelMatch"] boolValue]) [exact addObject:candidate];
    }
    return exact.count == 1 ? exact.firstObject : nil;
}

static NSDictionary *HFADSCRegistryRecord(NSArray *registry, NSString *label) {
    NSString *needle = HFADSCNormalize(label);
    if (!needle.length) return nil;
    NSDictionary *match = nil;
    for (NSDictionary *record in registry ?: @[]) {
        NSString *name = [record[@"name"] isKindOfClass:NSString.class] ? record[@"name"] : @"";
        if (![HFADSCNormalize(name) isEqualToString:needle]) continue;
        if (match) return nil; // ambiguous labels fail closed
        match = record;
    }
    return match;
}

static BOOL HFADSCParseArrayPath(NSString *path, NSString **parentOut, NSInteger *indexOut) {
    if (!path.length || ![path hasSuffix:@"]"]) return NO;
    NSRange open = [path rangeOfString:@"[" options:NSBackwardsSearch];
    if (open.location == NSNotFound || open.location + 2 > path.length) return NO;
    NSString *indexText = [path substringWithRange:NSMakeRange(open.location + 1,
        path.length - open.location - 2)];
    NSScanner *scanner = [NSScanner scannerWithString:indexText];
    NSInteger index = -1;
    if (![scanner scanInteger:&index] || !scanner.isAtEnd || index < 0) return NO;
    if (parentOut) *parentOut = [path substringToIndex:open.location];
    if (indexOut) *indexOut = index;
    return YES;
}

static BOOL HFADSCTokenMatchesMethod(NSDictionary *descriptor, NSDictionary *method) {
    NSMutableSet *tokens = [NSMutableSet set];
    for (NSString *key in @[@"label", @"identifier"]) {
        NSString *value = descriptor[key];
        NSString *normalized = HFADSCNormalize(value);
        if (normalized.length >= 3) [tokens addObject:normalized];
    }
    if (!tokens.count) return NO;
    for (NSDictionary *entry in method[@"stringEvidence"] ?: @[]) {
        NSString *normalized = HFADSCNormalize(entry[@"value"]);
        if ([tokens containsObject:normalized]) return YES;
    }
    return NO;
}

static NSArray<NSNumber *> *HFADSCPointerSitesForVM(NSData *data,
                                                     uint64_t sliceOffset,
                                                     uint64_t sliceSize,
                                                     uint64_t targetVM) {
    if (!data.length || sliceOffset >= data.length) return @[];
    uint64_t available = MIN(sliceSize, (uint64_t)data.length - sliceOffset);
    if (available < 8) return @[];
    const uint8_t *bytes = (const uint8_t *)data.bytes + sliceOffset;
    NSMutableArray *sites = [NSMutableArray array];
    for (uint64_t off = 0; off + 8 <= available && sites.count < kHFADSCMaxPointerSitesPerMethod; off += 8) {
        uint64_t value = 0;
        memcpy(&value, bytes + off, sizeof(value));
        if (value == targetVM) [sites addObject:@(off)];
    }
    return sites;
}

static NSArray<NSDictionary *> *HFADSCUniqueOrderedCluster(NSArray<NSDictionary *> *methods,
                                                           NSData *data,
                                                           NSDictionary *source) {
    if (!methods.count || methods.count > kHFADSCMaxMethods) return nil;
    uint64_t sliceOffset = [source[@"sliceOffset"] unsignedLongLongValue];
    uint64_t sliceSize = [source[@"sliceSize"] unsignedLongLongValue];
    NSMutableArray *allSites = [NSMutableArray array];
    for (NSUInteger i = 0; i < methods.count; ++i) {
        uint64_t vm = [methods[i][@"functionVM"] unsignedLongLongValue];
        NSArray *sites = HFADSCPointerSitesForVM(data, sliceOffset, sliceSize, vm);
        for (NSNumber *site in sites) {
            [allSites addObject:@{ @"methodIndex": @(i), @"fileOffset": site }];
        }
    }
    [allSites sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        uint64_t av = [a[@"fileOffset"] unsignedLongLongValue];
        uint64_t bv = [b[@"fileOffset"] unsignedLongLongValue];
        return av < bv ? NSOrderedAscending : (av > bv ? NSOrderedDescending : NSOrderedSame);
    }];

    NSMutableArray *clusters = [NSMutableArray array];
    NSUInteger m = methods.count;
    if (allSites.count < m) return nil;
    for (NSUInteger start = 0; start + m <= allSites.count; ++start) {
        NSArray *window = [allSites subarrayWithRange:NSMakeRange(start, m)];
        BOOL ordered = YES;
        for (NSUInteger j = 0; j < m; ++j) {
            if ([window[j][@"methodIndex"] unsignedIntegerValue] != j) { ordered = NO; break; }
        }
        if (!ordered) continue;
        uint64_t first = [window.firstObject[@"fileOffset"] unsignedLongLongValue];
        uint64_t last = [window.lastObject[@"fileOffset"] unsignedLongLongValue];
        if (last < first || last - first > kHFADSCMaxClusterSpan) continue;
        [clusters addObject:window];
        if (clusters.count > 1) return nil; // ambiguous cluster fails closed
    }
    return clusters.count == 1 ? clusters.firstObject : nil;
}

static NSDictionary *HFADSCMethodMatch(NSDictionary *method,
                                       NSDictionary *descriptor,
                                       NSString *confidence,
                                       NSArray *evidence,
                                       NSDictionary *pointerSite) {
    NSMutableDictionary *match = [NSMutableDictionary dictionary];
    match[@"schema"] = @"com.hfa.descriptor-static-callback/v1";
    match[@"status"] = @"matched";
    match[@"confidence"] = confidence ?: @"unknown";
    match[@"featureDescriptor"] = descriptor ?: @{};
    match[@"callbackRVA"] = method[@"callbackRVA"] ?: @0;
    match[@"callbackRVAHex"] = method[@"callbackRVAHex"] ?: @"";
    match[@"staticRuntimeMethod"] = method ?: @{};
    match[@"evidence"] = evidence ?: @[];
    if (pointerSite) match[@"callbackPointerSite"] = pointerSite;
    match[@"association"] = @"descriptor-to-static-callback-provenance";
    match[@"analysisOnly"] = @YES;
    match[@"canonicalEligible"] = @NO;
    match[@"callbackInvoked"] = @NO;
    match[@"selectorInvoked"] = @NO;
    match[@"memoryWritten"] = @NO;
    return match;
}

NSDictionary *HFAMapResolveDescriptorStaticCallbacks(NSDictionary *handlerGraph,
                                                      NSArray<NSDictionary *> *registry,
                                                      NSString *loadedImage) {
    if (![handlerGraph isKindOfClass:NSDictionary.class]) return @{};
    NSDictionary *catalog = HFAMapStaticCatalogCurrent();
    NSMutableDictionary *out = [handlerGraph mutableCopy];
    out[@"descriptorStaticCallbackSchema"] = @"com.hfa.descriptor-static-callback/v1";
    out[@"descriptorStaticCallbackPolicy"] = @"exact-descriptor-token-or-unique-ordered-pointer-cluster-fail-closed";
    out[@"descriptorStaticCallbackGenericity"] = @"no-game-name-no-feature-name-no-method-name-no-fixed-rva";
    if (!catalog || !loadedImage.length) {
        out[@"descriptorStaticCallbackStatus"] = @"no-static-catalog";
        out[@"descriptorStaticCallbackMatchCount"] = @0;
        return [out autorelease];
    }

    NSString *catalogImage = [catalog valueForKeyPath:@"source.fileName"] ?: @"";
    if (![catalogImage isEqualToString:loadedImage]) {
        out[@"descriptorStaticCallbackStatus"] = @"catalog-image-mismatch";
        out[@"descriptorStaticCallbackMatchCount"] = @0;
        return [out autorelease];
    }

    NSArray *catalogMethods = catalog[@"runtimeMethods"] ?: @[];
    NSMutableArray *methods = [NSMutableArray array];
    for (NSDictionary *method in catalogMethods) {
        if (methods.count >= kHFADSCMaxMethods) break;
        uint64_t rva = [method[@"callbackRVA"] unsignedLongLongValue];
        if (!rva || !HFAMapStaticCatalogLookup(loadedImage, rva)) continue; // includes UUID verification
        [methods addObject:method];
    }

    NSMutableArray *records = [NSMutableArray array];
    NSMutableArray *unmatchedFeatureIndexes = [NSMutableArray array];
    NSMutableIndexSet *usedMethods = [NSMutableIndexSet indexSet];
    NSUInteger matchCount = 0, tokenMatchCount = 0, orderedMatchCount = 0;

    NSArray *inputRecords = handlerGraph[@"records"] ?: @[];
    for (NSUInteger i = 0; i < inputRecords.count && i < kHFADSCMaxFeatures; ++i) {
        NSDictionary *record = inputRecords[i];
        NSMutableDictionary *recordOut = [record mutableCopy];
        NSDictionary *descriptor = HFADSCExactDescriptor(record);
        NSDictionary *registryRecord = HFADSCRegistryRecord(registry, record[@"label"] ?: @"");
        BOOL canonicalStatic = [registryRecord[@"canonicalEligible"] boolValue] &&
                               [registryRecord[@"canonicalPatchCount"] unsignedIntegerValue] > 0;
        if (descriptor && !canonicalStatic) {
            NSInteger uniqueMethod = -1;
            for (NSUInteger m = 0; m < methods.count; ++m) {
                if ([usedMethods containsIndex:m]) continue;
                if (!HFADSCTokenMatchesMethod(descriptor, methods[m])) continue;
                if (uniqueMethod >= 0) { uniqueMethod = -2; break; }
                uniqueMethod = (NSInteger)m;
            }
            if (uniqueMethod >= 0) {
                NSDictionary *match = HFADSCMethodMatch(methods[(NSUInteger)uniqueMethod], descriptor, @"high",
                    @[@"exact-feature-descriptor", @"unique-descriptor-token-xref-in-static-method",
                      @"static-catalog-image-match", @"static-catalog-uuid-validated"], nil);
                recordOut[@"descriptorStaticCallbackMatch"] = match;
                [usedMethods addIndex:(NSUInteger)uniqueMethod];
                ++matchCount; ++tokenMatchCount;
            } else {
                [unmatchedFeatureIndexes addObject:@(i)];
            }
        }
        [records addObject:recordOut];
        [recordOut release];
    }

    // Fallback: correlate remaining exact non-canonical descriptors with one unique
    // ordered static callback pointer cluster. This only fires when the runtime
    // descriptors share one array parent and expose strictly increasing indices.
    NSMutableArray *remainingMethods = [NSMutableArray array];
    NSMutableArray *remainingMethodOriginalIndexes = [NSMutableArray array];
    for (NSUInteger m = 0; m < methods.count; ++m) {
        if (![usedMethods containsIndex:m]) {
            [remainingMethods addObject:methods[m]];
            [remainingMethodOriginalIndexes addObject:@(m)];
        }
    }

    if (unmatchedFeatureIndexes.count > 0 && unmatchedFeatureIndexes.count == remainingMethods.count) {
        NSString *commonParent = nil;
        NSInteger previousIndex = -1;
        BOOL orderedDescriptors = YES;
        NSMutableArray *descriptorInfo = [NSMutableArray array];
        for (NSNumber *featureNumber in unmatchedFeatureIndexes) {
            NSUInteger featureIndex = featureNumber.unsignedIntegerValue;
            NSDictionary *descriptor = HFADSCExactDescriptor(inputRecords[featureIndex]);
            NSString *parent = nil; NSInteger index = -1;
            if (!descriptor || !HFADSCParseArrayPath(descriptor[@"objectPath"], &parent, &index)) {
                orderedDescriptors = NO; break;
            }
            if (!commonParent) commonParent = parent;
            else if (![commonParent isEqualToString:parent]) { orderedDescriptors = NO; break; }
            if (previousIndex >= 0 && index <= previousIndex) { orderedDescriptors = NO; break; }
            previousIndex = index;
            [descriptorInfo addObject:@{ @"descriptor": descriptor, @"arrayIndex": @(index),
                                         @"parentPath": parent ?: @"" }];
        }

        NSString *path = [catalog valueForKeyPath:@"source.path"];
        NSData *data = orderedDescriptors && path.length
            ? [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil] : nil;
        NSArray *cluster = data ? HFADSCUniqueOrderedCluster(remainingMethods, data, catalog[@"source"] ?: @{}) : nil;
        if (orderedDescriptors && cluster.count == remainingMethods.count) {
            for (NSUInteger j = 0; j < unmatchedFeatureIndexes.count; ++j) {
                NSUInteger featureIndex = [unmatchedFeatureIndexes[j] unsignedIntegerValue];
                NSMutableDictionary *recordOut = [records[featureIndex] mutableCopy];
                NSDictionary *descriptor = descriptorInfo[j][@"descriptor"];
                NSDictionary *method = remainingMethods[j];
                NSDictionary *site = @{ @"sliceRelativeFileOffset": cluster[j][@"fileOffset"] ?: @0,
                                         @"descriptorArrayIndex": descriptorInfo[j][@"arrayIndex"] ?: @0,
                                         @"descriptorArrayParentPath": descriptorInfo[j][@"parentPath"] ?: @"" };
                NSDictionary *match = HFADSCMethodMatch(method, descriptor, @"medium",
                    @[@"exact-feature-descriptor", @"registry-noncanonical-feature",
                      @"same-parent-strictly-increasing-descriptor-array-indices",
                      @"unique-ordered-static-callback-pointer-cluster",
                      @"equal-unmatched-feature-and-static-method-count",
                      @"static-catalog-uuid-validated"], site);
                recordOut[@"descriptorStaticCallbackMatch"] = match;
                records[featureIndex] = recordOut;
                [recordOut release];
                ++matchCount; ++orderedMatchCount;
            }
        }
    }

    out[@"records"] = records;
    out[@"descriptorStaticCallbackStatus"] = matchCount ? @"matched" : @"unresolved";
    out[@"descriptorStaticCallbackMatchCount"] = @(matchCount);
    out[@"descriptorStaticCallbackTokenMatchCount"] = @(tokenMatchCount);
    out[@"descriptorStaticCallbackOrderedClusterMatchCount"] = @(orderedMatchCount);
    out[@"descriptorStaticCallbackMethodCandidateCount"] = @(methods.count);
    out[@"descriptorStaticCallbackAnalysisOnly"] = @YES;
    out[@"descriptorStaticCallbackCanonicalEligible"] = @NO;
    return [out autorelease];
}
