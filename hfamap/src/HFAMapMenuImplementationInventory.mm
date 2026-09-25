#import "HFAMapMenuImplementationInventory.h"
#import "HFAMapStrippedActionAnalyzer.h"
#import "HFAMapOutputName.h"

#include <stdint.h>

static const NSUInteger kHFAImplementationMaxActionsPerFeature = 16;
static const NSUInteger kHFAImplementationMaxEvidenceDepth = 10;

static NSString *HFAImplementationNormalize(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return @"";
    NSString *lower = value.lowercaseString;
    NSCharacterSet *allowed = NSCharacterSet.alphanumericCharacterSet;
    NSMutableString *result = [NSMutableString string];
    for (NSUInteger i = 0; i < lower.length; ++i) {
        unichar c = [lower characterAtIndex:i];
        if ([allowed characterIsMember:c]) [result appendFormat:@"%C", c];
    }
    return result;
}

static BOOL HFAImplementationParsePointer(id token, uint64_t *valueOut) {
    if (![token isKindOfClass:NSString.class]) return NO;
    NSString *text = (NSString *)token;
    if (![text hasPrefix:@"0x"] || text.length <= 2) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:[text substringFromIndex:2]];
    unsigned long long value = 0;
    if (![scanner scanHexLongLong:&value] || !scanner.isAtEnd || !value) return NO;
    if (valueOut) *valueOut = value;
    return YES;
}

static void HFAImplementationCollectRuntimeMethods(id node,
                                                   NSUInteger depth,
                                                   NSMutableArray *records,
                                                   NSMutableSet *seen,
                                                   NSDictionary *actionContext) {
    if (!node || depth > kHFAImplementationMaxEvidenceDepth) return;
    if ([node isKindOfClass:NSDictionary.class]) {
        NSDictionary *dict = (NSDictionary *)node;
        NSString *pointer = [dict[@"methodPointerToken"] isKindOfClass:NSString.class] ? dict[@"methodPointerToken"] : nil;
        NSString *klass = [dict[@"class"] isKindOfClass:NSString.class] ? dict[@"class"] : nil;
        NSString *method = [dict[@"method"] isKindOfClass:NSString.class] ? dict[@"method"] : nil;
        if (pointer.length && klass.length && method.length) {
            NSString *key = [NSString stringWithFormat:@"%@|%@|%@", pointer, klass, method];
            if (![seen containsObject:key]) {
                [seen addObject:key];
                NSMutableDictionary *record = [dict mutableCopy];
                record[@"implementationKind"] = @"runtime-method";
                record[@"evidenceSource"] = @"menu-action-il2cpp-correlation";
                record[@"confidence"] = [dict[@"matchType"] isEqualToString:@"exact-method-entry"]
                    ? @"exact-method-pointer" : @"containing-method-range";
                if (actionContext.count) record[@"actionContext"] = actionContext;
                record[@"analysisOnly"] = @YES;
                record[@"canonicalEligible"] = @NO;
                [records addObject:record];
                [record release];
            }
        }
        for (id key in dict)
            HFAImplementationCollectRuntimeMethods(dict[key], depth + 1, records, seen, actionContext);
    } else if ([node isKindOfClass:NSArray.class]) {
        for (id value in (NSArray *)node)
            HFAImplementationCollectRuntimeMethods(value, depth + 1, records, seen, actionContext);
    }
}

static NSArray *HFAImplementationCanonicalPatches(NSArray<NSDictionary *> *features) {
    NSMutableArray *records = [NSMutableArray array];
    for (NSDictionary *feature in features ?: @[]) {
        if (![feature isKindOfClass:NSDictionary.class] ||
            ![feature[@"canonicalEligible"] boolValue] ||
            ![feature[@"confidence"] isEqualToString:@"byte-validated"]) continue;
        NSString *title = [feature[@"name"] isKindOfClass:NSString.class] ? feature[@"name"] : @"";
        NSString *identifier = [feature[@"identifier"] isKindOfClass:NSString.class] ? feature[@"identifier"] : @"";
        NSString *target = [feature[@"targetImage"] isKindOfClass:NSString.class] ? feature[@"targetImage"] : @"";
        NSString *offset = [feature[@"offset"] isKindOfClass:NSString.class] ? feature[@"offset"] : @"";
        NSString *original = [feature[@"original"] isKindOfClass:NSString.class] ? feature[@"original"] : @"";
        NSString *patch = [feature[@"patch"] isKindOfClass:NSString.class] ? feature[@"patch"] : @"";
        if (!title.length || !target.length || !offset.length || !original.length || !patch.length) continue;
        [records addObject:@{
            @"implementationKind": @"memory-patch",
            @"title": title,
            @"normalizedTitle": HFAImplementationNormalize(title),
            @"identifier": identifier,
            @"targetImage": target,
            @"offset": offset,
            @"original": original,
            @"patch": patch,
            @"confidence": @"byte-validated",
            @"canonicalEligible": @YES,
            @"evidenceSource": @"deep-analyze-menu-canonical-feature"
        }];
    }
    return records;
}

static NSArray *HFAImplementationPatchesForFeature(NSDictionary *feature, NSArray *patches) {
    NSString *title = HFAImplementationNormalize(feature[@"title"]);
    NSArray *identifiers = [feature[@"identifiers"] isKindOfClass:NSArray.class] ? feature[@"identifiers"] : @[];
    NSMutableSet *ids = [NSMutableSet set];
    for (id identifier in identifiers)
        if ([identifier isKindOfClass:NSString.class]) [ids addObject:identifier];
    NSMutableArray *matches = [NSMutableArray array];
    for (NSDictionary *patch in patches) {
        BOOL titleMatch = title.length && [title isEqualToString:patch[@"normalizedTitle"]];
        BOOL idMatch = [patch[@"identifier"] length] && [ids containsObject:patch[@"identifier"]];
        if (titleMatch || idMatch) [matches addObject:patch];
    }
    return matches;
}

static NSDictionary *HFAImplementationDirectedEvidence(NSDictionary *feature, NSDictionary *directed) {
    NSString *normalized = HFAImplementationNormalize(feature[@"title"]);
    for (NSDictionary *entry in directed[@"featureResolutions"] ?: @[]) {
        NSString *candidate = HFAImplementationNormalize(entry[@"title"] ?: entry[@"featureTitle"] ?: @"");
        if (normalized.length && [normalized isEqualToString:candidate]) return entry;
    }
    return @{};
}

NSDictionary *HFAMapBuildMenuImplementationInventory(NSString *menuPath,
                                                       NSDictionary *featureInventory,
                                                       NSDictionary *directedDescriptors,
                                                       NSDictionary *secretWrapperEvidence,
                                                       NSArray<NSDictionary *> *canonicalPatchFeatures,
                                                       NSError **error) {
    if (error) *error = nil;
    if (!menuPath.length || ![featureInventory isKindOfClass:NSDictionary.class]) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.menu-implementation-inventory" code:1
                                             userInfo:@{NSLocalizedDescriptionKey:@"missing-menu-path-or-feature-inventory"}];
        return nil;
    }

    NSArray *patchRecords = HFAImplementationCanonicalPatches(canonicalPatchFeatures);
    NSMutableArray *featureRecords = [NSMutableArray array];
    NSUInteger runtimeMethodCount = 0, patchCount = 0, mutationCandidateCount = 0;

    for (NSDictionary *feature in featureInventory[@"featureCandidates"] ?: @[]) {
        if (![feature isKindOfClass:NSDictionary.class]) continue;
        NSMutableArray *runtimeMethods = [NSMutableArray array];
        NSMutableSet *runtimeSeen = [NSMutableSet set];
        NSMutableArray *actionEvidence = [NSMutableArray array];
        NSUInteger actionBudget = kHFAImplementationMaxActionsPerFeature;

        for (NSDictionary *control in feature[@"controls"] ?: @[]) {
            for (NSDictionary *action in control[@"actions"] ?: @[]) {
                if (!actionBudget--) break;
                NSDictionary *implementationRecord = action[@"implementation"];
                uint64_t implementation = 0;
                if (!HFAImplementationParsePointer(implementationRecord[@"runtimeVA"], &implementation)) continue;
                NSDictionary *actionContext = @{
                    @"event": action[@"event"] ?: @"",
                    @"selector": action[@"selector"] ?: @"",
                    @"targetClass": action[@"targetClass"] ?: @"",
                    @"targetToken": action[@"targetToken"] ?: @"",
                    @"senderToken": control[@"token"] ?: @"",
                    @"implementation": implementationRecord ?: @{}
                };
                NSDictionary *analysis = HFAMapAnalyzeStrippedActionIMP((const void *)(uintptr_t)implementation, menuPath) ?: @{};
                NSUInteger before = runtimeMethods.count;
                HFAImplementationCollectRuntimeMethods(analysis, 0, runtimeMethods, runtimeSeen, actionContext);
                [actionEvidence addObject:@{
                    @"context": actionContext,
                    @"runtimeMethodCorrelationCount": @(runtimeMethods.count - before),
                    @"analyzerIL2CPPCorrelationCount": analysis[@"il2cppCorrelationCount"] ?: @0,
                    @"decodedInstructionCount": analysis[@"decodedInstructionCount"] ?: @0,
                    @"blockCount": analysis[@"blockCount"] ?: @0,
                    @"callCount": analysis[@"callCount"] ?: @0,
                    @"status": analysis[@"status"] ?: @"unknown"
                }];
            }
        }

        NSArray *featurePatches = HFAImplementationPatchesForFeature(feature, patchRecords);
        NSDictionary *directedEvidence = HFAImplementationDirectedEvidence(feature, directedDescriptors ?: @{});
        BOOL mutationCandidate = featurePatches.count == 0 && runtimeMethods.count == 0 && actionEvidence.count > 0;
        NSMutableArray *kinds = [NSMutableArray array];
        if (featurePatches.count) [kinds addObject:@"memory-patch"];
        if (runtimeMethods.count) [kinds addObject:@"runtime-method"];
        if (mutationCandidate) [kinds addObject:@"state-mutation-candidate"];
        if (!kinds.count) [kinds addObject:@"unresolved"];

        runtimeMethodCount += runtimeMethods.count;
        patchCount += featurePatches.count;
        if (mutationCandidate) ++mutationCandidateCount;
        [featureRecords addObject:@{
            @"title": feature[@"title"] ?: @"",
            @"normalizedTitle": feature[@"normalizedTitle"] ?: HFAImplementationNormalize(feature[@"title"]),
            @"identifiers": feature[@"identifiers"] ?: @[],
            @"mechanismClass": feature[@"mechanismClass"] ?: @"unknown",
            @"mechanismEvidence": feature[@"mechanismEvidence"] ?: @[],
            @"implementationKinds": kinds,
            @"memoryPatches": featurePatches,
            @"runtimeMethods": runtimeMethods,
            @"stateMutationCandidates": mutationCandidate ? actionEvidence : @[],
            @"actionEvidence": actionEvidence,
            @"directedDescriptorEvidence": directedEvidence,
            @"secretWrapperEvidenceAvailable": @([secretWrapperEvidence[@"wrapperEvidenceCount"] unsignedIntegerValue] > 0),
            @"analysisOnly": @YES
        }];
    }

    NSMutableSet *coveredPatchTitles = [NSMutableSet set];
    for (NSDictionary *feature in featureRecords)
        if ([feature[@"memoryPatches"] count]) [coveredPatchTitles addObject:HFAImplementationNormalize(feature[@"title"])];
    for (NSDictionary *patch in patchRecords) {
        if ([coveredPatchTitles containsObject:patch[@"normalizedTitle"]]) continue;
        [coveredPatchTitles addObject:patch[@"normalizedTitle"]];
        [featureRecords addObject:@{
            @"title": patch[@"title"] ?: @"", @"normalizedTitle": patch[@"normalizedTitle"] ?: @"",
            @"identifiers": [patch[@"identifier"] length] ? @[patch[@"identifier"]] : @[],
            @"mechanismClass": @"memory-patch", @"mechanismEvidence": @[@"deep-analyze-menu-canonical-feature"],
            @"implementationKinds": @[@"memory-patch"], @"memoryPatches": @[patch], @"runtimeMethods": @[],
            @"stateMutationCandidates": @[], @"actionEvidence": @[], @"directedDescriptorEvidence": @{},
            @"secretWrapperEvidenceAvailable": @NO, @"analysisOnly": @YES
        }];
    }

    return @{
        @"schema": @"com.hfa.menu-implementation-inventory/v1",
        @"buildVersion": @"2.5.20-dev",
        @"componentVersion": @"2.5.20-dev-menu-implementation-inventory",
        @"status": @"complete",
        @"menuPath": menuPath, @"menuImage": menuPath.lastPathComponent ?: @"",
        @"features": featureRecords,
        @"summary": @{
            @"featureCount": @(featureRecords.count), @"memoryPatchCount": @(patchCount),
            @"runtimeMethodCount": @(runtimeMethodCount), @"stateMutationCandidateCount": @(mutationCandidateCount),
            @"canonicalPatchInputCount": @(canonicalPatchFeatures.count),
            @"loadedFeatureInputCount": @([featureInventory[@"featureCandidates"] count])
        },
        @"classificationPolicy": @{
            @"memoryPatch": @"existing-deep-analyze-byte-validated-canonical-feature",
            @"runtimeMethod": @"menu-action-call-or-branch-correlated-to-il2cpp-method-index",
            @"stateMutationCandidate": @"feature-has-action-evidence-but-no-canonical-patch-or-il2cpp-method-proof"
        },
        @"referenceIntegration": @[
            @"loaded-menu-feature-inventory-target-action-object-graph",
            @"verify-inspired-callback-and-runtime-object-relationship",
            @"vipcrack-inspired-objc-ownership-fingerprint",
            @"h5gg-inspired-method-pointer-to-native-method-range-index",
            @"existing-deep-analyze-menu-canonical-patch-export"
        ],
        @"safety": @{
            @"readOnly": @YES, @"selectorInvoked": @NO, @"blockInvoked": @NO,
            @"hookInstalled": @NO, @"memoryWritten": @NO,
            @"stateMutationCandidateIsNotProofOfWrite": @YES
        }
    };
}

BOOL HFAMapPersistMenuImplementationInventory(NSDictionary *inventory, NSError **error) {
    if (error) *error = nil;
    if (![inventory isKindOfClass:NSDictionary.class]) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"MenuImplementationInventory.json")];
    NSData *data = [NSJSONSerialization dataWithJSONObject:inventory options:NSJSONWritingPrettyPrinted error:error];
    return data && [data writeToFile:path options:NSDataWritingAtomic error:error];
}
