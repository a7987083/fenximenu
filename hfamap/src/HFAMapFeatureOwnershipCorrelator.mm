#import "HFAMapFeatureOwnershipCorrelator.h"
#import "HFAMapStrippedActionAnalyzer.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>

static uintptr_t HFAPointerFromHex(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return 0;
    return (uintptr_t)strtoull(value.UTF8String, NULL, 0);
}

static NSArray *HFABlocksFromFields(NSArray *fields, NSString *ownerToken, NSString *edgeKind) {
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *field in fields ?: @[]) {
        NSDictionary *block = field[@"blockEvidence"];
        if (![block isKindOfClass:NSDictionary.class]) continue;
        NSMutableDictionary *e = [block mutableCopy];
        e[@"ownership"] = @{ @"ownerToken": ownerToken ?: @"",
                              @"edgeKind": edgeKind ?: @"",
                              @"fieldName": field[@"name"] ?: @"",
                              @"fieldOffset": field[@"offset"] ?: @"" };
        e[@"ownershipVerified"] = @YES;
        [out addObject:e];
        [e release];
    }
    return out;
}

static NSArray *HFADedupBlocks(NSArray *blocks) {
    NSMutableArray *out = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];
    for (NSDictionary *b in blocks ?: @[]) {
        NSString *token = b[@"token"] ?: @"";
        NSString *owner = b[@"ownership"][@"ownerToken"] ?: @"";
        NSString *field = b[@"ownership"][@"fieldName"] ?: @"";
        NSString *key = [NSString stringWithFormat:@"%@|%@|%@", token, owner, field];
        if ([seen containsObject:key]) continue;
        [seen addObject:key];
        [out addObject:b];
    }
    return out;
}

static NSDictionary *HFAAnalyzeActionRecord(NSDictionary *action, NSString *menuPath) {
    NSDictionary *impl = action[@"implementation"] ?: @{};
    NSString *runtimeVA = impl[@"runtimeVA"] ?: @"";
    uintptr_t pointer = HFAPointerFromHex(runtimeVA);
    NSDictionary *analysis = pointer ? HFAMapAnalyzeStrippedActionIMP((const void *)pointer, menuPath) : @{};
    return @{ @"event": action[@"event"] ?: @"",
              @"selector": action[@"selector"] ?: @"",
              @"targetToken": action[@"targetToken"] ?: @"",
              @"targetClass": action[@"targetClass"] ?: @"",
              @"implementation": impl,
              @"analysis": analysis ?: @{},
              @"analysisOnly": @YES,
              @"invokedByAnalyzer": @NO };
}

NSDictionary *HFAMapCorrelateFeatureOwnership(NSString *loadedMenuPath,
                                               NSDictionary *featureInventory,
                                               NSError **error) {
    if (![featureInventory isKindOfClass:NSDictionary.class]) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.feature-ownership" code:1
                                             userInfo:@{NSLocalizedDescriptionKey:@"missing-feature-inventory"}];
        return nil;
    }
    NSArray *controls = featureInventory[@"controls"] ?: @[];
    NSArray *nodes = featureInventory[@"objectGraph"][@"nodes"] ?: @[];
    NSArray *features = featureInventory[@"featureCandidates"] ?: @[];
    NSMutableDictionary *controlByToken = [NSMutableDictionary dictionary];
    NSMutableDictionary *nodeByToken = [NSMutableDictionary dictionary];
    for (NSDictionary *c in controls) if ([c[@"controlToken"] length]) controlByToken[c[@"controlToken"]] = c;
    for (NSDictionary *n in nodes) if ([n[@"token"] length]) nodeByToken[n[@"token"]] = n;

    NSMutableArray *resolved = [NSMutableArray array];
    NSUInteger exactBlockFeatureCount = 0;
    NSUInteger actionAnalysisCount = 0;
    NSUInteger editingActionCount = 0;
    for (NSDictionary *feature in features) {
        NSMutableArray *exactBlocks = [NSMutableArray array];
        NSMutableArray *actionAnalyses = [NSMutableArray array];
        NSMutableArray *ownershipEdges = [NSMutableArray array];
        for (NSDictionary *controlRef in feature[@"controls"] ?: @[]) {
            NSString *controlToken = controlRef[@"token"] ?: @"";
            NSDictionary *control = controlByToken[controlToken] ?: @{};
            NSArray *direct = HFABlocksFromFields(control[@"objectFields"], controlToken, @"feature-control-ivar");
            [exactBlocks addObjectsFromArray:direct];
            for (NSDictionary *b in direct)
                [ownershipEdges addObject:@{ @"fromFeature": feature[@"title"] ?: @"",
                                              @"fromToken": controlToken,
                                              @"toBlock": b[@"token"] ?: @"",
                                              @"kind": @"feature-control-ivar" }];
            for (NSDictionary *action in controlRef[@"actions"] ?: @[]) {
                [actionAnalyses addObject:HFAAnalyzeActionRecord(action, loadedMenuPath)];
                ++actionAnalysisCount;
                if ([action[@"event"] isEqualToString:@"editing-changed"]) ++editingActionCount;
                NSString *targetToken = action[@"targetToken"] ?: @"";
                NSDictionary *targetNode = nodeByToken[targetToken] ?: @{};
                NSArray *targetBlocks = HFABlocksFromFields(targetNode[@"fields"], targetToken, @"exact-action-target-ivar");
                [exactBlocks addObjectsFromArray:targetBlocks];
                for (NSDictionary *b in targetBlocks)
                    [ownershipEdges addObject:@{ @"fromFeature": feature[@"title"] ?: @"",
                                                  @"fromToken": targetToken,
                                                  @"toBlock": b[@"token"] ?: @"",
                                                  @"kind": @"exact-action-target-ivar" }];
            }
        }
        NSArray *dedupBlocks = HFADedupBlocks(exactBlocks);
        if (dedupBlocks.count) ++exactBlockFeatureCount;
        NSString *mechanism = dedupBlocks.count ? @"exact-block-callback" :
                              actionAnalyses.count ? @"exact-action-dataflow" : @"ui-only-unresolved";
        [resolved addObject:@{ @"title": feature[@"title"] ?: @"",
                               @"normalizedTitle": feature[@"normalizedTitle"] ?: @"",
                               @"identifiers": feature[@"identifiers"] ?: @[],
                               @"mechanismClass": mechanism,
                               @"exactOwnedBlocks": dedupBlocks,
                               @"ownershipEdges": ownershipEdges,
                               @"actionAnalyses": actionAnalyses,
                               @"nearbyBlocksExcluded": @YES,
                               @"analysisOnly": @YES,
                               @"canonicalEligible": @NO }];
    }
    NSDictionary *result = @{
        @"schema": @"com.hfa.feature-ownership/v1",
        @"buildVersion": @"2.5.14-dev",
        @"componentVersion": @"2.5.14-dev-feature-ownership-correlator",
        @"policy": @"EXACT-OBJECT-EDGE-ONLY-NO-NEARBY-BLOCK-PROPAGATION",
        @"menuImage": loadedMenuPath.lastPathComponent ?: @"",
        @"menuPath": loadedMenuPath ?: @"",
        @"summary": @{ @"featureCount": @(resolved.count),
                        @"exactBlockFeatureCount": @(exactBlockFeatureCount),
                        @"actionAnalysisCount": @(actionAnalysisCount),
                        @"editingChangedActionCount": @(editingActionCount) },
        @"features": resolved,
        @"correlationRules": @{ @"controlIvarEdgeAccepted": @YES,
                                 @"exactActionTargetIvarEdgeAccepted": @YES,
                                 @"nearbySuperviewBlockRejected": @YES,
                                 @"sharedGraphBlockWithoutEdgeRejected": @YES,
                                 @"actionIMPAnalyzedStatically": @YES },
        @"safety": @{ @"unknownSelectorInvoked": @NO,
                       @"blockInvoked": @NO,
                       @"actionInvoked": @NO,
                       @"impReplaced": @NO,
                       @"inlineHookInstalled": @NO,
                       @"memoryWritten": @NO,
                       @"gameStateWritten": @NO }
    };
    HFADiagnosticsLog(@"feature-ownership-correlator", @"complete", result[@"summary"]);
    return result;
}

BOOL HFAMapPersistFeatureOwnership(NSDictionary *result, NSError **error) {
    if (!result) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"FeatureOwnership.json")];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}

static void HFAOwnershipProcessPersistedInventory(void) {
    static NSString *lastDigest;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *inventoryPath = [documents stringByAppendingPathComponent:HFAOutputFileName(@"LoadedMenuFeatureInventory.json")];
    NSData *data = [NSData dataWithContentsOfFile:inventoryPath];
    if (!data.length) return;
    NSString *digest = [NSString stringWithFormat:@"%lu:%@", (unsigned long)data.length,
                         [[[NSFileManager defaultManager] attributesOfItemAtPath:inventoryPath error:nil] fileModificationDate] ?: @""];
    if ([digest isEqualToString:lastDigest]) return;
    NSDictionary *inventory = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![inventory isKindOfClass:NSDictionary.class]) return;
    NSString *menuPath = inventory[@"menuPath"] ?: @"";
    if (!menuPath.length) return;
    NSError *error = nil;
    NSDictionary *ownership = HFAMapCorrelateFeatureOwnership(menuPath, inventory, &error);
    if (!ownership) {
        HFADiagnosticsLog(@"feature-ownership-correlator", @"failed", @{ @"error": error.localizedDescription ?: @"unknown" });
        return;
    }
    if (HFAMapPersistFeatureOwnership(ownership, &error)) {
        [lastDigest release];
        lastDigest = [digest copy];
        HFADiagnosticsLog(@"feature-ownership-correlator", @"persisted", ownership[@"summary"] ?: @{});
    }
}

static void HFAOwnershipSchedulePoll(void) {
    static dispatch_source_t timer;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
        timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                                  (uint64_t)(1.0 * NSEC_PER_SEC), (uint64_t)(0.1 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(timer, ^{ HFAOwnershipProcessPersistedInventory(); });
        dispatch_resume(timer);
    });
}

__attribute__((constructor)) static void HFAFeatureOwnershipConstructor(void) {
    HFAOwnershipSchedulePoll();
}
