#import "HFAMapFeatureDispatcherSliceResolver.h"
#import "HFAIL2CPPMethodIndex.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>

static uintptr_t HFASliceParseAddress(id value) {
    if ([value isKindOfClass:NSNumber.class]) return (uintptr_t)[value unsignedLongLongValue];
    if ([value isKindOfClass:NSString.class] && [value length]) return (uintptr_t)strtoull([value UTF8String], NULL, 0);
    return 0;
}

static BOOL HFASliceEntryDerivedArg(NSDictionary *arg) {
    return [arg isKindOfClass:NSDictionary.class] && [arg[@"entryDerived"] boolValue];
}

static NSString *HFASliceTargetKey(NSDictionary *target) {
    if (![target isKindOfClass:NSDictionary.class]) return @"";
    NSString *image = target[@"image"] ?: @"";
    NSString *offset = target[@"offsetFromLoadBase"] ?: @"";
    uintptr_t runtime = HFASliceParseAddress(target[@"runtimeVA"] ?: target[@"runtimeVAHex"]);
    if (image.length || offset.length) return [NSString stringWithFormat:@"%@|%@", image, offset];
    return runtime ? [NSString stringWithFormat:@"0x%llX", (unsigned long long)runtime] : @"";
}

static NSDictionary *HFASliceIL2CPP(uintptr_t runtime) {
    if (!runtime) return @{};
    NSDictionary *exact = HFAIL2CPPMethodForRuntimeAddress((const void *)runtime);
    if (exact) {
        NSMutableDictionary *r = [[exact mutableCopy] autorelease];
        r[@"matchType"] = @"exact-method-pointer";
        return r;
    }
    NSDictionary *containing = HFAIL2CPPMethodContainingRuntimeAddress((const void *)runtime);
    if (containing) {
        NSMutableDictionary *r = [[containing mutableCopy] autorelease];
        if (!r[@"matchType"]) r[@"matchType"] = @"containing-method-range";
        return r;
    }
    return @{};
}

NSDictionary *HFAMapBuildFeatureDispatcherSlices(NSDictionary *featureBranchProvenance, NSError **error) {
    if (![featureBranchProvenance isKindOfClass:NSDictionary.class]) {
        if (error) *error = [NSError errorWithDomain:@"com.hfa.feature-dispatcher-slice" code:1 userInfo:@{NSLocalizedDescriptionKey:@"missing-feature-branch-provenance"}];
        return nil;
    }

    NSArray *features = featureBranchProvenance[@"features"] ?: @[];
    NSMutableDictionary *targetFeatures = [NSMutableDictionary dictionary];
    NSMutableArray *firstPass = [NSMutableArray array];

    for (NSDictionary *feature in features) {
        NSString *title = feature[@"title"] ?: @"";
        NSMutableArray *calls = [NSMutableArray array];
        NSMutableArray *branches = [NSMutableArray array];
        NSMutableSet *seenTargetsForFeature = [NSMutableSet set];

        for (NSDictionary *action in feature[@"actionProvenance"] ?: @[]) {
            NSDictionary *prov = action[@"entrySeededProvenance"] ?: @{};
            NSDictionary *impl = action[@"implementation"] ?: @{};
            NSString *selector = action[@"selector"] ?: @"";
            NSString *event = action[@"event"] ?: @"";
            NSString *senderToken = prov[@"entryContext"][@"senderToken"] ?: @"";

            for (NSDictionary *call in prov[@"calls"] ?: @[]) {
                if ([call[@"entryDerivedArgumentCount"] unsignedIntegerValue] == 0) continue;
                NSDictionary *args = call[@"arguments"] ?: @{};
                BOOL senderBound = HFASliceEntryDerivedArg(args[@"x2"]);
                BOOL targetBound = HFASliceEntryDerivedArg(args[@"x0"]);
                BOOL selectorBound = HFASliceEntryDerivedArg(args[@"x1"]);
                NSDictionary *target = call[@"target"] ?: @{};
                NSString *targetKey = HFASliceTargetKey(target);
                uintptr_t runtime = HFASliceParseAddress(target[@"runtimeVA"] ?: target[@"runtimeVAHex"]);
                if (!targetKey.length) continue;

                if (![seenTargetsForFeature containsObject:targetKey]) {
                    [seenTargetsForFeature addObject:targetKey];
                    NSMutableSet *users = targetFeatures[targetKey];
                    if (![users isKindOfClass:NSMutableSet.class]) {
                        users = [NSMutableSet set];
                        targetFeatures[targetKey] = users;
                    }
                    [users addObject:title.length ? title : @"<untitled>"];
                }

                NSMutableDictionary *record = [@{
                    @"selector": selector,
                    @"event": event,
                    @"senderToken": senderToken,
                    @"implementation": impl,
                    @"kind": call[@"kind"] ?: @"",
                    @"callsiteRVA": call[@"callsiteRVA"] ?: @0,
                    @"target": target,
                    @"targetKey": targetKey,
                    @"arguments": args,
                    @"entryDerivedArgumentCount": call[@"entryDerivedArgumentCount"] ?: @0,
                    @"senderBound": @(senderBound),
                    @"targetBound": @(targetBound),
                    @"selectorBound": @(selectorBound),
                    @"binding": senderBound ? @"feature-sender-x2" : @"entry-derived-argument",
                    @"analysisOnly": @YES,
                    @"canonicalEligible": @NO
                } mutableCopy];
                NSDictionary *method = HFASliceIL2CPP(runtime);
                if (method.count) record[@"il2cppMethod"] = method;
                [calls addObject:[record autorelease]];
            }

            for (NSDictionary *branch in prov[@"branches"] ?: @[]) {
                if (![branch[@"entryDerived"] boolValue]) continue;
                [branches addObject:@{
                    @"selector": selector,
                    @"event": event,
                    @"senderToken": senderToken,
                    @"implementation": impl,
                    @"kind": branch[@"kind"] ?: @"",
                    @"fromRVA": branch[@"fromRVA"] ?: @0,
                    @"targetRVA": branch[@"targetRVA"] ?: @0,
                    @"testedRegister": branch[@"testedRegister"] ?: @"",
                    @"testedBit": branch[@"testedBit"] ?: @0,
                    @"testedValue": branch[@"testedValue"] ?: @{},
                    @"conditionProvenance": branch[@"conditionProvenance"] ?: @{},
                    @"binding": @"feature-entry-derived-branch",
                    @"analysisOnly": @YES,
                    @"canonicalEligible": @NO
                }];
            }
        }

        [firstPass addObject:@{
            @"title": title,
            @"normalizedTitle": feature[@"normalizedTitle"] ?: @"",
            @"identifiers": feature[@"identifiers"] ?: @[],
            @"downstreamCalls": calls,
            @"entryDerivedBranches": branches
        }];
    }

    NSMutableArray *outFeatures = [NSMutableArray array];
    NSUInteger senderBoundCallCount = 0, exclusiveTargetCount = 0, il2cppCorrelationCount = 0;
    for (NSDictionary *feature in firstPass) {
        NSMutableArray *calls = [NSMutableArray array];
        for (NSDictionary *call in feature[@"downstreamCalls"] ?: @[]) {
            NSString *key = call[@"targetKey"] ?: @"";
            NSUInteger useCount = [(NSSet *)targetFeatures[key] count];
            NSMutableDictionary *annotated = [[call mutableCopy] autorelease];
            annotated[@"featureUseCount"] = @(useCount);
            annotated[@"featureExclusive"] = @(useCount == 1);
            annotated[@"sharedAcrossFeatures"] = @(useCount > 1);
            annotated[@"confidence"] = [call[@"senderBound"] boolValue] ? @"sender-bound" : @"entry-derived";
            if ([call[@"senderBound"] boolValue]) ++senderBoundCallCount;
            if (useCount == 1) ++exclusiveTargetCount;
            if ([call[@"il2cppMethod"] count]) ++il2cppCorrelationCount;
            [calls addObject:annotated];
        }
        [outFeatures addObject:@{
            @"title": feature[@"title"] ?: @"",
            @"normalizedTitle": feature[@"normalizedTitle"] ?: @"",
            @"identifiers": feature[@"identifiers"] ?: @[],
            @"downstreamCalls": calls,
            @"entryDerivedBranches": feature[@"entryDerivedBranches"] ?: @[],
            @"downstreamCallCount": @(calls.count),
            @"entryDerivedBranchCount": @([feature[@"entryDerivedBranches"] count]),
            @"analysisOnly": @YES,
            @"canonicalEligible": @NO
        }];
    }

    NSMutableDictionary *targetUseCounts = [NSMutableDictionary dictionary];
    [targetFeatures enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSSet *users, BOOL *stop) {
        (void)stop;
        targetUseCounts[key] = @(users.count);
    }];

    NSDictionary *result = @{
        @"schema": @"com.hfa.feature-dispatcher-slices/v1",
        @"buildVersion": @"2.5.22-dev",
        @"componentVersion": @"2.5.22-dev-feature-dispatcher-slicing",
        @"policy": @"READ-ONLY-ENTRY-SENDER-FEATURE-SLICING-NO-REEXECUTION",
        @"menuImage": featureBranchProvenance[@"menuImage"] ?: @"",
        @"menuPath": featureBranchProvenance[@"menuPath"] ?: @"",
        @"features": outFeatures,
        @"targetFeatureUseCounts": targetUseCounts,
        @"summary": @{
            @"featureCount": @(outFeatures.count),
            @"senderBoundCallCount": @(senderBoundCallCount),
            @"featureExclusiveTargetCount": @(exclusiveTargetCount),
            @"il2cppCorrelationCount": @(il2cppCorrelationCount)
        },
        @"rules": @{
            @"featureIdentitySource": @"existing-entry-seeded-x2-sender-provenance",
            @"sharedTargetDowngraded": @YES,
            @"featureExclusiveTargetUpgraded": @YES,
            @"reexecutesHandlerCFG": @NO,
            @"knownGameOffsetsUsedAsInput": @NO
        },
        @"safety": @{
            @"actionInvoked": @NO,
            @"selectorInvoked": @NO,
            @"blockInvoked": @NO,
            @"hookInstalled": @NO,
            @"memoryWritten": @NO,
            @"gameStateWritten": @NO
        }
    };
    HFADiagnosticsLog(@"feature-dispatcher-slicing", @"complete", result[@"summary"]);
    return result;
}

BOOL HFAMapPersistFeatureDispatcherSlices(NSDictionary *result, NSError **error) {
    if (!result) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"FeatureDispatcherSlices.json")];
    return [data writeToFile:path options:NSDataWritingAtomic error:error];
}

static void HFASliceProcessProvenance(void) {
    static NSString *lastDigest;
    NSString *documents = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *path = [documents stringByAppendingPathComponent:HFAOutputFileName(@"FeatureBranchProvenance.json")];
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return;
    NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    NSString *digest = [NSString stringWithFormat:@"%lu:%@", (unsigned long)data.length, attrs.fileModificationDate ?: @""];
    if ([digest isEqualToString:lastDigest]) return;
    NSDictionary *source = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![source isKindOfClass:NSDictionary.class]) return;
    NSError *error = nil;
    NSDictionary *result = HFAMapBuildFeatureDispatcherSlices(source, &error);
    if (result && HFAMapPersistFeatureDispatcherSlices(result, &error)) {
        [lastDigest release]; lastDigest = [digest copy];
        HFADiagnosticsLog(@"feature-dispatcher-slicing", @"persisted", result[@"summary"] ?: @{});
    } else if (error) {
        HFADiagnosticsLog(@"feature-dispatcher-slicing", @"failed", @{ @"error": error.localizedDescription ?: @"unknown" });
    }
}

__attribute__((constructor)) static void HFAFeatureDispatcherSliceConstructor(void) {
    static dispatch_source_t timer;
    dispatch_queue_t q = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), (uint64_t)(1.5 * NSEC_PER_SEC), (uint64_t)(0.1 * NSEC_PER_SEC));
    dispatch_source_set_event_handler(timer, ^{ HFASliceProcessProvenance(); });
    dispatch_resume(timer);
}
