#import "HFACanonicalMutation.h"

#include <stdio.h>

NSString * const HFACanonicalMutationSchema = @"com.hfa.mutation/v1";

@interface HFACanonicalMutationRegistry : NSObject
@end
@implementation HFACanonicalMutationRegistry
@end

static NSMutableDictionary *gHFACanonicalMutations;

static NSString *HFAMutationDocuments(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static void HFAMutationLog(NSString *message) {
    if (!message.length) return;
    NSString *path = [HFAMutationDocuments() stringByAppendingPathComponent:@"HFAMap_Learn.log"];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
    fprintf(f, "%s\n", message.UTF8String ?: "[MUTATION-IR]");
    fflush(f);
    fclose(f);
}

static BOOL HFAHexStringIsValid(NSString *value) {
    if (![value isKindOfClass:[NSString class]] || !value.length || (value.length & 1)) return NO;
    static NSCharacterSet *invalid;
    @synchronized([HFACanonicalMutationRegistry class]) {
        if (!invalid) {
            NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"];
            invalid = [hex invertedSet];
        }
    }
    return [value rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

static NSString *HFAString(id value) {
    return [value isKindOfClass:[NSString class]] ? value : @"";
}

static NSMutableDictionary *HFAStore(void) {
    @synchronized([HFACanonicalMutationRegistry class]) {
        if (!gHFACanonicalMutations)
            gHFACanonicalMutations = [NSMutableDictionary dictionary];
        return gHFACanonicalMutations;
    }
}

static NSString *HFAMutationKey(NSString *featureID,
                                NSString *targetID,
                                NSString *offset,
                                NSString *enabled) {
    return [NSString stringWithFormat:@"%@|%@|%@|%@",
            featureID ?: @"", targetID ?: @"", offset ?: @"", enabled ?: @""];
}

static NSDictionary *HFATargetRecord(NSString *targetID, NSDictionary *targets) {
    NSDictionary *meta = [targets[targetID] isKindOfClass:[NSDictionary class]] ? targets[targetID] : nil;
    NSString *image = HFAString(meta[@"image"]);
    if (!image.length) image = HFAString(meta[@"resolvedImage"]);
    if (!image.length) image = targetID;
    NSMutableDictionary *target = [NSMutableDictionary dictionary];
    target[@"id"] = targetID ?: @"";
    target[@"image"] = image ?: @"";
    if ([meta isKindOfClass:[NSDictionary class]]) {
        NSString *uuid = HFAString(meta[@"uuid"]);
        NSString *arch = HFAString(meta[@"architecture"]);
        if (uuid.length) target[@"uuid"] = uuid;
        if (arch.length) target[@"architecture"] = arch;
    }
    return target;
}

static void HFARegisterMutation(NSDictionary *mutation, NSString *provider) {
    NSString *featureID = HFAString(mutation[@"id"]);
    NSDictionary *target = [mutation[@"target"] isKindOfClass:[NSDictionary class]] ? mutation[@"target"] : nil;
    NSDictionary *location = [mutation[@"location"] isKindOfClass:[NSDictionary class]] ? mutation[@"location"] : nil;
    NSDictionary *bytes = [mutation[@"bytes"] isKindOfClass:[NSDictionary class]] ? mutation[@"bytes"] : nil;
    NSString *targetID = HFAString(target[@"id"]);
    NSString *offset = HFAString(location[@"offset"]);
    NSString *enabled = HFAString(bytes[@"enabled"]);
    NSString *key = HFAMutationKey(featureID, targetID, offset, enabled);
    if (!featureID.length || !targetID.length || !offset.length || !enabled.length) return;

    @synchronized([HFACanonicalMutationRegistry class]) {
        NSMutableDictionary *store = HFAStore();
        NSMutableDictionary *existing = [store[key] mutableCopy];
        if (!existing) {
            existing = [mutation mutableCopy];
            NSMutableDictionary *evidence = [@{ @"providers": [NSMutableArray array],
                                                 @"truth": @"original-enabled-byte-difference-validated" } mutableCopy];
            existing[@"evidence"] = evidence;
            store[key] = existing;
        }
        NSMutableDictionary *evidence = [existing[@"evidence"] mutableCopy];
        if (!evidence) evidence = [NSMutableDictionary dictionary];
        NSMutableArray *providers = [evidence[@"providers"] mutableCopy];
        if (!providers) providers = [NSMutableArray array];
        if (provider.length && ![providers containsObject:provider]) [providers addObject:provider];
        evidence[@"providers"] = providers;
        evidence[@"truth"] = @"original-enabled-byte-difference-validated";
        existing[@"evidence"] = evidence;
        store[key] = existing;
    }
}

void HFAIngestCanonicalPackage(NSArray *features,
                               NSDictionary *targets,
                               NSString *provider) {
    if (![features isKindOfClass:[NSArray class]] || ![targets isKindOfClass:[NSDictionary class]]) return;
    unsigned accepted = 0, rejected = 0;
    for (id rawFeature in features) {
        if (![rawFeature isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *feature = (NSDictionary *)rawFeature;
        NSString *featureID = HFAString(feature[@"id"]);
        if (!featureID.length) { rejected++; continue; }
        NSString *title = HFAString(feature[@"title"]);
        if (!title.length) title = featureID;
        NSString *group = HFAString(feature[@"group"]);
        if (!group.length) group = @"Imported";
        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        for (id rawPatch in patches) {
            if (![rawPatch isKindOfClass:[NSDictionary class]]) { rejected++; continue; }
            NSDictionary *patch = (NSDictionary *)rawPatch;
            NSString *targetID = HFAString(patch[@"target"]);
            NSString *offset = HFAString(patch[@"offset"]);
            NSString *original = HFAString(patch[@"original"]);
            NSString *enabled = HFAString(patch[@"enabled"]);
            if (!targetID.length || !offset.length ||
                !HFAHexStringIsValid(original) || !HFAHexStringIsValid(enabled) ||
                original.length != enabled.length || [original caseInsensitiveCompare:enabled] == NSOrderedSame) {
                rejected++;
                HFAMutationLog([NSString stringWithFormat:
                    @"[MUTATION-IR-REJECT] id=%@ target=%@ offset=%@ reason=invalid-byte-patch",
                    featureID, targetID, offset]);
                continue;
            }
            NSDictionary *mutation = @{
                @"id": featureID,
                @"title": title,
                @"group": group,
                @"kind": @"static-bytes",
                @"target": HFATargetRecord(targetID, targets),
                @"location": @{
                    @"offset": offset,
                    @"semantics": @"preferred-mach-o-vmaddr"
                },
                @"bytes": @{
                    @"original": original.uppercaseString,
                    @"enabled": enabled.uppercaseString
                },
                @"canonicalEligible": @YES,
                @"confidence": @1.0
            };
            HFARegisterMutation(mutation, provider ?: @"unknown");
            accepted++;
        }
    }
    HFAMutationLog([NSString stringWithFormat:
        @"[MUTATION-IR-INGEST] provider=%@ accepted=%u rejected=%u total=%lu",
        provider ?: @"unknown", accepted, rejected,
        (unsigned long)HFACanonicalMutationSnapshot().count]);
}

NSArray *HFACanonicalMutationSnapshot(void) {
    @synchronized([HFACanonicalMutationRegistry class]) {
        NSArray *values = [HFAStore().allValues copy];
        return [values sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSString *ak = [NSString stringWithFormat:@"%@|%@|%@",
                            HFAString(a[@"id"]),
                            HFAString([a[@"target"] objectForKey:@"id"]),
                            HFAString([a[@"location"] objectForKey:@"offset"])];
            NSString *bk = [NSString stringWithFormat:@"%@|%@|%@",
                            HFAString(b[@"id"]),
                            HFAString([b[@"target"] objectForKey:@"id"]),
                            HFAString([b[@"location"] objectForKey:@"offset"])];
            return [ak compare:bk];
        }];
    }
}

BOOL HFAFlushCanonicalMutations(void) {
    NSArray *mutations = HFACanonicalMutationSnapshot();
    NSDictionary *root = @{
        @"schema": HFACanonicalMutationSchema,
        @"analysisOnly": @NO,
        @"count": @(mutations.count),
        @"mutations": mutations
    };
    if (![NSJSONSerialization isValidJSONObject:root]) return NO;
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:root
                                                   options:NSJSONWritingPrettyPrinted
                                                     error:&error];
    if (!json) {
        HFAMutationLog([NSString stringWithFormat:@"[MUTATION-IR-FLUSH-FAIL] reason=%@",
                        error.localizedDescription ?: @"json"]);
        return NO;
    }
    NSString *path = [HFAMutationDocuments() stringByAppendingPathComponent:@"HFAMap_CanonicalMutations.json"];
    BOOL ok = [json writeToFile:path options:NSDataWritingAtomic error:&error];
    HFAMutationLog([NSString stringWithFormat:@"[MUTATION-IR-FLUSH] status=%@ count=%lu file=%@%@",
                    ok ? @"pass" : @"fail", (unsigned long)mutations.count,
                    path.lastPathComponent,
                    error ? [NSString stringWithFormat:@" error=%@", error.localizedDescription] : @""]]);
    return ok;
}

void HFAResetCanonicalMutations(void) {
    @synchronized([HFACanonicalMutationRegistry class]) {
        [gHFACanonicalMutations removeAllObjects];
    }
}
