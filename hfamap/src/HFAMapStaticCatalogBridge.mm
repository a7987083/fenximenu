#import "HFAMapStaticCatalogBridge.h"
#import "HFAMapStaticCatalog.h"
#import "HFAMapDescriptorStaticCallbackResolver.h"

static NSString *HFABridgeNormalizedType(NSString *value) {
    if (![value isKindOfClass:NSString.class] || !value.length) return @"";
    NSString *lower = value.lowercaseString;
    if ([lower isEqualToString:@"unknown"] || [lower isEqualToString:@"none"] ||
        [lower isEqualToString:@"null"]) return @"";
    return lower;
}

static NSDictionary *HFABridgeExactDescriptor(NSDictionary *record) {
    NSArray *candidates = [record valueForKeyPath:@"ownership.descriptorCandidates"];
    NSDictionary *match = nil;
    for (NSDictionary *candidate in candidates ?: @[]) {
        if (![candidate[@"exactLabelMatch"] boolValue]) continue;
        if (match) return nil;
        match = candidate;
    }
    return match;
}

// When canonical/static registry metadata is not yet available at this stage,
// derive a conservative synthetic eligibility set from descriptor structure only.
// A cohort is eligible only when exactly one non-empty descriptor type cohort has
// the same cardinality as the static runtime-method catalog. This is evidence-only.
static NSArray<NSDictionary *> *HFABridgeStructuralEligibilityRegistry(NSDictionary *graph,
                                                                       NSDictionary *catalog) {
    NSUInteger methodCount = [catalog[@"runtimeMethods"] count];
    if (!methodCount) return @[];
    NSMutableDictionary<NSString *, NSMutableArray<NSNumber *> *> *groups = [NSMutableDictionary dictionary];
    NSArray *records = graph[@"records"] ?: @[];
    for (NSUInteger i = 0; i < records.count; ++i) {
        NSDictionary *descriptor = HFABridgeExactDescriptor(records[i]);
        NSString *type = HFABridgeNormalizedType(descriptor[@"type"]);
        if (!descriptor || !type.length) continue;
        NSMutableArray *indexes = groups[type];
        if (!indexes) { indexes = [NSMutableArray array]; groups[type] = indexes; }
        [indexes addObject:@(i)];
    }
    NSArray<NSNumber *> *eligible = nil;
    for (NSString *type in groups) {
        NSArray *indexes = groups[type];
        if (indexes.count != methodCount) continue;
        if (eligible) return @[]; // multiple equally-sized cohorts are ambiguous
        eligible = indexes;
    }
    if (!eligible.count) return @[];
    NSSet *eligibleSet = [NSSet setWithArray:eligible];
    NSMutableArray *registry = [NSMutableArray array];
    for (NSUInteger i = 0; i < records.count; ++i) {
        NSString *label = records[i][@"label"] ?: @"";
        BOOL include = [eligibleSet containsObject:@(i)];
        [registry addObject:@{ @"name": label,
                               @"canonicalEligible": @(!include),
                               @"canonicalPatchCount": include ? @0 : @1,
                               @"correlationEligibility": include ? @"unique-descriptor-type-cohort" : @"excluded-structurally" }];
    }
    return registry;
}

NSDictionary *HFAMapStaticCatalogAnnotateHandlerGraph(NSDictionary *graph,
                                                      NSString *loadedImage) {
    if (![graph isKindOfClass:NSDictionary.class]) return @{};
    NSDictionary *current = HFAMapStaticCatalogCurrent();
    NSMutableDictionary *result = [graph mutableCopy];
    result[@"staticCatalogLoaded"] = @(current != nil);
    result[@"staticCatalogSource"] = current[@"source"] ?: @{};
    if (!current) return [result autorelease];

    NSMutableArray *records = [NSMutableArray array];
    NSUInteger matchedBlocks = 0;
    NSUInteger matchedRuntimeMethods = 0;
    for (NSDictionary *record in graph[@"records"] ?: @[]) {
        NSMutableDictionary *recordOut = [record mutableCopy];
        NSMutableArray *blocks = [NSMutableArray array];
        for (NSDictionary *block in record[@"handlerBlocks"] ?: @[]) {
            NSMutableDictionary *blockOut = [block mutableCopy];
            NSDictionary *semantic = block[@"semantic"];
            uint64_t rva = [semantic[@"invokeRVA"] unsignedLongLongValue];
            NSDictionary *match = rva ? HFAMapStaticCatalogLookup(loadedImage, rva) : nil;
            if (match) {
                blockOut[@"staticCatalogMatch"] = match;
                ++matchedBlocks;
                if ([[match valueForKeyPath:@"record.classification"] isEqualToString:@"runtime-method-candidate"])
                    ++matchedRuntimeMethods;
            }
            [blocks addObject:blockOut];
            [blockOut release];
        }
        recordOut[@"handlerBlocks"] = blocks;
        recordOut[@"staticCatalogMatchedBlockCount"] = @([blocks filteredArrayUsingPredicate:
            [NSPredicate predicateWithBlock:^BOOL(NSDictionary *entry, NSDictionary *bindings) {
                return entry[@"staticCatalogMatch"] != nil;
            }]].count);
        [records addObject:recordOut];
        [recordOut release];
    }
    result[@"records"] = records;
    result[@"staticCatalogMatchedBlockCount"] = @(matchedBlocks);
    result[@"staticCatalogMatchedRuntimeMethodCount"] = @(matchedRuntimeMethods);
    result[@"staticCatalogAssociation"] = @"runtime-handler-rva-to-same-session-static-catalog";

    NSArray *structuralRegistry = HFABridgeStructuralEligibilityRegistry(result, current);
    result[@"descriptorStaticCallbackEligibility"] = structuralRegistry.count
        ? @"unique-descriptor-type-cohort"
        : @"no-unique-descriptor-type-cohort";
    NSDictionary *resolved = HFAMapResolveDescriptorStaticCallbacks(result,
        structuralRegistry, loadedImage ?: @"");
    [result release];
    return resolved;
}
