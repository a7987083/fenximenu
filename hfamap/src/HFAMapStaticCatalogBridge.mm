#import "HFAMapStaticCatalogBridge.h"
#import "HFAMapStaticCatalog.h"

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
    return [result autorelease];
}
