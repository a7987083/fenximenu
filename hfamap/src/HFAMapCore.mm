#import "HFAMapCore.h"
#import "HFAMapImageProbe.h"
#import "HFAMapResolver.h"

static BOOL gHFAScanning;
static dispatch_queue_t HFAWorker(void) {
    static dispatch_queue_t queue; static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = dispatch_queue_create("com.hfa.map.worker", DISPATCH_QUEUE_SERIAL); });
    return queue;
}

static NSString *HFADocuments(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void HFAWriteJSON(id object, NSString *name) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:&error];
    if (data) [data writeToFile:[HFADocuments() stringByAppendingPathComponent:name]
                        options:NSDataWritingAtomic error:&error];
}

static void HFAWriteEvents(NSArray<NSDictionary *> *events) {
    NSMutableData *data = [NSMutableData data];
    for (NSDictionary *event in events) {
        NSData *line = [NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
        if (!line) continue; [data appendData:line]; [data appendBytes:"\n" length:1];
    }
    [data writeToFile:[HFADocuments() stringByAppendingPathComponent:@"HFAMap_Process.jsonl"]
              options:NSDataWritingAtomic error:nil];
}

static NSDictionary *HFASelectCandidate(NSArray<NSDictionary *> *candidates, NSString **reason) {
    if (!candidates.count) { if (reason) *reason = @"no-loaded-menu-image"; return nil; }
    NSDictionary *first = candidates.firstObject;
    if ([first[@"score"] unsignedIntValue] < 50) { if (reason) *reason = @"weak-fingerprint"; return nil; }
    if (candidates.count > 1) {
        NSInteger a = [first[@"score"] integerValue], b = [candidates[1][@"score"] integerValue];
        if (a - b < 10) { if (reason) *reason = @"ambiguous-top-candidates"; return nil; }
    }
    return first;
}

void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary)) {
    @synchronized(NSObject.class) {
        if (gHFAScanning) { if (completion) completion(@{ @"status": @"busy" }); return; }
        gHFAScanning = YES;
    }
    dispatch_async(HFAWorker(), ^{
        NSMutableArray<NSDictionary *> *events = [NSMutableArray array];
        NSTimeInterval started = NSDate.date.timeIntervalSince1970;
        [events addObject:@{ @"time": @(started), @"stage": @"scan", @"status": @"start",
                             @"schema": @"com.hfa.process/v2", @"budgetMs": @5000 }];
        NSArray *candidates = HFAMapDiscoverMenuImages(started + 2.0, events);
        NSString *reject = nil; NSDictionary *selected = HFASelectCandidate(candidates, &reject);
        if (!selected) {
            NSDictionary *analysis = @{ @"schema": @"com.hfa.analysis/v2", @"status": @"incomplete",
                                         @"reason": reject ?: @"selection-failed", @"candidates": candidates,
                                         @"features": @[], @"unresolved": @[] };
            [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"selection",
                                 @"status": @"reject", @"reason": reject ?: @"?" }];
            HFAWriteJSON(analysis, @"HFAMap_Analysis.json"); HFAWriteEvents(events);
            dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class) { gHFAScanning = NO; }
                if (completion) completion(analysis); });
            return;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSDictionary *resolved = HFAMapResolveFeatures(selected, NSDate.date.timeIntervalSince1970 + 2.0, events);
            dispatch_async(HFAWorker(), ^{
                NSArray *features = resolved[@"features"] ?: @[];
                NSDictionary *analysis = @{ @"schema": @"com.hfa.analysis/v2",
                                             @"status": @"complete", @"candidate": selected,
                                             @"features": features,
                                             @"unresolved": resolved[@"unresolved"] ?: @[],
                                             @"metrics": resolved[@"metrics"] ?: @{} };
                NSDictionary *patch = @{ @"schema": @"com.hfa.patch/v2",
                                          @"generatedAt": @([[NSDate date] timeIntervalSince1970]),
                                          @"sourceMenuImage": selected[@"image"], @"features": features };
                [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"export",
                                     @"status": @"complete", @"canonicalFeatures": @(features.count),
                                     @"analysisFeatures": @([resolved[@"unresolved"] count]) }];
                HFAWriteJSON(analysis, @"HFAMap_Analysis.json");
                HFAWriteJSON(patch, @"HFAMap_Patches.json"); HFAWriteEvents(events);
                dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class) { gHFAScanning = NO; }
                    if (completion) completion(analysis); });
            });
        });
    });
}
