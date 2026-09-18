#import "HFAMapCore.h"
#import "HFAMapImageProbe.h"
#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"

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
        if (a - b < 10) {
            NSDictionary *second = candidates[1];
            NSInteger firstDescriptor = MAX([first[@"legacyScore"] integerValue], [first[@"jailpatchScore"] integerValue]);
            NSInteger secondDescriptor = MAX([second[@"legacyScore"] integerValue], [second[@"jailpatchScore"] integerValue]);
            if (secondDescriptor >= 80 && secondDescriptor >= firstDescriptor * 2) return second;
            if (firstDescriptor >= 80 && firstDescriptor >= secondDescriptor * 2) return first;
            if (reason) *reason = @"ambiguous-top-candidates"; return nil;
        }
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
        NSString *session = HFADiagnosticsBeginSession();
        [events addObject:@{ @"time": @(started), @"stage": @"scan", @"status": @"start",
                             @"schema": @"com.hfa.process/v2", @"session": session,
                             @"budgetMs": @5000 }];
        HFADiagnosticsLog(@"scan", @"start", @{ @"budgetMs": @5000 });
        NSArray *candidates = HFAMapDiscoverMenuImages(started + 2.0, events);
        HFADiagnosticsLog(@"image-discovery", @"complete", @{
            @"candidateCount": @(candidates.count), @"candidates": candidates ?: @[]
        });
        NSString *reject = nil; NSDictionary *selected = HFASelectCandidate(candidates, &reject);
        if (!selected) {
            NSDictionary *analysis = @{ @"schema": @"com.hfa.analysis/v2", @"status": @"incomplete",
                                         @"session": session,
                                         @"reason": reject ?: @"selection-failed", @"candidates": candidates,
                                         @"features": @[], @"unresolved": @[] };
            [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"selection",
                                 @"status": @"reject", @"reason": reject ?: @"?" }];
            HFAWriteJSON(analysis, @"HFAMap_Analysis.json"); HFAWriteEvents(events);
            HFADiagnosticsFinishSession(@"incomplete", @{
                @"reason": reject ?: @"selection-failed", @"candidateCount": @(candidates.count)
            });
            dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class) { gHFAScanning = NO; }
                if (completion) completion(analysis); });
            return;
        }
        HFADiagnosticsLog(@"selection", @"selected", selected);
        dispatch_async(dispatch_get_main_queue(), ^{
            NSTimeInterval captureStarted = NSDate.date.timeIntervalSince1970;
            NSDictionary *snapshot = HFAMapCaptureFeatureSeeds(selected, captureStarted + 0.35, events);
            HFADiagnosticsLog(@"ui-snapshot", @"complete", snapshot[@"metrics"] ?: @{});
            dispatch_async(HFAWorker(), ^{
                NSDictionary *resolved = HFAMapResolveFeatureSeeds(selected, snapshot,
                                                                   started + 4.5, events);
                NSArray *features = resolved[@"features"] ?: @[];
                NSDictionary *analysis = @{ @"schema": @"com.hfa.analysis/v2",
                                             @"status": resolved[@"status"] ?: @"complete",
                                             @"session": session, @"candidate": selected,
                                             @"features": features,
                                             @"unresolved": resolved[@"unresolved"] ?: @[],
                                             @"metrics": resolved[@"metrics"] ?: @{} };
                NSDictionary *patch = @{ @"schema": @"com.hfa.patch/v2",
                                          @"session": session,
                                          @"generatedAt": @([[NSDate date] timeIntervalSince1970]),
                                          @"sourceMenuImage": selected[@"image"], @"features": features };
                [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"export",
                                     @"status": @"complete", @"canonicalFeatures": @(features.count),
                                     @"analysisFeatures": @([resolved[@"unresolved"] count]) }];
                HFAWriteJSON(analysis, @"HFAMap_Analysis.json");
                HFAWriteJSON(patch, @"HFAMap_Patches.json"); HFAWriteEvents(events);
                HFADiagnosticsFinishSession(analysis[@"status"], @{
                    @"validated": @(features.count),
                    @"unresolved": @([resolved[@"unresolved"] count]),
                    @"metrics": resolved[@"metrics"] ?: @{}
                });
                dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class) { gHFAScanning = NO; }
                    if (completion) completion(analysis); });
            });
        });
    });
}
