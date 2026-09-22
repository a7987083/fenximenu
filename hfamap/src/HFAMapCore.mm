#import "HFAMapCore.h"
#import <dispatch/dispatch.h>
#import "HFAMapImageProbe.h"
#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"
#import "HFAMapPatchV1.h"
#import "HFAMapRuntimeProbe.h"

static BOOL gHFAScanning;
static NSDictionary *gHFALastSelectedCandidate;
static dispatch_queue_t HFAWorker(void) {
    static dispatch_queue_t queue; static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = dispatch_queue_create("com.hfa.map.worker", DISPATCH_QUEUE_SERIAL); });
    return queue;
}

static NSString *HFADocuments(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static NSString *HFAOutputPath(NSString *name) {
    return [HFADocuments() stringByAppendingPathComponent:name];
}

static BOOL HFAWriteJSON(id object, NSString *name) {
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingPrettyPrinted error:&error];
    return data && [data writeToFile:HFAOutputPath(name) options:NSDataWritingAtomic error:&error];
}

static void HFARemoveOutput(NSString *name) {
    NSString *path = HFAOutputPath(name);
    NSFileManager *manager = NSFileManager.defaultManager;
    if ([manager fileExistsAtPath:path]) [manager removeItemAtPath:path error:nil];
}

static void HFAWriteEvents(NSArray<NSDictionary *> *events) {
    NSMutableData *data = [NSMutableData data];
    for (NSDictionary *event in events) {
        NSData *line = [NSJSONSerialization dataWithJSONObject:event options:0 error:nil];
        if (!line) continue; [data appendData:line]; [data appendBytes:"\n" length:1];
    }
    [data writeToFile:[HFADocuments() stringByAppendingPathComponent:HFAOutputFileName(@"Process.jsonl")]
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

void HFAMapArmLastSelectedRuntimeProbe(void (^completion)(NSDictionary *summary)) {
    NSDictionary *candidate = nil;
    @synchronized(NSObject.class) { candidate = [gHFALastSelectedCandidate copy]; }
    HFAMapArmRuntimeProbeForCandidate(candidate, 8.0, completion);
    [candidate release];
}

void HFAMapStopActiveRuntimeProbe(NSString *reason) {
    HFAMapStopRuntimeProbe(reason ?: @"manual-stop");
}

BOOL HFAMapRuntimeProbeIsActive(void) {
    return HFAMapRuntimeProbeIsArmed();
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
            HFAWriteJSON(analysis, HFAOutputFileName(@"Analysis.json")); HFAWriteEvents(events);
            HFAWriteJSON(@{ @"schema": @"com.hfa.patch/v2", @"session": session,
                            @"status": @"incomplete", @"features": @[] }, HFAOutputFileName(@"Patches.json"));
            HFAWriteJSON(@{ @"schema": @"com.hfa.registry/v1", @"session": session,
                            @"status": @"incomplete", @"records": @[] },
                         HFAOutputFileName(@"FeatureRegistry.json"));
            HFAWriteJSON(@{ @"schema": @"com.hfa.igmm.runtime/v1", @"session": session,
                            @"status": @"incomplete", @"records": @[] },
                         HFAOutputFileName(@"RuntimeActions.json"));
            NSString *v1Reason = nil;
            NSDictionary *v1Report = nil;
            NSDictionary *v1Package = HFAMapBuildPatchV1PackageWithReport(@[], &v1Reason, &v1Report);
            NSString *canonicalName = HFAOutputFileName(@"Canonical.hfapatch.json");
            NSString *reportName = HFAOutputFileName(@"Canonical.shared-sites.json");
            if (!v1Package || !HFAWriteJSON(v1Package, canonicalName)) HFARemoveOutput(canonicalName);
            if (!v1Report || !HFAWriteJSON(v1Report, reportName)) HFARemoveOutput(reportName);
            HFADiagnosticsFinishSession(@"incomplete", @{
                @"reason": reject ?: @"selection-failed", @"candidateCount": @(candidates.count)
            });
            dispatch_async(dispatch_get_main_queue(), ^{ @synchronized(NSObject.class) { gHFAScanning = NO; }
                if (completion) completion(analysis); });
            return;
        }
        HFADiagnosticsLog(@"selection", @"selected", selected);
        @synchronized(NSObject.class) {
            [gHFALastSelectedCandidate release];
            gHFALastSelectedCandidate = [selected copy];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSTimeInterval captureStarted = NSDate.date.timeIntervalSince1970;
            NSDictionary *snapshot = HFAMapCaptureFeatureSeeds(selected, captureStarted + 0.35, events);
            HFADiagnosticsLog(@"ui-snapshot", @"complete", snapshot[@"metrics"] ?: @{});
            dispatch_async(HFAWorker(), ^{
                NSDictionary *resolved = HFAMapResolveFeatureSeeds(selected, snapshot,
                                                                   started + 4.5, events);
                NSArray *features = resolved[@"features"] ?: @[];
                NSArray *runtimeRecords = resolved[@"runtimeRecords"] ?: @[];
                NSMutableOrderedSet *runtimeHints = [NSMutableOrderedSet orderedSet];
                for (NSDictionary *record in resolved[@"registry"] ?: @[]) {
                    for (NSString *key in @[@"label", @"title", @"name", @"identifier"]) {
                        NSString *value = [record[key] isKindOfClass:NSString.class] ? record[key] : @"";
                        if (value.length) [runtimeHints addObject:value];
                    }
                }
                NSMutableDictionary *runtimeCandidate = [selected mutableCopy];
                runtimeCandidate[@"runtimeFeatureHints"] = runtimeHints.array ?: @[];
                @synchronized(NSObject.class) {
                    [gHFALastSelectedCandidate release];
                    gHFALastSelectedCandidate = [runtimeCandidate copy];
                }
                [runtimeCandidate release];
                NSDictionary *analysis = @{ @"schema": @"com.hfa.analysis/v2",
                                             @"status": resolved[@"status"] ?: @"complete",
                                             @"session": session, @"candidate": selected,
                                             @"features": features,
                                             @"registry": resolved[@"registry"] ?: @[],
                                             @"runtimeRecords": runtimeRecords,
                                             @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                                             @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                                             @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                                             @"unresolved": resolved[@"unresolved"] ?: @[],
                                             @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                                             @"metrics": resolved[@"metrics"] ?: @{} };
                NSDictionary *patch = @{ @"schema": @"com.hfa.patch/v2",
                                          @"session": session,
                                          @"generatedAt": @([[NSDate date] timeIntervalSince1970]),
                                          @"sourceMenuImage": selected[@"image"], @"features": features };
                [events addObject:@{ @"time": @(NSDate.date.timeIntervalSince1970), @"stage": @"export",
                                     @"status": @"complete", @"canonicalFeatures": @(features.count),
                                     @"analysisFeatures": @([resolved[@"unresolved"] count]) }];
                HFAWriteJSON(analysis, HFAOutputFileName(@"Analysis.json"));
                HFAWriteJSON(patch, HFAOutputFileName(@"Patches.json")); HFAWriteEvents(events);
                NSString *v1Reason = nil;
                NSDictionary *v1Report = nil;
                NSDictionary *v1Package = HFAMapBuildPatchV1PackageWithReport(features, &v1Reason,
                                                                               &v1Report);
                NSString *canonicalName = HFAOutputFileName(@"Canonical.hfapatch.json");
                NSString *reportName = HFAOutputFileName(@"Canonical.shared-sites.json");
                BOOL canonicalWritten = v1Package && HFAWriteJSON(v1Package, canonicalName);
                if (canonicalWritten) {
                    if (!v1Report || !HFAWriteJSON(v1Report, reportName)) HFARemoveOutput(reportName);
                    HFADiagnosticsLog(@"patch-v1-export", @"complete", @{
                        @"featureCount": @([v1Package[@"features"] count]),
                        @"targetCount": @([v1Package[@"targets"] count]),
                        @"sharedPatchSiteCount": @([v1Report[@"sharedPatchSites"] count]),
                        @"rejectedRecordCount": @([v1Report[@"rejectedRecords"] count]),
                        @"file": canonicalName,
                        @"reportFile": reportName
                    });
                } else {
                    HFARemoveOutput(canonicalName);
                    if (!v1Report || !HFAWriteJSON(v1Report, reportName)) HFARemoveOutput(reportName);
                    HFADiagnosticsLog(@"patch-v1-export", @"rejected", @{
                        @"reason": v1Reason ?: (v1Package ? @"canonical-write-failed"
                                                          : @"package-build-failed"),
                        @"staleCanonicalRemoved": @YES
                    });
                }
                HFAWriteJSON(@{ @"schema": @"com.hfa.registry/v1", @"session": session,
                                @"candidate": selected, @"records": resolved[@"registry"] ?: @[],
                                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                                @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                                @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                                @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                                @"status": resolved[@"status"] ?: @"complete" },
                             HFAOutputFileName(@"FeatureRegistry.json"));
                HFAWriteJSON(@{ @"schema": @"com.hfa.igmm.runtime/v1", @"session": session,
                                @"candidate": selected, @"records": runtimeRecords,
                                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                                @"analysisOnly": @YES,
                                @"status": resolved[@"status"] ?: @"complete" },
                             HFAOutputFileName(@"RuntimeActions.json"));
                HFADiagnosticsLog(@"runtime-export", @"complete", @{
                    @"recordCount": @(runtimeRecords.count),
                    @"file": HFAOutputFileName(@"RuntimeActions.json"),
                    @"staticPatchContractUnchanged": @YES
                });
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
