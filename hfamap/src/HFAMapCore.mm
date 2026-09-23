#import "HFAMapCore.h"
#import <dispatch/dispatch.h>
#import "HFAMapFastDiscovery.h"
#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"
#import "HFAMapPatchV1.h"
#import "HFAMapRuntimeProbe.h"
#import "HFAMapFeatureHandlerResolver.h"

static BOOL gHFADiscovering;
static BOOL gHFAAnalyzing;
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
        if (!line) continue;
        [data appendData:line];
        [data appendBytes:"\n" length:1];
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
        if (a - b < 8) {
            NSInteger ad = MAX([first[@"legacyScore"] integerValue], [first[@"jailpatchScore"] integerValue]);
            NSInteger bd = MAX([candidates[1][@"legacyScore"] integerValue], [candidates[1][@"jailpatchScore"] integerValue]);
            if (ad >= 60 && ad >= bd * 2) return first;
            if (bd >= 60 && bd >= ad * 2) return candidates[1];
            if (reason) *reason = @"ambiguous-top-candidates";
            return nil;
        }
    }
    return first;
}

void HFAMapArmLastSelectedRuntimeProbe(void (^completion)(NSDictionary *summary)) {
    NSDictionary *candidate = nil;
    @synchronized(NSObject.class) { candidate = [gHFALastSelectedCandidate copy]; }
    if (!candidate) {
        if (completion) completion(@{ @"status": @"no-selected-menu" });
        return;
    }
    HFAMapArmRuntimeProbeForCandidate(candidate, 8.0, completion);
    [candidate release];
}

void HFAMapStopActiveRuntimeProbe(NSString *reason) {
    HFAMapStopRuntimeProbe(reason ?: @"manual-stop");
}

BOOL HFAMapRuntimeProbeIsActive(void) {
    return HFAMapRuntimeProbeIsArmed();
}

void HFAMapRunMenuDiscovery(void (^completion)(NSDictionary *summary)) {
    @synchronized(NSObject.class) {
        if (gHFADiscovering) { if (completion) completion(@{ @"status": @"busy" }); return; }
        gHFADiscovering = YES;
    }
    dispatch_async(HFAWorker(), ^{
        NSMutableArray<NSDictionary *> *events = [NSMutableArray array];
        NSTimeInterval started = NSDate.date.timeIntervalSince1970;
        NSString *session = HFADiagnosticsBeginSession();
        HFADiagnosticsLog(@"menu-discovery", @"start", @{
            @"mode": @"full-list-lightweight-only",
            @"deepAnalysisPerformed": @NO
        });

        NSArray *candidates = HFAMapFastDiscoverMenuImages(events);
        NSString *reject = nil;
        NSDictionary *selected = HFASelectCandidate(candidates, &reject);
        if (selected) {
            @synchronized(NSObject.class) {
                [gHFALastSelectedCandidate release];
                gHFALastSelectedCandidate = [selected copy];
            }
            HFADiagnosticsLog(@"menu-discovery", @"selected", selected);
        } else {
            HFADiagnosticsLog(@"menu-discovery", @"not-selected", @{
                @"reason": reject ?: @"selection-failed",
                @"candidateCount": @(candidates.count)
            });
        }

        NSDictionary *summary = @{
            @"schema": @"com.hfa.menu-discovery/v1",
            @"status": selected ? @"selected" : @"incomplete",
            @"session": session,
            @"reason": reject ?: @"",
            @"selected": selected ?: @{},
            @"candidates": candidates ?: @[],
            @"candidateCount": @(candidates.count),
            @"deepAnalysisPerformed": @NO,
            @"elapsedMs": @((NSDate.date.timeIntervalSince1970 - started) * 1000.0)
        };
        HFAWriteJSON(summary, HFAOutputFileName(@"Discovery.json"));
        HFAWriteEvents(events);
        HFADiagnosticsFinishSession(selected ? @"selected" : @"incomplete", @{
            @"candidateCount": @(candidates.count),
            @"selectedImage": selected[@"image"] ?: @"",
            @"deepAnalysisPerformed": @NO
        });
        dispatch_async(dispatch_get_main_queue(), ^{
            @synchronized(NSObject.class) { gHFADiscovering = NO; }
            if (completion) completion(summary);
        });
    });
}

void HFAMapRunBoundedScan(void (^completion)(NSDictionary *summary)) {
    HFAMapRunMenuDiscovery(completion);
}

void HFAMapRunSelectedDeepAnalysis(void (^completion)(NSDictionary *summary)) {
    NSDictionary *selected = nil;
    @synchronized(NSObject.class) {
        if (gHFAAnalyzing) { if (completion) completion(@{ @"status": @"busy" }); return; }
        selected = [gHFALastSelectedCandidate copy];
        if (selected) gHFAAnalyzing = YES;
    }
    if (!selected) {
        if (completion) completion(@{ @"status": @"no-selected-menu", @"reason": @"run-discovery-first" });
        return;
    }

    NSMutableArray<NSDictionary *> *events = [NSMutableArray array];
    NSTimeInterval started = NSDate.date.timeIntervalSince1970;
    NSString *session = HFADiagnosticsBeginSession();
    HFADiagnosticsLog(@"deep-analysis", @"start", @{
        @"selectedImage": selected[@"image"] ?: @"?",
        @"selectedPath": selected[@"path"] ?: @"?",
        @"discoveryReused": @YES,
        @"globalRediscoveryPerformed": @NO
    });

    dispatch_async(dispatch_get_main_queue(), ^{
        NSTimeInterval captureStarted = NSDate.date.timeIntervalSince1970;
        NSDictionary *snapshot = HFAMapCaptureFeatureSeeds(selected, captureStarted + 0.50, events);
        NSDictionary *handlerGraph = [HFAMapAnalyzeFeatureHandlerSnapshot(snapshot, selected) retain];
        HFADiagnosticsLog(@"feature-handler-graph", handlerGraph[@"status"] ?: @"complete", @{
            @"recordCount": handlerGraph[@"recordCount"] ?: @0,
            @"runtimeMethodCandidateCount": handlerGraph[@"runtimeMethodCandidateCount"] ?: @0,
            @"il2cppCorrelationCount": handlerGraph[@"il2cppCorrelationCount"] ?: @0,
            @"policy": handlerGraph[@"policy"] ?: @""
        });
        HFADiagnosticsLog(@"ui-snapshot", @"complete", snapshot[@"metrics"] ?: @{});
        dispatch_async(HFAWorker(), ^{
            NSDictionary *resolved = HFAMapResolveFeatureSeeds(selected, snapshot, started + 9.0, events);
            NSArray *features = resolved[@"features"] ?: @[];
            NSArray *runtimeRecords = resolved[@"runtimeRecords"] ?: @[];
            NSDictionary *analysis = @{
                @"schema": @"com.hfa.analysis/v3",
                @"status": resolved[@"status"] ?: @"complete",
                @"session": session,
                @"candidate": selected,
                @"discoveryReused": @YES,
                @"globalRediscoveryPerformed": @NO,
                @"features": features,
                @"registry": resolved[@"registry"] ?: @[],
                @"runtimeRecords": runtimeRecords,
                @"featureHandlerGraph": handlerGraph ?: @{},
                @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                @"unresolved": resolved[@"unresolved"] ?: @[],
                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                @"metrics": resolved[@"metrics"] ?: @{}
            };
            NSDictionary *patch = @{
                @"schema": @"com.hfa.patch/v2", @"session": session,
                @"generatedAt": @([[NSDate date] timeIntervalSince1970]),
                @"sourceMenuImage": selected[@"image"] ?: @"?", @"features": features
            };
            HFAWriteJSON(analysis, HFAOutputFileName(@"Analysis.json"));
            HFAWriteJSON(patch, HFAOutputFileName(@"Patches.json"));
            HFAWriteEvents(events);

            NSString *v1Reason = nil;
            NSDictionary *v1Report = nil;
            NSDictionary *v1Package = HFAMapBuildPatchV1PackageWithReport(features, &v1Reason, &v1Report);
            NSString *canonicalName = HFAOutputFileName(@"Canonical.hfapatch.json");
            NSString *reportName = HFAOutputFileName(@"Canonical.shared-sites.json");
            BOOL canonicalWritten = v1Package && HFAWriteJSON(v1Package, canonicalName);
            if (canonicalWritten) {
                if (!v1Report || !HFAWriteJSON(v1Report, reportName)) HFARemoveOutput(reportName);
            } else {
                HFARemoveOutput(canonicalName);
                if (!v1Report || !HFAWriteJSON(v1Report, reportName)) HFARemoveOutput(reportName);
            }

            HFAWriteJSON(@{
                @"schema": @"com.hfa.registry/v1", @"session": session,
                @"candidate": selected, @"records": resolved[@"registry"] ?: @[],
                @"featureHandlerGraph": handlerGraph ?: @{},
                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                @"status": resolved[@"status"] ?: @"complete"
            }, HFAOutputFileName(@"FeatureRegistry.json"));
            HFAWriteJSON(@{
                @"schema": @"com.hfa.igmm.runtime/v1", @"session": session,
                @"candidate": selected, @"records": runtimeRecords,
                @"featureHandlerGraph": handlerGraph ?: @{},
                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                @"analysisOnly": @YES,
                @"status": resolved[@"status"] ?: @"complete"
            }, HFAOutputFileName(@"RuntimeActions.json"));

            HFADiagnosticsFinishSession(analysis[@"status"], @{
                @"selectedImage": selected[@"image"] ?: @"?",
                @"validated": @(features.count),
                @"unresolved": @([resolved[@"unresolved"] count]),
                @"runtimeMethodCandidates": handlerGraph[@"runtimeMethodCandidateCount"] ?: @0,
                @"globalRediscoveryPerformed": @NO,
                @"metrics": resolved[@"metrics"] ?: @{}
            });
            [handlerGraph release];
            [selected release];
            dispatch_async(dispatch_get_main_queue(), ^{
                @synchronized(NSObject.class) { gHFAAnalyzing = NO; }
                if (completion) completion(analysis);
            });
        });
    });
}
