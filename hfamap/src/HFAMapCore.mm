#import "HFAMapCore.h"
#import <dispatch/dispatch.h>
#import "HFAMapFastDiscovery.h"
#import "HFAMapResolver.h"
#import "HFAMapDiagnostics.h"
#import "HFAMapOutputName.h"
#import "HFAMapPatchV1.h"
#import "HFAMapRuntimeProbe.h"
#import "HFAMapFeatureHandlerResolver.h"
#import "HFAMapStaticCatalog.h"
#import "HFAMapStaticCatalogBridge.h"
#import "HFAMapStaticConsumerTargetResolver.h"
#import "HFAMapNativeConsumerTargetBridge.h"
#import "HFAMapGenericRuntimeTemplateResolver.h"

static BOOL gHFADiscovering;
static BOOL gHFAAnalyzing;
static NSDictionary *gHFALastSelectedCandidate;

static dispatch_queue_t HFAWorker(void) {
    static dispatch_queue_t queue; static dispatch_once_t once;
    dispatch_once(&once, ^{ queue = dispatch_queue_create("com.hfa.map.worker", DISPATCH_QUEUE_SERIAL); });
    return queue;
}

static NSString *HFAOutputPath(NSString *name) {
    return [HFAOutputDirectoryPath() stringByAppendingPathComponent:name];
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
    [data writeToFile:[HFAOutputDirectoryPath() stringByAppendingPathComponent:HFAOutputFileName(@"Process.jsonl")]
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

BOOL HFAMapSelectMenuCandidate(NSDictionary *candidate) {
    if (![candidate isKindOfClass:NSDictionary.class]) return NO;
    NSString *image = [candidate[@"image"] isKindOfClass:NSString.class] ? candidate[@"image"] : @"";
    NSString *path = [candidate[@"path"] isKindOfClass:NSString.class] ? candidate[@"path"] : @"";
    if (!image.length && !path.length) return NO;
    @synchronized(NSObject.class) {
        [gHFALastSelectedCandidate release];
        gHFALastSelectedCandidate = [candidate copy];
    }
    HFASetOutputTargetFileName(image.length ? image : path.lastPathComponent);
    HFAAdoptRootOutputsIntoCurrentDirectory();
    HFADiagnosticsLog(@"menu-discovery", @"manually-selected-after-ambiguity", @{
        @"image": image ?: @"",
        @"path": path ?: @"",
        @"score": candidate[@"score"] ?: @0
    });
    return YES;
}

void HFAMapRunMenuDiscovery(void (^completion)(NSDictionary *summary)) {
    @synchronized(NSObject.class) {
        if (gHFADiscovering) { if (completion) completion(@{ @"status": @"busy" }); return; }
        gHFADiscovering = YES;
    }
    dispatch_async(HFAWorker(), ^{
        NSMutableArray<NSDictionary *> *events = [NSMutableArray array];
        NSTimeInterval started = NSDate.date.timeIntervalSince1970;
        HFASetOutputTargetFileName(nil);
        NSArray *candidates = HFAMapFastDiscoverMenuImages(events);
        NSString *reject = nil;
        NSDictionary *selected = HFASelectCandidate(candidates, &reject);
        NSString *selectedImage = [selected[@"image"] isKindOfClass:NSString.class] ? selected[@"image"] : @"";
        NSString *selectedPath = [selected[@"path"] isKindOfClass:NSString.class] ? selected[@"path"] : @"";
        if (selected) {
            HFASetOutputTargetFileName(selectedImage.length ? selectedImage : selectedPath.lastPathComponent);
            HFAAdoptRootOutputsIntoCurrentDirectory();
        }
        NSString *session = HFADiagnosticsBeginSession();
        HFADiagnosticsLog(@"menu-discovery", @"start", @{
            @"mode": @"full-list-lightweight-only",
            @"deepAnalysisPerformed": @NO,
            @"outputDirectory": HFAOutputDirectoryPath() ?: @""
        });
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
            @"staticCatalogLoaded": @(HFAMapStaticCatalogCurrent() != nil),
            @"elapsedMs": @((NSDate.date.timeIntervalSince1970 - started) * 1000.0)
        };
        HFAWriteJSON(summary, HFAOutputFileName(@"Discovery.json"));
        HFAWriteEvents(events);
        HFADiagnosticsFinishSession(selected ? @"selected" : @"incomplete", @{
            @"candidateCount": @(candidates.count),
            @"selectedImage": selected[@"image"] ?: @"",
            @"deepAnalysisPerformed": @NO,
            @"staticCatalogLoaded": @(HFAMapStaticCatalogCurrent() != nil)
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

    NSString *selectedImage = [selected[@"image"] isKindOfClass:NSString.class] ? selected[@"image"] : @"";
    NSString *selectedPath = [selected[@"path"] isKindOfClass:NSString.class] ? selected[@"path"] : @"";
    HFASetOutputTargetFileName(selectedImage.length ? selectedImage : selectedPath.lastPathComponent);
    NSMutableArray<NSDictionary *> *events = [NSMutableArray array];
    NSTimeInterval started = NSDate.date.timeIntervalSince1970;
    NSString *session = HFADiagnosticsBeginSession();
    HFADiagnosticsLog(@"deep-analysis", @"start", @{
        @"selectedImage": selected[@"image"] ?: @"?",
        @"selectedPath": selected[@"path"] ?: @"?",
        @"discoveryReused": @YES,
        @"globalRediscoveryPerformed": @NO,
        @"staticCatalogLoaded": @(HFAMapStaticCatalogCurrent() != nil),
        @"outputDirectory": HFAOutputDirectoryPath() ?: @""
    });

    dispatch_async(dispatch_get_main_queue(), ^{
        NSTimeInterval captureStarted = NSDate.date.timeIntervalSince1970;
        NSDictionary *snapshot = HFAMapCaptureFeatureSeeds(selected, captureStarted + 0.50, events);
        NSDictionary *rawHandlerGraph = HFAMapAnalyzeFeatureHandlerSnapshot(snapshot, selected);
        NSDictionary *handlerGraph = [HFAMapStaticCatalogAnnotateHandlerGraph(rawHandlerGraph,
            selected[@"image"] ?: @"") retain];
        HFADiagnosticsLog(@"feature-handler-graph", handlerGraph[@"status"] ?: @"complete", @{
            @"recordCount": handlerGraph[@"recordCount"] ?: @0,
            @"runtimeMethodCandidateCount": handlerGraph[@"runtimeMethodCandidateCount"] ?: @0,
            @"il2cppCorrelationCount": handlerGraph[@"il2cppCorrelationCount"] ?: @0,
            @"staticCatalogLoaded": handlerGraph[@"staticCatalogLoaded"] ?: @NO,
            @"staticCatalogMatchedBlockCount": handlerGraph[@"staticCatalogMatchedBlockCount"] ?: @0,
            @"staticCatalogMatchedRuntimeMethodCount": handlerGraph[@"staticCatalogMatchedRuntimeMethodCount"] ?: @0,
            @"policy": handlerGraph[@"policy"] ?: @""
        });
        HFADiagnosticsLog(@"ui-snapshot", @"complete", snapshot[@"metrics"] ?: @{});
        dispatch_async(HFAWorker(), ^{
            NSDictionary *resolved = HFAMapResolveFeatureSeeds(selected, snapshot, started + 9.0, events);
            NSArray *features = resolved[@"features"] ?: @[];
            NSArray *runtimeRecords = resolved[@"runtimeRecords"] ?: @[];
            NSDictionary *staticConsumers = HFAMapResolveStaticNativeConsumers(
                selected, resolved[@"registry"] ?: @[],
                NSDate.date.timeIntervalSince1970 + 2.0);
            HFADiagnosticsLog(@"static-native-consumer",
                              staticConsumers[@"status"] ?: @"complete", @{
                @"groupCount": staticConsumers[@"groupCount"] ?: @0,
                @"featureLinkCount": staticConsumers[@"featureLinkCount"] ?: @0,
                @"policy": staticConsumers[@"policy"] ?: @""
            });
            NSDictionary *consumerTargets = HFAMapResolveNativeConsumerTargets(
                selected, staticConsumers, NSDate.date.timeIntervalSince1970 + 1.5);
            HFADiagnosticsLog(@"native-consumer-target-bridge",
                              consumerTargets[@"status"] ?: @"complete", @{
                @"groupCount": consumerTargets[@"groupCount"] ?: @0,
                @"slotsInspected": consumerTargets[@"slotsInspected"] ?: @0,
                @"livePointers": consumerTargets[@"livePointers"] ?: @0,
                @"externalPointers": consumerTargets[@"externalPointers"] ?: @0,
                @"il2cppResolved": consumerTargets[@"il2cppResolved"] ?: @0,
                @"policy": consumerTargets[@"policy"] ?: @""
            });
            NSDictionary *runtimeTemplates = HFAMapResolveGenericRuntimeTemplates(
                selected, NSDate.date.timeIntervalSince1970 + 1.5);
            HFADiagnosticsLog(@"generic-runtime-template",
                              runtimeTemplates[@"status"] ?: @"complete", @{
                @"wrapperCount": runtimeTemplates[@"wrapperCount"] ?: @0,
                @"plaintextResolvedCount": runtimeTemplates[@"plaintextResolvedCount"] ?: @0,
                @"policy": runtimeTemplates[@"policy"] ?: @""
            });
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
                @"staticCatalog": HFAMapStaticCatalogCurrent() ?: @{},
                @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                @"staticNativeConsumerEvidence": staticConsumers ?: @{},
                @"nativeConsumerTargetEvidence": consumerTargets ?: @{},
                @"runtimeTemplateEvidence": runtimeTemplates ?: @{},
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
                @"staticCatalog": HFAMapStaticCatalogCurrent() ?: @{},
                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                @"hookSemanticEvidence": resolved[@"hookSemanticEvidence"] ?: @{},
                @"blockProvenanceEvidence": resolved[@"blockProvenanceEvidence"] ?: @[],
                @"actionProvenanceEvidence": resolved[@"actionProvenanceEvidence"] ?: @[],
                @"staticNativeConsumerEvidence": staticConsumers ?: @{},
                @"nativeConsumerTargetEvidence": consumerTargets ?: @{},
                @"runtimeTemplateEvidence": runtimeTemplates ?: @{},
                @"status": resolved[@"status"] ?: @"complete"
            }, HFAOutputFileName(@"FeatureRegistry.json"));
            HFAWriteJSON(@{
                @"schema": @"com.hfa.igmm.runtime/v1", @"session": session,
                @"candidate": selected, @"records": runtimeRecords,
                @"featureHandlerGraph": handlerGraph ?: @{},
                @"staticCatalog": HFAMapStaticCatalogCurrent() ?: @{},
                @"runtimeEvidence": resolved[@"runtimeEvidence"] ?: @{},
                @"analysisOnly": @YES,
                @"status": resolved[@"status"] ?: @"complete"
            }, HFAOutputFileName(@"RuntimeActions.json"));

            HFADiagnosticsFinishSession(analysis[@"status"], @{
                @"selectedImage": selected[@"image"] ?: @"?",
                @"validated": @(features.count),
                @"unresolved": @([resolved[@"unresolved"] count]),
                @"runtimeMethodCandidates": handlerGraph[@"runtimeMethodCandidateCount"] ?: @0,
                @"staticCatalogMatchedBlockCount": handlerGraph[@"staticCatalogMatchedBlockCount"] ?: @0,
                @"staticNativeConsumerGroups": staticConsumers[@"groupCount"] ?: @0,
                @"nativeConsumerTargetGroups": consumerTargets[@"groupCount"] ?: @0,
                @"nativeConsumerIL2CPPResolved": consumerTargets[@"il2cppResolved"] ?: @0,
                @"runtimeTemplatesResolved": runtimeTemplates[@"plaintextResolvedCount"] ?: @0,
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
