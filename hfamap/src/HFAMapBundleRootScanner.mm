#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "HFAMapStaticCatalog.h"
#import "HFAMapImportedDylibEvidenceAnalyzer.h"
#import "HFAMapLoadedDylibEvidenceResolver.h"
#import "HFAMapRuntimeRootGraphResolver.h"
#import "HFAMapDirectedDescriptorResolver.h"
#import "HFAMapSecretWrapperEvidenceResolver.h"
#import "HFAMapDiagnostics.h"
#include <unistd.h>

static const NSUInteger kHFABundleScanMaxDepth = 12;
static const NSUInteger kHFABundleScanMaxFiles = 512;
static const NSUInteger kHFABundlePickerMaxItems = 128;
static const NSUInteger kHFADirectedRetryCount = 3;
static const useconds_t kHFADirectedRetryDelayUS[] = { 0, 500000, 1500000 };

static UIViewController *HFABundleTopController(void) {
    UIApplication *app = UIApplication.sharedApplication;
    UIWindow *window = nil;
    for (UIWindow *candidate in app.windows) if (candidate.isKeyWindow && !candidate.hidden && candidate.alpha > 0.0) { window = candidate; break; }
    if (!window) window = app.keyWindow ?: app.windows.lastObject;
    UIViewController *controller = window.rootViewController;
    while (controller.presentedViewController) controller = controller.presentedViewController;
    if ([controller isKindOfClass:UINavigationController.class]) controller = [(UINavigationController *)controller topViewController];
    if ([controller isKindOfClass:UITabBarController.class]) controller = [(UITabBarController *)controller selectedViewController];
    return controller;
}

static void HFAAppendDylibsFromRoot(NSString *root, NSString *label, NSMutableArray *results, NSMutableSet *seen) {
    if (!root.length || results.count >= kHFABundleScanMaxFiles) return;
    NSDirectoryEnumerator *e = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:root isDirectory:YES]
        includingPropertiesForKeys:@[NSURLIsRegularFileKey, NSURLFileSizeKey, NSURLIsSymbolicLinkKey]
        options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:^BOOL(__unused NSURL *u, __unused NSError *er){ return YES; }];
    for (NSURL *u in e) {
        if (results.count >= kHFABundleScanMaxFiles) break;
        NSString *p = u.path ?: @"";
        if (p.length <= root.length) continue;
        NSString *rel = [p substringFromIndex:MIN(root.length + 1, p.length)];
        NSUInteger depth = rel.pathComponents.count;
        if (depth > kHFABundleScanMaxDepth) { [e skipDescendants]; continue; }
        NSNumber *regular=nil,*symlink=nil,*size=nil;
        [u getResourceValue:&regular forKey:NSURLIsRegularFileKey error:nil];
        [u getResourceValue:&symlink forKey:NSURLIsSymbolicLinkKey error:nil];
        if (![regular boolValue] || [symlink boolValue] || ![u.pathExtension.lowercaseString isEqualToString:@"dylib"] || [seen containsObject:p]) continue;
        [u getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        [seen addObject:p];
        [results addObject:@{ @"name":u.lastPathComponent?:@"?", @"path":p, @"relativePath":rel?:@"", @"size":size?:@0, @"rootLabel":label?:@"ROOT", @"depth":@(depth) }];
    }
}

static NSArray *HFADeepBundleDylibInventory(void) {
    NSMutableArray *r=[NSMutableArray array]; NSMutableSet *s=[NSMutableSet set];
    HFAAppendDylibsFromRoot(NSBundle.mainBundle.bundlePath,@"APP",r,s);
    HFAAppendDylibsFromRoot(NSHomeDirectory(),@"DATA",r,s);
    [r sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b){ return [(a[@"relativePath"]?:@"") compare:(b[@"relativePath"]?:@"") options:NSCaseInsensitiveSearch]; }];
    return r;
}

static BOOL HFADirectedResultUsable(NSDictionary *directed) {
    if (![directed isKindOfClass:NSDictionary.class]) return NO;
    NSArray *features = directed[@"featureResolutions"];
    NSDictionary *graph = directed[@"graph"];
    NSUInteger descriptorCount = [graph[@"descriptorCandidateCount"] unsignedIntegerValue];
    if (features.count == 0) return NO;
    for (NSDictionary *feature in features)
        if ([feature[@"descriptorMatchCount"] unsignedIntegerValue] > 0) return YES;
    return descriptorCount > 0;
}

static NSDictionary *HFAResolveDirectedWithRetry(NSString *path, NSDictionary *rootGraph,
                                                  NSArray **attemptsOut, NSError **errorOut) {
    NSMutableArray *attempts = [NSMutableArray array];
    NSDictionary *best = nil;
    NSError *lastError = nil;
    for (NSUInteger attempt = 0; attempt < kHFADirectedRetryCount; ++attempt) {
        useconds_t delay = kHFADirectedRetryDelayUS[attempt];
        if (delay) usleep(delay);
        NSError *attemptError = nil;
        NSDictionary *current = HFAMapResolveDirectedDescriptors(path, rootGraph ?: @{}, &attemptError);
        NSArray *features = current[@"featureResolutions"] ?: @[];
        NSDictionary *graph = current[@"graph"] ?: @{};
        NSUInteger resolved = 0;
        for (NSDictionary *feature in features)
            if ([feature[@"descriptorMatchCount"] unsignedIntegerValue] > 0) ++resolved;
        NSDictionary *summary = @{
            @"attempt": @(attempt + 1),
            @"delayMilliseconds": @(delay / 1000),
            @"featureCount": @(features.count),
            @"resolvedFeatureCount": @(resolved),
            @"descriptorCandidateCount": graph[@"descriptorCandidateCount"] ?: @0,
            @"nodeCount": graph[@"nodeCount"] ?: @0,
            @"usable": @(HFADirectedResultUsable(current)),
            @"error": attemptError.localizedDescription ?: @""
        };
        [attempts addObject:summary];
        HFADiagnosticsLog(@"directed-retry", @"attempt", summary);
        if (current) best = current;
        if (attemptError) lastError = attemptError;
        if (HFADirectedResultUsable(current)) break;
    }
    if (attemptsOut) *attemptsOut = attempts;
    if (errorOut && lastError && !best) *errorOut = lastError;
    if (!best) return nil;
    NSMutableDictionary *annotated = [[best mutableCopy] autorelease];
    annotated[@"stabilization"] = @{
        @"policy": @"BOUNDED-LIVE-UI-RETRY",
        @"maxAttempts": @(kHFADirectedRetryCount),
        @"attemptCount": @(attempts.count),
        @"attempts": attempts,
        @"finalUsable": @(HFADirectedResultUsable(best))
    };
    return annotated;
}

static void HFAPresentResult(NSDictionary *evidence, NSDictionary *loadedEvidence, NSDictionary *rootGraph, NSDictionary *directed, NSDictionary *secretEvidence, NSError *error) {
    UIViewController *c = HFABundleTopController(); if (!c) return;
    NSString *msg = nil;
    if (evidence) {
        BOOL loaded = [loadedEvidence[@"loaded"] boolValue];
        NSDictionary *graph = rootGraph[@"graph"] ?: @{};
        NSDictionary *dgraph = directed[@"graph"] ?: @{};
        NSArray *features = directed[@"featureResolutions"] ?: @[];
        NSDictionary *stabilization = directed[@"stabilization"] ?: @{};
        NSUInteger resolved = 0;
        for (NSDictionary *feature in features) if ([feature[@"descriptorMatchCount"] unsignedIntegerValue] > 0) ++resolved;
        msg = [NSString stringWithFormat:@"Universal Evidence READY ✅\n%@\nstatic: features %@ · patches %@ · offsets %@\nruntime-loaded: %@\nclasses %@ · methods %@ · fields %@\nroots %@ · nodes %@ · descriptors %@\ndirected: features %lu · resolved %lu · candidates %@ · attempts %@\nsecret wrappers: %@\nEvidence JSON saved",
            evidence[@"source"][@"fileName"]?:@"dylib",
            @([evidence[@"featureEvidence"] count]), @([evidence[@"patchEvidence"] count]), @([evidence[@"offsetEvidence"] count]), loaded ? @"YES ✅" : @"NO",
            loadedEvidence[@"classCount"] ?: @0, loadedEvidence[@"methodInImageCount"] ?: @0, @([loadedEvidence[@"structuralFields"] count]),
            graph[@"rootCount"] ?: @0, graph[@"nodeCount"] ?: @0, graph[@"descriptorCandidateCount"] ?: @0,
            (unsigned long)features.count, (unsigned long)resolved, dgraph[@"descriptorCandidateCount"] ?: @0,
            stabilization[@"attemptCount"] ?: @1, secretEvidence[@"wrapperEvidenceCount"] ?: @0];
        if (!loaded && error) msg = [msg stringByAppendingFormat:@"\nloaded resolver: %@", error.localizedDescription ?: @"not-loaded"];
    } else msg = [NSString stringWithFormat:@"Analysis failed\n%@", error.localizedDescription?:@"unknown error"];
    UIAlertController *a=[UIAlertController alertControllerWithTitle:@"HFAMap v2.5.12" message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]]; [c presentViewController:a animated:YES completion:nil];
}

static void HFAAnalyzeImportedPath(NSString *path) {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
        NSError *catalogError=nil; NSDictionary *catalog=HFAMapStaticCatalogAnalyzeFile(path,&catalogError);
        NSError *catalogPersistError=nil; if (catalog) HFAMapStaticCatalogRegisterAndPersist(catalog,&catalogPersistError);
        NSError *evidenceError=nil; NSDictionary *evidence=HFAMapAnalyzeImportedDylibEvidence(path,catalog?:@{},&evidenceError);
        NSError *evidencePersistError=nil; BOOL saved=evidence && HFAMapPersistImportedDylibEvidence(evidence,&evidencePersistError);
        NSError *loadedError=nil; NSDictionary *loadedEvidence = saved ? HFAMapResolveLoadedDylibEvidence(path,evidence,&loadedError) : nil;
        NSError *loadedPersistError=nil; BOOL loadedSaved = loadedEvidence && HFAMapPersistLoadedDylibEvidence(loadedEvidence,&loadedPersistError);
        NSError *rootGraphError=nil; NSDictionary *rootGraph = loadedEvidence ? HFAMapResolveRuntimeRootGraph(path,loadedEvidence,&rootGraphError) : nil;
        NSError *rootGraphPersistError=nil; BOOL rootGraphSaved = rootGraph && HFAMapPersistRuntimeRootGraph(rootGraph,&rootGraphPersistError);
        NSArray *directedAttempts=nil; NSError *directedError=nil;
        NSDictionary *directed = rootGraph ? HFAResolveDirectedWithRetry(path,rootGraph,&directedAttempts,&directedError) : nil;
        NSError *directedPersistError=nil; BOOL directedSaved = directed && HFAMapPersistDirectedDescriptors(directed,&directedPersistError);
        NSError *secretError=nil; NSDictionary *secretEvidence = directed ? HFAMapResolveSecretWrapperEvidence(path,directed,&secretError) : nil;
        NSError *secretPersistError=nil; BOOL secretSaved = secretEvidence && HFAMapPersistSecretWrapperEvidence(secretEvidence,&secretPersistError);
        NSError *finalError=evidenceError?:evidencePersistError?:loadedError?:loadedPersistError?:rootGraphError?:rootGraphPersistError?:directedError?:directedPersistError?:secretError?:secretPersistError?:catalogError?:catalogPersistError;
        NSDictionary *graph=rootGraph[@"graph"]?:@{}; NSDictionary *dgraph=directed[@"graph"]?:@{}; NSArray *features=directed[@"featureResolutions"]?:@[];
        NSUInteger resolved=0; for(NSDictionary *feature in features) if([feature[@"descriptorMatchCount"] unsignedIntegerValue]>0) ++resolved;
        HFADiagnosticsLog(@"imported-dylib-evidence", saved?@"ui-ready":@"ui-failed", @{
            @"file":path.lastPathComponent?:@"", @"saved":@(saved), @"loadedRuntimeEvidence":@(loadedEvidence!=nil), @"loadedRuntimeEvidenceSaved":@(loadedSaved),
            @"loadedClassCount":loadedEvidence[@"classCount"]?:@0, @"loadedMethodInImageCount":loadedEvidence[@"methodInImageCount"]?:@0, @"loadedStructuralFieldCount":@([loadedEvidence[@"structuralFields"] count]),
            @"runtimeRootGraph":@(rootGraph!=nil), @"runtimeRootGraphSaved":@(rootGraphSaved), @"runtimeRootCount":graph[@"rootCount"]?:@0, @"runtimeNodeCount":graph[@"nodeCount"]?:@0, @"runtimeDescriptorCandidateCount":graph[@"descriptorCandidateCount"]?:@0,
            @"directedDescriptors":@(directed!=nil), @"directedDescriptorsSaved":@(directedSaved), @"directedFeatureCount":@(features.count), @"directedResolvedFeatureCount":@(resolved), @"directedDescriptorCandidateCount":dgraph[@"descriptorCandidateCount"]?:@0,
            @"directedRetryAttemptCount":@(directedAttempts.count), @"directedRetryAttempts":directedAttempts?:@[],
            @"secretWrapperEvidence":@(secretEvidence!=nil), @"secretWrapperEvidenceSaved":@(secretSaved), @"secretWrapperEvidenceCount":secretEvidence[@"wrapperEvidenceCount"]?:@0 });
        dispatch_async(dispatch_get_main_queue(), ^{ HFAPresentResult(saved?evidence:nil,loadedEvidence,rootGraph,directed,secretEvidence,finalError); });
    });
}

static void HFAStaticAnalyzeBundleRootReplacement(__unused id self, __unused SEL _cmd) {
    UIViewController *controller=HFABundleTopController(); if (!controller) return;
    NSArray *files=HFADeepBundleDylibInventory();
    if (!files.count) { HFAPresentResult(nil,nil,nil,nil,nil,[NSError errorWithDomain:@"com.hfa.import" code:1 userInfo:@{NSLocalizedDescriptionKey:@"No .dylib found under APP Bundle or DATA container"}]); return; }
    UIAlertController *picker=[UIAlertController alertControllerWithTitle:nil message:nil preferredStyle:UIAlertControllerStyleActionSheet];
    NSUInteger limit=MIN(files.count,kHFABundlePickerMaxItems);
    for(NSUInteger i=0;i<limit;i++) { NSDictionary *entry=files[i]; NSString *title=[NSString stringWithFormat:@"[%@] %@",entry[@"rootLabel"]?:@"?",entry[@"relativePath"]?:entry[@"name"]?:@"dylib"];
        [picker addAction:[UIAlertAction actionWithTitle:title style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *a){ HFAAnalyzeImportedPath(entry[@"path"]); }]]; }
    [picker addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    UIPopoverPresentationController *p=picker.popoverPresentationController; if(p){p.sourceView=controller.view;p.sourceRect=CGRectMake(CGRectGetMidX(controller.view.bounds),CGRectGetMidY(controller.view.bounds),1,1);p.permittedArrowDirections=0;}
    [controller presentViewController:picker animated:YES completion:nil];
}

static void HFAInstallBundleRootScannerOverride(void) {
    Class cls=NSClassFromString(@"HFAMapFloatingTarget");
    if(!cls){dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{HFAInstallBundleRootScannerOverride();});return;}
    Method m=class_getInstanceMethod(cls,@selector(staticAnalyze)); if(!m)return; method_setImplementation(m,(IMP)HFAStaticAnalyzeBundleRootReplacement);
    NSLog(@"[HFAMap] v2.5.12 UNIVERSAL directed retry stabilization installed");
}
__attribute__((constructor)) static void HFABundleRootScannerConstructor(void){dispatch_async(dispatch_get_main_queue(),^{HFAInstallBundleRootScannerOverride();});}
