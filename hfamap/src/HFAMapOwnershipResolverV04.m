#import <Foundation/Foundation.h>
#include <stdio.h>

extern unsigned HFAAnalyzerV02ScanSelectedImage(void);
extern NSArray *HFA5MDispatcherAllEvidence(void);
extern const char *HFAAppLocalPrimaryImage(void);

static NSMutableArray *gHFAV04Features;
static BOOL gHFAV04Analyzed;

static void HFAV04Log(NSString *line) {
    if (!line.length) return;
    @synchronized([NSFileHandle class]) {
        NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/HFAMap_Learn.log"];
        FILE *f = fopen(path.fileSystemRepresentation, "a");
        if (!f) return;
        fprintf(f, "%s\n", line.UTF8String ?: "[V04]");
        fflush(f);
        fclose(f);
    }
}

static NSString *HFAV04Documents(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static NSDictionary *HFAV04ReadJSON(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data.length) return nil;
    id root = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    return [root isKindOfClass:[NSDictionary class]] ? root : nil;
}

static BOOL HFAV04WriteJSON(id root, NSString *path) {
    if (!root || !path.length || ![NSJSONSerialization isValidJSONObject:root]) return NO;
    NSData *data = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:nil];
    return data.length && [data writeToFile:path atomically:YES];
}

static NSMutableDictionary *HFAV04FindFeature(NSMutableArray *features, NSString *identifier, NSString *title) {
    for (NSMutableDictionary *feature in features) {
        NSString *fid = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : @"";
        NSString *ftitle = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : @"";
        if (identifier.length && [fid caseInsensitiveCompare:identifier] == NSOrderedSame) return feature;
        if (title.length && [ftitle caseInsensitiveCompare:title] == NSOrderedSame) return feature;
    }
    return nil;
}

static void HFAV04MergeEvidence(NSMutableDictionary *feature, NSString *key, id evidence) {
    if (!feature || !key.length || !evidence) return;
    NSMutableDictionary *runtime = [feature[@"runtimeEvidence"] isKindOfClass:[NSDictionary class]]
        ? [feature[@"runtimeEvidence"] mutableCopy] : [NSMutableDictionary dictionary];
    runtime[key] = evidence;
    feature[@"runtimeEvidence"] = runtime;
}

unsigned HFAOwnershipV04Analyze(void) {
    @synchronized([NSFileHandle class]) {
        unsigned nativeCandidates = HFAAnalyzerV02ScanSelectedImage();
        NSString *docs = HFAV04Documents();
        NSDictionary *low = HFAV04ReadJSON([docs stringByAppendingPathComponent:@"HFAMap_RuntimeAnalyzer_v03.json"]) ?: @{};
        NSArray *descriptors = [low[@"descriptors"] isKindOfClass:[NSArray class]] ? low[@"descriptors"] : @[];
        NSArray *dispatcher = HFA5MDispatcherAllEvidence() ?: @[];
        NSMutableArray *features = [NSMutableArray array];

        for (NSDictionary *record in descriptors) {
            if (![[record[@"sink"] description] isEqualToString:@"native-hook"]) continue;
            NSArray *hints = [record[@"featureHints"] isKindOfClass:[NSArray class]] ? record[@"featureHints"] : @[];
            if (!hints.count) hints = @[[NSString stringWithFormat:@"native@%@", record[@"descriptorRVA"] ?: @"?"]];
            for (NSString *hint in hints) {
                if (![hint isKindOfClass:[NSString class]] || !hint.length) continue;
                NSMutableDictionary *feature = HFAV04FindFeature(features, hint, hint);
                if (!feature) {
                    feature = [@{ @"id": hint, @"title": hint } mutableCopy];
                    [features addObject:feature];
                }
                feature[@"backend"] = @"native-hook";
                feature[@"executionPrimitive"] = @"nativeHook";
                feature[@"runtimeResolved"] = @YES;
                HFAV04MergeEvidence(feature, @"nativeHook", record);
            }
        }

        for (NSDictionary *record in dispatcher) {
            NSString *identifier = [record[@"identifier"] isKindOfClass:[NSString class]] ? record[@"identifier"] : @"";
            NSString *title = [record[@"title"] isKindOfClass:[NSString class]] ? record[@"title"] : identifier;
            if (!identifier.length) continue;
            NSMutableDictionary *feature = HFAV04FindFeature(features, identifier, title);
            if (!feature) {
                feature = [@{ @"id": identifier, @"title": title.length ? title : identifier } mutableCopy];
                [features addObject:feature];
            }
            if (!feature[@"backend"]) feature[@"backend"] = @"runtime-5m";
            feature[@"dispatcherResolved"] = @([record[@"dispatcherResolved"] boolValue]);
            feature[@"downstreamCallbackResolved"] = @([record[@"downstreamCallbackResolved"] boolValue]);
            HFAV04MergeEvidence(feature, @"dispatcher", record);
        }

        const char *image = HFAAppLocalPrimaryImage();
        NSString *imageName = image && *image ? [NSString stringWithUTF8String:image] : @"?";
        NSDictionary *root = @{
            @"schema": @"com.hfa.runtime-analyzer/v0.4",
            @"image": imageName ?: @"?",
            @"lowLevelNativeCandidates": @(nativeCandidates),
            @"analyzer": low,
            @"dispatcherEvidence": dispatcher,
            @"features": features
        };
        NSString *out = [docs stringByAppendingPathComponent:@"HFAMap_RuntimeAnalyzer_v04.json"];
        BOOL wrote = HFAV04WriteJSON(root, out);
        gHFAV04Features = features;
        gHFAV04Analyzed = YES;
        HFAV04Log([NSString stringWithFormat:@"[V04-SCAN-END] image=%@ features=%lu native=%u dispatchers=%lu wrote=%d",
                   imageName, (unsigned long)features.count, nativeCandidates,
                   (unsigned long)dispatcher.count, wrote ? 1 : 0]);
        return (unsigned)features.count;
    }
}

BOOL HFAOwnershipV04MergeLatestAnalysis(void) {
    @synchronized([NSFileHandle class]) {
        if (!gHFAV04Analyzed) HFAOwnershipV04Analyze();
        if (!gHFAV04Features.count) return NO;

        NSBundle *bundle = NSBundle.mainBundle;
        NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
        NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
        NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
        NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        NSString *prefix = [NSString stringWithFormat:@"%@_%@_%@", safeID, shortVersion, buildVersion];
        NSString *path = [HFAV04Documents() stringByAppendingPathComponent:[prefix stringByAppendingString:@".hfamap.analysis.json"]];
        NSDictionary *existingRoot = HFAV04ReadJSON(path);
        if (!existingRoot) return NO;

        NSMutableDictionary *root = [existingRoot mutableCopy];
        NSMutableArray *analysisFeatures = [NSMutableArray array];
        NSArray *oldFeatures = [root[@"features"] isKindOfClass:[NSArray class]] ? root[@"features"] : @[];
        for (NSDictionary *item in oldFeatures)
            [analysisFeatures addObject:[item isKindOfClass:[NSDictionary class]] ? [item mutableCopy] : item];

        unsigned merged = 0, appended = 0;
        for (NSDictionary *ownership in gHFAV04Features) {
            NSString *identifier = [ownership[@"id"] isKindOfClass:[NSString class]] ? ownership[@"id"] : @"";
            NSString *title = [ownership[@"title"] isKindOfClass:[NSString class]] ? ownership[@"title"] : identifier;
            NSMutableDictionary *target = HFAV04FindFeature(analysisFeatures, identifier, title);
            if (!target) {
                target = [@{ @"id": identifier.length ? identifier : title,
                             @"title": title.length ? title : identifier,
                             @"group": @"Imported",
                             @"patches": @[],
                             @"canonicalEligible": @NO } mutableCopy];
                [analysisFeatures addObject:target];
                appended++;
            }

            NSDictionary *runtime = [ownership[@"runtimeEvidence"] isKindOfClass:[NSDictionary class]] ? ownership[@"runtimeEvidence"] : @{};
            NSDictionary *native = [runtime[@"nativeHook"] isKindOfClass:[NSDictionary class]] ? runtime[@"nativeHook"] : nil;
            NSDictionary *disp = [runtime[@"dispatcher"] isKindOfClass:[NSDictionary class]] ? runtime[@"dispatcher"] : nil;
            if (native) {
                target[@"backend"] = @"native-hook";
                target[@"analysisKind"] = @"runtime-native-hook";
                target[@"executionPrimitive"] = @"nativeHook";
                target[@"runtimeResolved"] = @YES;
                target[@"canonicalEligible"] = @NO;
                target[@"canonicalReason"] = @"runtime-native-hook-confirmed";
                HFAV04MergeEvidence(target, @"nativeHook", native);
            }
            if (disp) {
                HFAV04MergeEvidence(target, @"dispatcher", disp);
                target[@"dispatcherResolved"] = @([ownership[@"dispatcherResolved"] boolValue]);
                target[@"downstreamCallbackResolved"] = @([ownership[@"downstreamCallbackResolved"] boolValue]);
                if (!native && [[target[@"backend"] description] isEqualToString:@"runtime-observed"])
                    target[@"backend"] = @"runtime-5m";
            }
            merged++;
        }

        root[@"features"] = analysisFeatures;
        root[@"ownershipV04"] = @{ @"schema": @"com.hfa.runtime-analyzer/v0.4",
                                     @"mergedFeatures": @(merged),
                                     @"appendedFeatures": @(appended),
                                     @"source": @"HFAMap_RuntimeAnalyzer_v04.json" };
        BOOL wrote = HFAV04WriteJSON(root, path);
        HFAV04Log([NSString stringWithFormat:@"[V04-ANALYSIS-MERGE] merged=%u appended=%u wrote=%d",
                   merged, appended, wrote ? 1 : 0]);
        return wrote;
    }
}
