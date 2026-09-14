#import <Foundation/Foundation.h>
#include <stdio.h>

static NSString *HFAJSONDocuments(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
}

static void HFAJSONLog(NSString *message) {
    if (!message.length) return;
    NSString *path = [HFAJSONDocuments() stringByAppendingPathComponent:@"HFAMap_Learn.log"];
    FILE *f = fopen(path.fileSystemRepresentation, "a");
    if (!f) return;
    fprintf(f, "%s\n", message.UTF8String ?: "[JSON-EXPORT]");
    fflush(f);
    fclose(f);
}

static NSDictionary *HFAJSONRead(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    NSError *error = nil;
    id root = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    if (![root isKindOfClass:[NSDictionary class]]) {
        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT-READ-FAIL] path=%@ reason=%@",
                    path.lastPathComponent, error.localizedDescription ?: @"not-dictionary"]);
        return nil;
    }
    return root;
}

static NSString *HFAJSONControlKind(NSDictionary *feature) {
    NSString *type = [feature[@"type"] isKindOfClass:[NSString class]] ? feature[@"type"] : @"";
    NSString *primitive = [feature[@"executionPrimitive"] isKindOfClass:[NSString class]]
        ? feature[@"executionPrimitive"] : @"";

    if ([type isEqualToString:@"customSwitch"] ||
        [primitive isEqualToString:@"runtimeBoolean"])
        return @"toggle";

    if ([type isEqualToString:@"button"] ||
        [type isEqualToString:@"kTypeButton"] ||
        [primitive isEqualToString:@"runtimeAction"] ||
        [primitive isEqualToString:@"blockHandler"])
        return @"button";

    if ([type isEqualToString:@"modtext"] ||
        [type isEqualToString:@"textfield"] ||
        [type isEqualToString:@"textField"] ||
        [primitive isEqualToString:@"numericRuntimeModifier"])
        return @"number";

    return @"unknown";
}

static NSArray *HFAJSONCanonicalFeatures(NSDictionary *package) {
    NSArray *raw = [package[@"features"] isKindOfClass:[NSArray class]] ? package[@"features"] : @[];
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *feature in raw) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *identifier = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : nil;
        if (!identifier.length) continue;
        NSMutableDictionary *record = [NSMutableDictionary dictionary];
        record[@"id"] = identifier;
        record[@"title"] = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : identifier;
        record[@"group"] = [feature[@"group"] isKindOfClass:[NSString class]] ? feature[@"group"] : @"Imported";
        record[@"control"] = @{ @"kind": @"toggle",
                                 @"default": @([feature[@"defaultEnabled"] boolValue]) };
        record[@"analysisKind"] = @"canonical-byte-patch";
        record[@"canonicalEligible"] = @YES;
        NSArray *patches = [feature[@"patches"] isKindOfClass:[NSArray class]] ? feature[@"patches"] : @[];
        record[@"patches"] = patches;
        [out addObject:record];
    }
    return out;
}

static NSArray *HFAJSONIGMMFeatures(NSDictionary *report) {
    NSArray *raw = [report[@"features"] isKindOfClass:[NSArray class]] ? report[@"features"] : @[];
    NSMutableArray *out = [NSMutableArray array];
    for (NSDictionary *feature in raw) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *identifier = [feature[@"id"] isKindOfClass:[NSString class]] ? feature[@"id"] : nil;
        if (!identifier.length) continue;
        NSMutableDictionary *record = [NSMutableDictionary dictionary];
        record[@"id"] = identifier;
        record[@"title"] = [feature[@"title"] isKindOfClass:[NSString class]] ? feature[@"title"] : identifier;
        NSString *kind = HFAJSONControlKind(feature);
        NSMutableDictionary *control = [@{ @"kind": kind } mutableCopy];
        NSDictionary *config = [feature[@"config"] isKindOfClass:[NSDictionary class]] ? feature[@"config"] : nil;
        id defaultValue = config[@"defaultValue"];
        if (defaultValue && defaultValue != [NSNull null] &&
            ([defaultValue isKindOfClass:[NSNumber class]] || [defaultValue isKindOfClass:[NSString class]]))
            control[@"default"] = defaultValue;
        record[@"control"] = control;
        record[@"analysisKind"] = @"igmm-runtime-definition";
        if ([feature[@"type"] isKindOfClass:[NSString class]]) record[@"type"] = feature[@"type"];
        if ([feature[@"backend"] isKindOfClass:[NSString class]]) record[@"backend"] = feature[@"backend"];
        if ([feature[@"executionPrimitive"] isKindOfClass:[NSString class]])
            record[@"executionPrimitive"] = feature[@"executionPrimitive"];
        record[@"canonicalEligible"] = @([feature[@"canonicalEligible"] boolValue]);
        if ([feature[@"canonicalReason"] isKindOfClass:[NSString class]])
            record[@"canonicalReason"] = feature[@"canonicalReason"];
        if (config.count) record[@"config"] = config;
        if ([feature[@"runtime"] isKindOfClass:[NSDictionary class]])
            record[@"runtimeEvidence"] = feature[@"runtime"];
        [out addObject:record];
    }
    return out;
}

BOOL HFAMapJSONExportLatest(void) {
    @autoreleasepool {
        NSBundle *bundle = NSBundle.mainBundle;
        NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
        NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
        NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
        NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
        NSString *prefix = [NSString stringWithFormat:@"%@_%@_%@", safeID, shortVersion, buildVersion];
        NSString *docs = HFAJSONDocuments();

        NSString *canonicalName = [prefix stringByAppendingString:@".hfapatch.json"];
        NSString *identityName = [prefix stringByAppendingString:@".hfapatch.identity.json"];
        NSString *igmmName = [prefix stringByAppendingString:@".hfamap.igmm.json"];
        NSString *canonicalPath = [docs stringByAppendingPathComponent:canonicalName];
        NSString *identityPath = [docs stringByAppendingPathComponent:identityName];
        NSString *igmmPath = [docs stringByAppendingPathComponent:igmmName];

        NSDictionary *canonical = HFAJSONRead(canonicalPath);
        NSDictionary *igmm = HFAJSONRead(igmmPath);
        BOOL haveIdentity = [[NSFileManager defaultManager] fileExistsAtPath:identityPath];

        NSMutableArray *features = [NSMutableArray array];
        NSMutableArray *sources = [NSMutableArray array];
        if ([canonical[@"schema"] isEqual:@"com.hfa.patch/v1"]) {
            [features addObjectsFromArray:HFAJSONCanonicalFeatures(canonical)];
            [sources addObject:@{ @"kind": @"canonical", @"file": canonicalName,
                                  @"schema": @"com.hfa.patch/v1" }];
        }
        if ([igmm[@"schema"] isEqual:@"com.hfa.igmm.runtime/v1"]) {
            [features addObjectsFromArray:HFAJSONIGMMFeatures(igmm)];
            [sources addObject:@{ @"kind": @"igmm-diagnostic", @"file": igmmName,
                                  @"schema": @"com.hfa.igmm.runtime/v1" }];
        }

        if (!features.count) {
            HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=skip reason=no-analysis-output prefix=%@", prefix]);
            return NO;
        }

        NSDictionary *package = @{
            @"bundleIdentifier": bundleID,
            @"shortVersion": shortVersion,
            @"buildVersion": buildVersion
        };
        NSMutableDictionary *root = [@{
            @"schema": @"com.hfa.menu.analysis/v1",
            @"analyzer": @"HFAMapUniversal v1.9.36.2 JSONExport",
            @"analysisOnly": @YES,
            @"package": package,
            @"sources": sources,
            @"features": features
        } mutableCopy];
        if (haveIdentity) root[@"identityFile"] = identityName;
        if ([igmm[@"menu"] isKindOfClass:[NSDictionary class]]) root[@"menu"] = igmm[@"menu"];

        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];
        if (!json) {
            HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=fail reason=json-encode error=%@",
                        error.localizedDescription ?: @"unknown"]);
            return NO;
        }
        NSString *name = [prefix stringByAppendingString:@".hfamap.analysis.json"];
        NSString *path = [docs stringByAppendingPathComponent:name];
        if (![json writeToFile:path options:NSDataWritingAtomic error:&error]) {
            HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=fail reason=write file=%@ error=%@",
                        name, error.localizedDescription ?: @"unknown"]);
            return NO;
        }
        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no"]);
        return YES;
    }
}
