from pathlib import Path

p = Path("hfapatch-consumer/src/HFAPatchConsumer.m")
s = p.read_text()


def replace_once(old, new, label):
    global s
    count = s.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    s = s.replace(old, new, 1)


replace_once(
    'static NSString *const HFAPCVersion = @"1.0.0";',
    'static NSString *const HFAPCVersion = @"1.1.0";',
    'consumer version',
)

normalize_helper = r'''static NSArray<NSDictionary *> *HFAPCNormalizeFeaturesForPlayback(NSDictionary *package,
                                                                          NSArray<NSDictionary *> *features,
                                                                          NSString **errorOut) {
    NSString *schema = package[@"schema"];
    if ([schema isEqualToString:@"com.hfa.patch/v1"]) return features;
    if (![schema isEqualToString:@"com.hfa.feature/v2"]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"unsupported-package-schema:%@", schema ?: @"?"];
        return nil;
    }

    NSMutableArray<NSDictionary *> *normalized = [NSMutableArray array];
    for (NSDictionary *feature in features) {
        if (![feature isKindOfClass:[NSDictionary class]]) {
            if (errorOut) *errorOut = @"v2-feature-not-dictionary";
            return nil;
        }
        NSString *fid = feature[@"id"];
        NSString *title = feature[@"title"];
        NSString *group = feature[@"group"];
        NSDictionary *control = feature[@"control"];
        NSDictionary *execution = feature[@"execution"];
        if (![fid isKindOfClass:[NSString class]] || !fid.length ||
            ![title isKindOfClass:[NSString class]] || !title.length ||
            ![group isKindOfClass:[NSString class]] || !group.length ||
            ![control isKindOfClass:[NSDictionary class]] ||
            ![execution isKindOfClass:[NSDictionary class]]) {
            if (errorOut) *errorOut = [NSString stringWithFormat:@"v2-feature-record-invalid:%@", fid ?: @"?"];
            return nil;
        }

        NSString *controlKind = control[@"kind"];
        NSString *executionKind = execution[@"kind"];
        if (![executionKind isEqualToString:@"bytePatch"]) {
            if (errorOut) *errorOut = [NSString stringWithFormat:@"v2-execution-not-playable:%@:%@", fid, executionKind ?: @"?"];
            return nil;
        }
        if (![controlKind isEqualToString:@"toggle"]) {
            if (errorOut) *errorOut = [NSString stringWithFormat:@"v2-bytepatch-control-not-toggle:%@:%@", fid, controlKind ?: @"?"];
            return nil;
        }

        NSNumber *defaultValue = control[@"default"];
        NSArray *patches = execution[@"patches"];
        if (![defaultValue isKindOfClass:[NSNumber class]] ||
            ![patches isKindOfClass:[NSArray class]] || patches.count == 0) {
            if (errorOut) *errorOut = [NSString stringWithFormat:@"v2-bytepatch-record-invalid:%@", fid];
            return nil;
        }

        [normalized addObject:@{
            @"id": fid,
            @"title": title,
            @"group": group,
            @"defaultEnabled": @([defaultValue boolValue]),
            @"patches": patches
        }];
    }
    if (!normalized.count) {
        if (errorOut) *errorOut = @"v2-no-playable-features";
        return nil;
    }
    return normalized;
}

'''

anchor = 'static BOOL HFAPCBuildPlan(NSDictionary *package,\n'
if s.count(anchor) != 1:
    raise SystemExit(f"normalize helper anchor: expected 1 match, got {s.count(anchor)}")
s = s.replace(anchor, normalize_helper + anchor, 1)

replace_once(
'''        NSDictionary *package = HFAPCReadJSON(HFAPCPath(packageName), &error);
        if (!package || ![package[@"schema"] isEqual:@"com.hfa.patch/v1"]) {
            error = error ?: @"package-schema-not-com.hfa.patch/v1";
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
''',
'''        NSDictionary *package = HFAPCReadJSON(HFAPCPath(packageName), &error);
        NSString *packageSchema = [package[@"schema"] isKindOfClass:[NSString class]] ? package[@"schema"] : nil;
        BOOL schemaSupported = [packageSchema isEqualToString:@"com.hfa.patch/v1"] ||
                               [packageSchema isEqualToString:@"com.hfa.feature/v2"];
        if (!package || !schemaSupported) {
            error = error ?: [NSString stringWithFormat:@"package-schema-unsupported:%@", packageSchema ?: @"?"];
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
''',
    'package schema gate',
)

replace_once(
'''        NSArray<NSDictionary *> *features = HFAPCSelectedFeatures(package, featureIds, &error);
        if (!features) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSMutableArray<HFAPCPatchPlan *> *plans = [NSMutableArray array];
''',
'''        NSArray<NSDictionary *> *features = HFAPCSelectedFeatures(package, featureIds, &error);
        if (!features) {
            HFAPCWriteJSON(HFAPCResultBase(@"fail", action, error), HFAPCPath(HFAPCResultName));
            return;
        }
        NSArray<NSDictionary *> *playbackFeatures = HFAPCNormalizeFeaturesForPlayback(package, features, &error);
        if (!playbackFeatures) {
            NSMutableDictionary *result = [HFAPCResultBase(@"fail", action, error) mutableCopy];
            result[@"package"] = packageName;
            result[@"identity"] = identityName;
            result[@"featureIds"] = featureIds;
            result[@"packageSchema"] = packageSchema ?: @"";
            HFAPCWriteJSON(result, HFAPCPath(HFAPCResultName));
            HFAPCLog(@"[V2-NORMALIZE] status=fail schema=%@ reason=%@", packageSchema ?: @"?", error ?: @"unknown");
            return;
        }
        NSMutableArray<HFAPCPatchPlan *> *plans = [NSMutableArray array];
''',
    'feature normalization insertion',
)

replace_once(
    'if (!HFAPCBuildPlan(package, identity, features, action, plans, targetRecords, &error)) {',
    'if (!HFAPCBuildPlan(package, identity, playbackFeatures, action, plans, targetRecords, &error)) {',
    'build plan normalized features',
)

replace_once(
'''        result[@"featureIds"] = featureIds;
        result[@"selectedFeatureCount"] = @(features.count);
        result[@"patchCount"] = @(plans.count);
''',
'''        result[@"featureIds"] = featureIds;
        result[@"packageSchema"] = packageSchema ?: @"";
        result[@"selectedFeatureCount"] = @(playbackFeatures.count);
        result[@"patchCount"] = @(plans.count);
''',
    'result schema metadata',
)

replace_once(
'''        HFAPCLog(@"[PLAYBACK] action=%@ status=%@ features=%lu patches=%lu reason=%@",
                 action, ok ? @"pass" : @"fail", (unsigned long)features.count,
                 (unsigned long)plans.count, error ?: @"none");
''',
'''        HFAPCLog(@"[PLAYBACK] action=%@ status=%@ schema=%@ features=%lu patches=%lu reason=%@",
                 action, ok ? @"pass" : @"fail", packageSchema ?: @"?",
                 (unsigned long)playbackFeatures.count, (unsigned long)plans.count,
                 error ?: @"none");
''',
    'playback log schema metadata',
)

p.write_text(s)
print("patched HFAPatchConsumer.m for com.hfa.feature/v2 bytePatch compatibility")
