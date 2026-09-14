#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/machine.h>
#include <stdio.h>
#include <string.h>

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

static const char *HFAJSONBase(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static int HFAJSONImageIndexForName(NSString *declaredImage) {
    if (![declaredImage isKindOfClass:[NSString class]] || !declaredImage.length) return -1;
    BOOL wantsMain = [declaredImage isEqualToString:@"@main"] || [declaredImage isEqualToString:@"main"];
    NSString *mainPath = NSBundle.mainBundle.executablePath;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *rawPath = _dyld_get_image_name(i);
        if (!rawPath) continue;
        NSString *path = [NSString stringWithUTF8String:rawPath];
        if (wantsMain) {
            if (mainPath.length && [path isEqualToString:mainPath]) return (int)i;
            const struct mach_header *header = _dyld_get_image_header(i);
            if (header && header->filetype == MH_EXECUTE) return (int)i;
            continue;
        }
        NSString *base = [NSString stringWithUTF8String:HFAJSONBase(rawPath)];
        if ([declaredImage isEqualToString:base] ||
            [declaredImage isEqualToString:base.stringByDeletingPathExtension])
            return (int)i;
    }
    return -1;
}

static NSString *HFAJSONUUID(const struct mach_header_64 *header) {
    if (!header) return nil;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) return nil;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) return nil;
        if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uc = (const struct uuid_command *)cursor;
            NSMutableString *result = [NSMutableString stringWithCapacity:36];
            for (unsigned j = 0; j < 16; j++) {
                if (j == 4 || j == 6 || j == 8 || j == 10) [result appendString:@"-"];
                [result appendFormat:@"%02X", uc->uuid[j]];
            }
            return result;
        }
        cursor += lc->cmdsize;
    }
    return nil;
}

static NSDictionary *HFAJSONImageIdentity(NSString *declaredImage) {
    int imageIndex = HFAJSONImageIndexForName(declaredImage);
    if (imageIndex < 0)
        return @{ @"declaredImage": declaredImage ?: @"?", @"status": @"unresolved" };

    const struct mach_header *mh = _dyld_get_image_header((uint32_t)imageIndex);
    const char *rawPath = _dyld_get_image_name((uint32_t)imageIndex);
    if (!mh || mh->magic != MH_MAGIC_64)
        return @{ @"declaredImage": declaredImage ?: @"?", @"status": @"unsupported-header" };

    const struct mach_header_64 *header = (const struct mach_header_64 *)mh;
    uint64_t textVMAddr = 0;
    int cryptid = -1;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *segment = (const struct segment_command_64 *)cursor;
            if (strncmp(segment->segname, "__TEXT", sizeof(segment->segname)) == 0)
                textVMAddr = segment->vmaddr;
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 &&
                   lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            cryptid = (int)((const struct encryption_info_command_64 *)cursor)->cryptid;
        }
        cursor += lc->cmdsize;
    }

    cpu_subtype_t subtype = header->cpusubtype & ~CPU_SUBTYPE_MASK;
    NSString *architecture = @"unknown";
    if (header->cputype == CPU_TYPE_ARM64) {
#ifdef CPU_SUBTYPE_ARM64E
        architecture = subtype == CPU_SUBTYPE_ARM64E ? @"arm64e" : @"arm64";
#else
        architecture = @"arm64";
#endif
    }

    NSString *resolvedImage = rawPath
        ? [NSString stringWithUTF8String:HFAJSONBase(rawPath)] : @"?";
    return @{
        @"declaredImage": declaredImage ?: @"?",
        @"resolvedImage": resolvedImage,
        @"status": @"resolved",
        @"uuid": HFAJSONUUID(header) ?: @"?",
        @"cputype": @((int)header->cputype),
        @"cpusubtype": @((int)subtype),
        @"architecture": architecture,
        @"filetype": @((unsigned)header->filetype),
        @"preferredTextVMAddr": [NSString stringWithFormat:@"0x%llX", (unsigned long long)textVMAddr],
        @"cryptid": @(cryptid)
    };
}

static void HFAJSONCollectImages(id value, NSMutableSet<NSString *> *images) {
    if (!value || value == [NSNull null]) return;
    if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dictionary = (NSDictionary *)value;
        for (id key in dictionary) {
            id child = dictionary[key];
            if ([key isKindOfClass:[NSString class]] && [child isKindOfClass:[NSString class]]) {
                NSString *keyString = (NSString *)key;
                NSString *image = (NSString *)child;
                if (([keyString isEqualToString:@"image"] ||
                     [keyString isEqualToString:@"menuImage"] ||
                     [keyString isEqualToString:@"declaredImage"] ||
                     [keyString isEqualToString:@"resolvedImage"]) &&
                    image.length && ![image isEqualToString:@"?"])
                    [images addObject:image];
            }
            HFAJSONCollectImages(child, images);
        }
    } else if ([value isKindOfClass:[NSArray class]]) {
        for (id child in (NSArray *)value) HFAJSONCollectImages(child, images);
    }
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

static NSString *HFAJSONNormalizedExecutionPrimitive(NSDictionary *feature, NSString *controlKind) {
    NSString *raw = [feature[@"executionPrimitive"] isKindOfClass:[NSString class]]
        ? feature[@"executionPrimitive"] : @"";
    NSDictionary *runtime = [feature[@"runtime"] isKindOfClass:[NSDictionary class]] ? feature[@"runtime"] : nil;
    NSDictionary *implementation = [runtime[@"implementation"] isKindOfClass:[NSDictionary class]]
        ? runtime[@"implementation"] : nil;
    NSDictionary *handler = [runtime[@"handler"] isKindOfClass:[NSDictionary class]] ? runtime[@"handler"] : nil;
    NSString *implementationKind = [implementation[@"kind"] isKindOfClass:[NSString class]]
        ? implementation[@"kind"] : @"";
    NSString *handlerKind = [handler[@"kind"] isKindOfClass:[NSString class]] ? handler[@"kind"] : @"";

    if ([controlKind isEqualToString:@"button"] &&
        ([implementationKind isEqualToString:@"buttonBlock"] ||
         [handlerKind isEqualToString:@"block"] ||
         [raw isEqualToString:@"runtimeAction"] ||
         [raw isEqualToString:@"blockHandler"]))
        return @"runtimeAction";

    return raw.length ? raw : @"unresolved";
}

static NSString *HFAJSONNormalizedCanonicalReason(NSDictionary *feature, NSString *normalizedPrimitive) {
    NSString *raw = [feature[@"canonicalReason"] isKindOfClass:[NSString class]]
        ? feature[@"canonicalReason"] : @"";
    if ([normalizedPrimitive isEqualToString:@"runtimeAction"])
        return @"runtime-action-not-static-bytes";
    if ([normalizedPrimitive isEqualToString:@"numericRuntimeModifier"])
        return @"dynamic-numeric-state-not-static-bytes";
    if ([normalizedPrimitive isEqualToString:@"nativeHook"])
        return @"runtime-hook-requires-portable-equivalent";
    if ([normalizedPrimitive isEqualToString:@"runtimeBoolean"])
        return @"runtime-boolean-implementation-unresolved";
    return raw.length ? raw : @"execution-primitive-unresolved";
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
        NSString *normalizedPrimitive = HFAJSONNormalizedExecutionPrimitive(feature, kind);
        record[@"normalizedExecutionPrimitive"] = normalizedPrimitive;
        record[@"normalizedCanonicalReason"] = HFAJSONNormalizedCanonicalReason(feature, normalizedPrimitive);
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

        NSMutableSet<NSString *> *imageNames = [NSMutableSet set];
        HFAJSONCollectImages(canonical, imageNames);
        HFAJSONCollectImages(igmm, imageNames);
        NSMutableDictionary *targetIdentities = [NSMutableDictionary dictionary];
        NSArray<NSString *> *sortedImages = [[imageNames allObjects] sortedArrayUsingSelector:@selector(compare:)];
        for (NSString *image in sortedImages) {
            NSDictionary *identity = HFAJSONImageIdentity(image);
            if (identity) targetIdentities[image] = identity;
        }

        NSDictionary *package = @{
            @"bundleIdentifier": bundleID,
            @"shortVersion": shortVersion,
            @"buildVersion": buildVersion
        };
        NSMutableDictionary *root = [@{
            @"schema": @"com.hfa.menu.analysis/v1",
            @"analyzer": @"HFAMapUniversal v1.9.36.4 JSONExport",
            @"analysisOnly": @YES,
            @"package": package,
            @"sources": sources,
            @"features": features
        } mutableCopy];
        if (targetIdentities.count) root[@"targetIdentities"] = targetIdentities;
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
        HFAJSONLog([NSString stringWithFormat:@"[JSON-EXPORT] status=pass file=%@ features=%lu sources=%lu identity=%@ targetIdentities=%lu",
                    name, (unsigned long)features.count, (unsigned long)sources.count,
                    haveIdentity ? @"yes" : @"no", (unsigned long)targetIdentities.count]);
        return YES;
    }
}
