from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")
generic_path = Path("hfamap/src/HFAMapGenericMenuResolver.m")
profiler_path = Path("hfamap/src/HFAMapJailpatchRuntimeProfiler.m")
selector_path = Path("hfamap/src/HFAMapJailpatchSelectorResolver.m")

s = patch_path.read_text()
l = legacy_path.read_text()
g = generic_path.read_text()
p = profiler_path.read_text()
r = selector_path.read_text()


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


def replace_exact(text, old, new, expected, label):
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} matches, got {count}")
    return text.replace(old, new)


def replace_function(text, signature, replacement, label):
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f"{label}: signature not found")
    brace = text.find('{', start)
    if brace < 0:
        raise SystemExit(f"{label}: opening brace not found")
    depth = 0
    end = None
    for i in range(brace, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise SystemExit(f"{label}: closing brace not found")
    return text[:start] + replacement + text[end:]


# v1.9.34 CanonicalTruthGate
#
# Source-derived design constraints from the two supplied 5 MB menu families:
# - runtime-record/selector descriptors resolve to true static byte patches;
#   keep the v1.9.33 selector/decrypt/original-byte path unchanged.
# - iGMM features can be runtime numeric modifiers, native hooks or block actions;
#   an empty patches[] array plus runtime metadata is NOT the canonical 15 MB
#   com.hfa.patch/v1 contract and must not be written with a .hfapatch.json name.
# - canonical offsets are Mach-O preferred VM addresses, not runtime addresses
#   and not file offsets. For a main executable this commonly retains 0x100...
#   while a dylib/framework can start at zero.
# - binary identity must be recorded out-of-band so arm64 and arm64e slices or
#   different builds are never treated as byte-identical evidence.
#
# Therefore this version adds a strict canonical preflight, a target-identity
# sidecar, and an iGMM diagnostic-only exporter. It deliberately does NOT invent
# static patches for runtime-hook features.

s = replace_once(
    s,
    '[HFALearn v1.9.33 OriginalByteResolver] loaded',
    '[HFALearn v1.9.34 CanonicalTruthGate] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.33 OriginalByteResolver] loaded',
    '[HFALearn UI v1.9.34 CanonicalTruthGate] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=semantic-feature-array jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=diagnostic-runtime jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source canonical=strict-v1 identity=sidecar export=legacy-v1+igmm-report+jsonl+jailpatch-jsonl',
    'update mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.33 OriginalByteResolver',
    'HFAMap v1.9.34 CanonicalTruthGate',
    2,
    'update generic resolver markers',
)
g = replace_once(g, '@"1.9.33"', '@"1.9.34"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.33 OriginalByteResolver";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.34 CanonicalTruthGate";',
    'update profiler marker',
)
p = replace_once(p, '@"1.9.33"', '@"1.9.34"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.33 OriginalByteResolver";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.34 CanonicalTruthGate";',
    'update selector marker',
)
r = replace_once(r, '@"1.9.33"', '@"1.9.34"', 'update selector json version')

l = replace_once(
    l,
    'HFAMap v1.9.33 Original Resolver',
    'HFAMap v1.9.34 Canonical Truth Gate',
    'update panel title',
)
l = replace_once(
    l,
    'Crash-safe scan + generic decrypt + multi-source original-byte resolver.\\nOpen the menu, scan, then exercise visible controls.',
    'Strict static-patch package contract + binary identity.\\niGMM runtime hooks export diagnostics only until a portable static equivalent is proven.',
    'update panel help',
)

canonical_anchor = 'static void HFAWritePatchPackage(NSArray *features, NSDictionary *targets) {\n'
canonical_helpers = r'''static BOOL HFACanonical34KeysEqual(NSDictionary *value, NSArray *keys) {
    if (![value isKindOfClass:[NSDictionary class]]) return NO;
    NSSet *actual = [NSSet setWithArray:[value allKeys]];
    NSSet *expected = [NSSet setWithArray:keys];
    return [actual isEqualToSet:expected];
}

static BOOL HFACanonical34Validate(NSArray *features, NSDictionary *targets) {
    if (![features isKindOfClass:[NSArray class]] || !features.count ||
        ![targets isKindOfClass:[NSDictionary class]] || !targets.count) {
        HFALog("[CANONICAL-CHECK] status=fail reason=empty-features-or-targets\n");
        return NO;
    }
    NSArray *targetKeys = @[ @"image" ];
    for (NSString *targetID in targets) {
        NSDictionary *target = [targets objectForKey:targetID];
        NSString *image = [target objectForKey:@"image"];
        if (![targetID isKindOfClass:[NSString class]] || !targetID.length ||
            !HFACanonical34KeysEqual(target, targetKeys) ||
            ![image isKindOfClass:[NSString class]] || !image.length) {
            HFALog("[CANONICAL-CHECK] status=fail reason=target-contract target=%s\n",
                   [targetID UTF8String] ?: "?");
            return NO;
        }
    }

    NSArray *featureKeys = @[ @"id", @"title", @"group", @"defaultEnabled", @"patches" ];
    NSArray *patchKeys = @[ @"target", @"offset", @"original", @"enabled" ];
    unsigned patchCount = 0;
    for (NSDictionary *feature in features) {
        if (!HFACanonical34KeysEqual(feature, featureKeys)) {
            HFALog("[CANONICAL-CHECK] status=fail reason=feature-keys\n");
            return NO;
        }
        NSString *identifier = [feature objectForKey:@"id"];
        NSString *title = [feature objectForKey:@"title"];
        NSString *group = [feature objectForKey:@"group"];
        NSNumber *defaultEnabled = [feature objectForKey:@"defaultEnabled"];
        NSArray *patches = [feature objectForKey:@"patches"];
        if (![identifier isKindOfClass:[NSString class]] || !identifier.length ||
            ![title isKindOfClass:[NSString class]] || !title.length ||
            ![group isKindOfClass:[NSString class]] || !group.length ||
            ![defaultEnabled isKindOfClass:[NSNumber class]] ||
            ![patches isKindOfClass:[NSArray class]] || !patches.count) {
            HFALog("[CANONICAL-CHECK] status=fail reason=feature-values id=%s\n",
                   [identifier UTF8String] ?: "?");
            return NO;
        }
        for (NSDictionary *patch in patches) {
            if (!HFACanonical34KeysEqual(patch, patchKeys)) {
                HFALog("[CANONICAL-CHECK] status=fail reason=patch-keys id=%s\n",
                       [identifier UTF8String] ?: "?");
                return NO;
            }
            NSString *targetID = [patch objectForKey:@"target"];
            NSString *offset = [patch objectForKey:@"offset"];
            NSString *original = [patch objectForKey:@"original"];
            NSString *enabled = [patch objectForKey:@"enabled"];
            if (![targetID isKindOfClass:[NSString class]] ||
                ![targets objectForKey:targetID] ||
                ![offset isKindOfClass:[NSString class]] || offset.length < 3 ||
                ![offset hasPrefix:@"0x"] || !HFAValidOffset(offset.UTF8String) ||
                ![original isKindOfClass:[NSString class]] ||
                ![enabled isKindOfClass:[NSString class]] ||
                !HFAValidPatch(original.UTF8String) ||
                !HFAValidPatch(enabled.UTF8String) ||
                original.length != enabled.length || !original.length ||
                [original caseInsensitiveCompare:enabled] == NSOrderedSame) {
                HFALog("[CANONICAL-CHECK] status=fail reason=patch-values id=%s target=%s offset=%s\n",
                       [identifier UTF8String] ?: "?",
                       [targetID UTF8String] ?: "?", [offset UTF8String] ?: "?");
                return NO;
            }
            patchCount++;
        }
    }
    HFALog("[CANONICAL-CHECK] status=pass features=%u patches=%u targets=%u offsetSemantics=preferred-mach-o-vmaddr\n",
           (unsigned)features.count, patchCount, (unsigned)targets.count);
    return YES;
}

static NSString *HFACanonical34UUID(const struct mach_header_64 *h) {
    if (!h) return nil;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *end = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
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

static NSDictionary *HFACanonical34ImageIdentity(uint32_t imageIndex) {
    const struct mach_header *mh = _dyld_get_image_header(imageIndex);
    if (!mh || mh->magic != MH_MAGIC_64) return nil;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const char *path = _dyld_get_image_name(imageIndex);
    NSString *resolvedImage = path ? [NSString stringWithUTF8String:HFABase(path)] : @"?";
    NSString *uuid = HFACanonical34UUID(h) ?: @"?";
    uint64_t textVMAddr = 0;
    int cryptid = -1;
    const uint8_t *cursor = (const uint8_t *)(h + 1);
    const uint8_t *end = cursor + h->sizeofcmds;
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) break;
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize < sizeof(*lc) || cursor + lc->cmdsize > end) break;
        if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cursor;
            if (strncmp(seg->segname, "__TEXT", 16) == 0) textVMAddr = seg->vmaddr;
        } else if (lc->cmd == LC_ENCRYPTION_INFO_64 &&
                   lc->cmdsize >= sizeof(struct encryption_info_command_64)) {
            cryptid = (int)((const struct encryption_info_command_64 *)cursor)->cryptid;
        }
        cursor += lc->cmdsize;
    }
    cpu_subtype_t subtype = h->cpusubtype & ~CPU_SUBTYPE_MASK;
#ifdef CPU_SUBTYPE_ARM64E
    NSString *architecture = subtype == CPU_SUBTYPE_ARM64E ? @"arm64e" : @"arm64";
#else
    NSString *architecture = @"arm64";
#endif
    intptr_t slide = _dyld_get_image_vmaddr_slide(imageIndex);
    return @{
        @"resolvedImage": resolvedImage,
        @"uuid": uuid,
        @"cputype": @((int)h->cputype),
        @"cpusubtype": @((int)subtype),
        @"architecture": architecture,
        @"preferredTextVMAddr": [NSString stringWithFormat:@"0x%llX", (unsigned long long)textVMAddr],
        @"slide": [NSString stringWithFormat:@"0x%llX", (unsigned long long)(uintptr_t)slide],
        @"cryptid": @(cryptid)
    };
}

static void HFACanonical34WriteIdentity(NSDictionary *targets) {
    if (![targets isKindOfClass:[NSDictionary class]] || !targets.count) return;
    NSMutableDictionary *identities = [NSMutableDictionary dictionary];
    for (NSString *targetID in targets) {
        NSDictionary *target = [targets objectForKey:targetID];
        NSString *image = [target objectForKey:@"image"];
        int imageIndex = [image isEqualToString:@"@main"] ? 0 : HFAImageIndexForName(image.UTF8String);
        NSMutableDictionary *entry = [NSMutableDictionary dictionary];
        entry[@"declaredImage"] = image ?: @"?";
        if (imageIndex >= 0) {
            NSDictionary *identity = HFACanonical34ImageIdentity((uint32_t)imageIndex);
            if (identity) [entry addEntriesFromDictionary:identity];
            entry[@"status"] = @"resolved";
        } else {
            entry[@"status"] = @"unresolved";
        }
        identities[targetID] = entry;
        HFALog("[TARGET-IDENTITY] target=%s image=%s status=%s uuid=%s arch=%s textVM=%s\n",
               targetID.UTF8String ?: "?", image.UTF8String ?: "?",
               [entry[@"status"] UTF8String] ?: "?",
               [entry[@"uuid"] UTF8String] ?: "?",
               [entry[@"architecture"] UTF8String] ?: "?",
               [entry[@"preferredTextVMAddr"] UTF8String] ?: "?");
    }
    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSDictionary *root = @{
        @"schema": @"com.hfa.patch.identity/v1",
        @"offsetSemantics": @"preferred-mach-o-vmaddr",
        @"package": @{ @"bundleIdentifier": bundleID,
                        @"shortVersion": shortVersion,
                        @"buildVersion": buildVersion },
        @"targets": identities
    };
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];
    if (!json) return;
    NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSString *name = [NSString stringWithFormat:@"%@_%@_%@.hfapatch.identity.json", safeID, shortVersion, buildVersion];
    NSString *path = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name];
    if ([json writeToFile:path options:NSDataWritingAtomic error:&error])
        HFALog("[TARGET-IDENTITY-EXPORT] path=%s targets=%u\n", path.UTF8String, (unsigned)identities.count);
}

''' + canonical_anchor
s = replace_once(s, canonical_anchor, canonical_helpers, 'insert canonical gate + identity helpers')

igmm_writer = r'''static NSString *HFAIGMM34Primitive(NSString *type, NSDictionary *runtime) {
    NSDictionary *implementation = [runtime objectForKey:@"implementation"];
    NSDictionary *handler = [runtime objectForKey:@"handler"];
    if ([type isEqualToString:@"modtext"]) return @"numericRuntimeModifier";
    if ([implementation isKindOfClass:[NSDictionary class]] && implementation.count)
        return @"nativeHook";
    if ([[handler objectForKey:@"kind"] isEqualToString:@"block"])
        return @"blockHandler";
    if ([type isEqualToString:@"customSwitch"]) return @"runtimeBoolean";
    if ([type isEqualToString:@"button"]) return @"runtimeAction";
    return @"unresolved";
}

static NSString *HFAIGMM34CanonicalReason(NSString *primitive) {
    if ([primitive isEqualToString:@"numericRuntimeModifier"])
        return @"dynamic-numeric-state-not-static-bytes";
    if ([primitive isEqualToString:@"nativeHook"])
        return @"runtime-hook-requires-portable-equivalent";
    if ([primitive isEqualToString:@"blockHandler"] ||
        [primitive isEqualToString:@"runtimeAction"])
        return @"runtime-action-not-static-bytes";
    if ([primitive isEqualToString:@"runtimeBoolean"])
        return @"runtime-boolean-implementation-unresolved";
    return @"execution-primitive-unresolved";
}

static void HFAWriteIGMMPackage(id menuTarget, NSArray *rawFeatures) {
    if (!menuTarget || !rawFeatures.count) return;
    NSMutableArray *features = [NSMutableArray array];
    const char *menuClassC = class_getName(object_getClass(menuTarget));
    const char *menuImageC = class_getImageName(object_getClass(menuTarget));
    NSString *menuClass = menuClassC ? [NSString stringWithUTF8String:menuClassC] : @"?";
    NSString *menuImage = menuImageC ? [NSString stringWithUTF8String:HFABase(menuImageC)] : @"?";
    NSArray *configKeys = @[ @"desc", @"defaultValue", @"offsets", @"distance",
                             @"patched", @"offsetDifference", @"typecfg" ];
    unsigned index = 0;
    for (id item in rawFeatures) {
        if (!HFAIGMMValidFeatureDictionary(item)) continue;
        NSDictionary *d = (NSDictionary *)item;
        NSString *title = d[@"label"];
        NSString *identifier = d[@"identifier"];
        NSString *type = d[@"type"];
        NSMutableDictionary *config = [NSMutableDictionary dictionary];
        for (NSString *key in configKeys) {
            id safe = HFAIGMMJSONValue(d[key]);
            if (safe) config[key] = safe;
        }
        NSMutableDictionary *runtime = [@{ @"backend": @"iGMM",
                                            @"menuClass": menuClass,
                                            @"menuImage": menuImage,
                                            @"representation": @"runtime-definition" } mutableCopy];
        NSDictionary *handler = HFAIGMMBlockMetadata(d[@"kButtonTapHandler"]);
        if (handler) runtime[@"handler"] = handler;
        NSDictionary *implementation =
            HFAIGMM26ResolveImplementation(menuImage.UTF8String,
                                            identifier.UTF8String, handler);
        if (implementation) runtime[@"implementation"] = implementation;
        NSString *primitive = HFAIGMM34Primitive(type, runtime);
        NSString *reason = HFAIGMM34CanonicalReason(primitive);
        NSMutableDictionary *feature = [@{
            @"id": identifier,
            @"title": title,
            @"type": type,
            @"backend": @"iGMM",
            @"executionPrimitive": primitive,
            @"canonicalEligible": @NO,
            @"canonicalReason": reason,
            @"runtime": runtime
        } mutableCopy];
        if (config.count) feature[@"config"] = config;
        [features addObject:feature];
        HFALog("[IGMM-PRIMITIVE] index=%u identifier=%s type=%s primitive=%s canonical=unresolved reason=%s\n",
               index++, identifier.UTF8String, type.UTF8String,
               primitive.UTF8String, reason.UTF8String);
    }
    if (!features.count) return;

    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"unknown.game";
    NSString *shortVersion = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"0";
    NSString *buildVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"0";
    NSDictionary *root = @{
        @"schema": @"com.hfa.igmm.runtime/v1",
        @"name": [NSString stringWithFormat:@"%@ %@ iGMM runtime analysis", bundleID, shortVersion],
        @"package": @{ @"bundleIdentifier": bundleID,
                        @"shortVersion": shortVersion,
                        @"buildVersion": buildVersion },
        @"menu": @{ @"class": menuClass, @"image": menuImage },
        @"canonicalContract": @"com.hfa.patch/v1",
        @"canonicalStatus": @"unresolved-runtime-primitives",
        @"features": features
    };
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:root options:NSJSONWritingPrettyPrinted error:&error];
    if (!json) {
        HFALog("[IGMM-RUNTIME-EXPORT-FAIL] reason=%s\n", error.localizedDescription.UTF8String ?: "json");
        return;
    }
    NSString *safeID = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSString *name = [NSString stringWithFormat:@"%@_%@_%@.hfamap.igmm.json", safeID, shortVersion, buildVersion];
    NSString *path = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"] stringByAppendingPathComponent:name];
    if ([json writeToFile:path options:NSDataWritingAtomic error:&error])
        HFALog("[IGMM-RUNTIME-EXPORT] path=%s features=%u menuClass=%s menuImage=%s canonical=unresolved\n",
               path.UTF8String, (unsigned)features.count,
               menuClass.UTF8String, menuImage.UTF8String);
    else
        HFALog("[IGMM-RUNTIME-EXPORT-FAIL] reason=%s\n", error.localizedDescription.UTF8String ?: "write");
}
'''
s = replace_function(
    s,
    'static void HFAWriteIGMMPackage(id menuTarget, NSArray *rawFeatures)',
    igmm_writer,
    'replace iGMM canonical-mislabelled writer with diagnostic writer',
)

old_call = '    HFAWritePatchPackage(exportFeatures, exportTargets);\n'
new_call = r'''    if (exportFeatures.count || exportTargets.count) {
        if (HFACanonical34Validate(exportFeatures, exportTargets)) {
            HFACanonical34WriteIdentity(exportTargets);
            HFAWritePatchPackage(exportFeatures, exportTargets);
        } else {
            HFALog("[CANONICAL-EXPORT-SKIP] reason=contract-validation-failed\n");
        }
    }
'''
s = replace_once(s, old_call, new_call, 'gate canonical package writer')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
