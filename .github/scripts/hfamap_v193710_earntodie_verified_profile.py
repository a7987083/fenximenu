from pathlib import Path


TRACE = Path("hfamap/src/HFAMapPatchExecutionTrace.m")

trace = TRACE.read_text()

function_anchor = "unsigned HFAPatchTraceFinalizeScan(void) {"
if function_anchor not in trace:
    raise SystemExit("HFAPatchTraceFinalizeScan anchor missing")

if "HFAAppendVerifiedEarnToDieRogueProfile" not in trace:
    implementation = r'''
typedef struct {
    const char *identifier;
    const char *title;
    uintptr_t rva;
    const char *original;
    const char *enabled;
} HFAVerifiedStaticPatch;

static BOOL HFAFeatureListContainsIdentifier(NSArray *features,
                                             NSString *identifier) {
    if (!identifier.length) return NO;
    for (NSDictionary *feature in features) {
        if (![feature isKindOfClass:[NSDictionary class]]) continue;
        NSString *existing = [feature[@"id"] isKindOfClass:[NSString class]]
            ? feature[@"id"] : @"";
        if ([existing isEqualToString:identifier]) return YES;
    }
    return NO;
}

static unsigned HFAAppendVerifiedEarnToDieRogueProfile(
    NSMutableArray *features, NSMutableDictionary *targets) {
    if (!features || !targets) return 0;

    NSBundle *bundle = NSBundle.mainBundle;
    NSString *bundleID = bundle.bundleIdentifier ?: @"";
    NSString *shortVersion =
        [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    NSString *buildVersion =
        [bundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"";
    if (![bundleID isEqualToString:@"com.notdoppler.earntodierogue"] ||
        ![shortVersion isEqualToString:@"1.28.251"] ||
        ![buildVersion isEqualToString:@"1"]) return 0;

    int imageIndex = HFAImageIndexForName("UnityFramework");
    if (imageIndex < 0) {
        HFALog("[VERIFIED-PROFILE] id=earntodie-1.28.251-1 status=reject reason=target-unresolved\n");
        return 0;
    }

    NSDictionary *identity =
        HFACanonical34ImageIdentity((uint32_t)imageIndex);
    NSString *uuid = [identity[@"uuid"] isKindOfClass:[NSString class]]
        ? identity[@"uuid"] : @"";
    NSString *architecture =
        [identity[@"architecture"] isKindOfClass:[NSString class]]
        ? identity[@"architecture"] : @"";
    if (![uuid isEqualToString:@"8654D76C-B760-34FC-BEE0-FE70AE8C95C8"] ||
        ![architecture isEqualToString:@"arm64"]) {
        HFALog("[VERIFIED-PROFILE] id=earntodie-1.28.251-1 status=reject reason=identity-mismatch uuid=%s arch=%s\n",
               uuid.UTF8String ?: "?", architecture.UTF8String ?: "?");
        return 0;
    }

    static const HFAVerifiedStaticPatch entries[] = {
        { "Fuel", "Unlimited Fuel", 0x2D98AC8,
          "0038211E", "1F2003D5" },
        { "Boost", "Unlimited Boost", 0x2D9887C,
          "0038281E", "1F2003D5" },
    };

    NSString *targetID = @"UnityFramework";
    NSString *resolvedImage =
        [identity[@"resolvedImage"] isKindOfClass:[NSString class]]
        ? identity[@"resolvedImage"] : @"UnityFramework";
    unsigned appended = 0;
    for (unsigned i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        const HFAVerifiedStaticPatch *entry = &entries[i];
        NSString *identifier = [NSString stringWithUTF8String:entry->identifier];
        if (HFAFeatureListContainsIdentifier(features, identifier)) {
            HFALog("[VERIFIED-PROFILE-PATCH] identifier=%s status=skip reason=already-exported\n",
                   entry->identifier);
            continue;
        }

        NSData *expected = HFADataFromHex(entry->original);
        NSData *enabled = HFADataFromHex(entry->enabled);
        const char *originalSource = "unavailable";
        int originalCryptid = -1;
        NSData *actual = HFAReadOriginalBytes(
            (uint32_t)imageIndex, entry->rva, expected.length,
            &originalSource, &originalCryptid);
        if ([actual isEqualToData:enabled]) {
            int fileCryptid = -1;
            NSData *fileOriginal = HFAReadOriginalBytesFromFile(
                (uint32_t)imageIndex, entry->rva, expected.length,
                &fileCryptid);
            if (fileOriginal.length == expected.length) {
                actual = fileOriginal;
                originalSource = "mach-o-file-after-enabled-live";
                originalCryptid = fileCryptid;
            }
        }
        if (expected.length != 4 || enabled.length != 4 ||
            ![actual isEqualToData:expected]) {
            HFALog("[VERIFIED-PROFILE-PATCH] identifier=%s status=reject rva=0x%llX expected=%s actual=%s source=%s cryptid=%d\n",
                   entry->identifier, (unsigned long long)entry->rva,
                   entry->original,
                   actual.length ? HFAHexData(actual).UTF8String : "?",
                   originalSource, originalCryptid);
            continue;
        }

        targets[targetID] = @{ @"image": resolvedImage };
        [features addObject:@{
            @"id": identifier,
            @"title": [NSString stringWithUTF8String:entry->title],
            @"group": @"Imported",
            @"defaultEnabled": @NO,
            @"patches": @[@{
                @"target": targetID,
                @"offset": [NSString stringWithFormat:@"0x%llX",
                            (unsigned long long)entry->rva],
                @"original": [NSString stringWithUTF8String:entry->original],
                @"enabled": [NSString stringWithUTF8String:entry->enabled]
            }]
        }];
        appended++;
        HFALog("[VERIFIED-PROFILE-PATCH] identifier=%s status=pass target=%s rva=0x%llX original=%s enabled=%s source=%s cryptid=%d\n",
               entry->identifier, resolvedImage.UTF8String ?: "?",
               (unsigned long long)entry->rva, entry->original,
               entry->enabled, originalSource, originalCryptid);
    }

    HFALog("[VERIFIED-PROFILE] id=earntodie-1.28.251-1 status=%s appended=%u uuid=%s\n",
           appended == 2 ? "pass" : "partial", appended,
           uuid.UTF8String ?: "?");
    return appended;
}

'''
    trace = trace.replace(function_anchor, implementation + function_anchor, 1)

call_anchor = """    unsigned nativeHooks =
        HFAAppendNativeHookPackageFeatures(exportFeatures, exportTargets);
"""
if call_anchor not in trace:
    raise SystemExit("native hook package anchor missing")
if "unsigned verifiedProfiles =" not in trace:
    trace = trace.replace(
        call_anchor,
        """    unsigned verifiedProfiles =
        HFAAppendVerifiedEarnToDieRogueProfile(exportFeatures, exportTargets);
    unsigned nativeHooks =
        HFAAppendNativeHookPackageFeatures(exportFeatures, exportTargets);
""",
        1,
    )

return_anchor = "    return validParts + nativeHooks;\n"
if return_anchor not in trace:
    raise SystemExit("finalize return anchor missing")
trace = trace.replace(
    return_anchor,
    "    return validParts + nativeHooks + verifiedProfiles;\n",
    1,
)

required = (
    "HFAAppendVerifiedEarnToDieRogueProfile",
    "8654D76C-B760-34FC-BEE0-FE70AE8C95C8",
    "0x2D98AC8",
    "0038211E",
    "0x2D9887C",
    "0038281E",
    "1F2003D5",
    "[VERIFIED-PROFILE-PATCH]",
)
for token in required:
    if token not in trace:
        raise SystemExit(f"verified profile token missing: {token}")

TRACE.write_text(trace)
print("patched v1.9.37.10: verified Earn to Die Rogue Fuel/Boost profile")
