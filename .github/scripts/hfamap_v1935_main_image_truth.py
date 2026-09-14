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


# v1.9.35 MainImageTruth
#
# Device evidence from v1.9.34 invalidated the historical assumption that dyld
# image index 0 is always the app executable. In the supplied injected runtime,
# index 0 resolved to systemhook.dylib. The same assumption was shared by both
# the new identity sidecar and the older "main" original-byte path, which let
# executable patch offsets acquire unrelated ASCII bytes as "original" values.
#
# Resolve @main/main by binary identity instead:
#   1. prefer NSBundle.mainBundle.executablePath matched to an MH_EXECUTE image;
#   2. otherwise accept only a unique loaded MH_EXECUTE image;
#   3. fail closed when no unique executable can be established.
# All other named-image resolution remains unchanged.

s = replace_once(
    s,
    '[HFALearn v1.9.34 CanonicalTruthGate] loaded',
    '[HFALearn v1.9.35 MainImageTruth] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.34 CanonicalTruthGate] loaded',
    '[HFALearn UI v1.9.35 MainImageTruth] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=diagnostic-runtime jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source canonical=strict-v1 identity=sidecar export=legacy-v1+igmm-report+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=diagnostic-runtime jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source canonical=strict-v1 identity=sidecar main=mh-execute export=legacy-v1+igmm-report+jsonl+jailpatch-jsonl',
    'update mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.34 CanonicalTruthGate',
    'HFAMap v1.9.35 MainImageTruth',
    2,
    'update generic resolver markers',
)
g = replace_once(g, '@"1.9.34"', '@"1.9.35"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.34 CanonicalTruthGate";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.35 MainImageTruth";',
    'update profiler marker',
)
p = replace_once(p, '@"1.9.34"', '@"1.9.35"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.34 CanonicalTruthGate";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.35 MainImageTruth";',
    'update selector marker',
)
r = replace_once(r, '@"1.9.34"', '@"1.9.35"', 'update selector json version')

l = replace_once(
    l,
    'HFAMap v1.9.34 Canonical Truth Gate',
    'HFAMap v1.9.35 Main Image Truth',
    'update panel title',
)
l = replace_once(
    l,
    'Strict static-patch package contract + binary identity.\\niGMM runtime hooks export diagnostics only until a portable static equivalent is proven.',
    'Strict static-patch contract + executable-identity main resolver.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'update panel help',
)

main_resolver = r'''static int HFAMainExecutableImageIndex(void) {
    static int cached = -2;
    if (cached != -2) return cached;

    NSString *bundlePath = NSBundle.mainBundle.executablePath;
    const char *wantedPath = bundlePath.fileSystemRepresentation;
    const char *wantedBase = wantedPath && *wantedPath ? HFABase(wantedPath) : NULL;
    int uniqueExecute = -1;
    unsigned executeCount = 0;
    uint32_t count = _dyld_image_count();

    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh || mh->filetype != MH_EXECUTE) continue;
        executeCount++;
        uniqueExecute = (int)i;
        const char *path = _dyld_get_image_name(i);
        const char *base = path ? HFABase(path) : NULL;
        if ((wantedPath && path && strcmp(wantedPath, path) == 0) ||
            (wantedBase && base && strcmp(wantedBase, base) == 0)) {
            cached = (int)i;
            HFALog("[MAIN-IMAGE-RESOLVE] status=resolved mode=bundle-executable index=%u image=%s filetype=MH_EXECUTE\\n",
                   i, base ? base : "?");
            return cached;
        }
    }

    if (executeCount == 1 && uniqueExecute >= 0) {
        cached = uniqueExecute;
        const char *path = _dyld_get_image_name((uint32_t)uniqueExecute);
        HFALog("[MAIN-IMAGE-RESOLVE] status=resolved mode=unique-mh-execute index=%d image=%s filetype=MH_EXECUTE\\n",
               uniqueExecute, path ? HFABase(path) : "?");
        return cached;
    }

    cached = -1;
    HFALog("[MAIN-IMAGE-RESOLVE] status=unresolved executeCount=%u bundleExecutable=%s\\n",
           executeCount, wantedBase ? wantedBase : "?");
    return cached;
}

static int HFAImageIndexForName(const char *value) {
    if (!value || !*value) return -1;
    if (strcmp(value, "main") == 0 || strcmp(value, "@main") == 0)
        return HFAMainExecutableImageIndex();
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *base = HFABase(_dyld_get_image_name(i));
        if (strcmp(value, base) == 0) return (int)i;
        char stem[256]; snprintf(stem, sizeof(stem), "%s", base);
        char *dot = strrchr(stem, '.'); if (dot) *dot = 0;
        if (strcmp(value, stem) == 0) return (int)i;
    }
    return -1;
}'''
s = replace_function(
    s,
    'static int HFAImageIndexForName(const char *value)',
    main_resolver,
    'replace dyld-index-zero main resolver',
)

s = replace_once(
    s,
    'int imageIndex = [image isEqualToString:@"@main"] ? 0 : HFAImageIndexForName(image.UTF8String);',
    'int imageIndex = HFAImageIndexForName(image.UTF8String);',
    'route identity @main through executable resolver',
)

# Do not let a structurally valid package pass if a declared target cannot be
# tied to a loaded image under the new resolver.
old_preflight = '    if (!HFACanonical34Validate(features, targets)) return;\n'
new_preflight = old_preflight + r'''    for (NSString *targetID in targets) {
        NSDictionary *target = [targets objectForKey:targetID];
        NSString *image = [target objectForKey:@"image"];
        int resolvedIndex = HFAImageIndexForName(image.UTF8String);
        if (resolvedIndex < 0) {
            HFALog("[CANONICAL-CHECK] status=fail reason=target-image-unresolved target=%s image=%s\\n",
                   targetID.UTF8String ?: "?", image.UTF8String ?: "?");
            return;
        }
        const struct mach_header *resolvedHeader =
            _dyld_get_image_header((uint32_t)resolvedIndex);
        if ([image isEqualToString:@"@main"] &&
            (!resolvedHeader || resolvedHeader->filetype != MH_EXECUTE)) {
            HFALog("[CANONICAL-CHECK] status=fail reason=main-not-mh-execute target=%s index=%d\\n",
                   targetID.UTF8String ?: "?", resolvedIndex);
            return;
        }
    }
'''
s = replace_once(s, old_preflight, new_preflight, 'add target identity preflight')

# Enrich the original-byte log so device evidence proves which Mach-O supplied
# the slide/file fallback for each canonical patch.
old_log = r'''                HFALog("[PACKAGE-ORIGINAL] title=\"%s\" module=%s offset=%s bytes=%u imageIndex=%d source=%s cryptid=%d status=%s\n",
                       title, descriptor->module[0] ? descriptor->module : "?",
                       normalizedOffset[0] ? normalizedOffset : "?",
                       (unsigned)enabled.length, imageIndex, originalSource,
                       originalCryptid,
                       original.length == enabled.length ? "ok" : "unavailable");
'''
new_log = r'''                const char *originalImage = imageIndex >= 0 ?
                    HFABase(_dyld_get_image_name((uint32_t)imageIndex)) : "?";
                const struct mach_header *originalHeader = imageIndex >= 0 ?
                    _dyld_get_image_header((uint32_t)imageIndex) : NULL;
                HFALog("[PACKAGE-ORIGINAL] title=\"%s\" module=%s offset=%s bytes=%u imageIndex=%d image=%s filetype=%u source=%s cryptid=%d status=%s\n",
                       title, descriptor->module[0] ? descriptor->module : "?",
                       normalizedOffset[0] ? normalizedOffset : "?",
                       (unsigned)enabled.length, imageIndex, originalImage,
                       originalHeader ? originalHeader->filetype : 0u,
                       originalSource, originalCryptid,
                       original.length == enabled.length ? "ok" : "unavailable");
'''
s = replace_once(s, old_log, new_log, 'log original source image identity')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
