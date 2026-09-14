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


# v1.9.36 ArchitectureTruth
#
# v1.9.35 device evidence proves that main-image resolution and original-byte
# acquisition are now tied to the real MH_EXECUTE image. The generated package
# still inherited one older metadata assumption: package.architectures was
# derived from _dyld_get_image_header(0). In injected runtimes, image index 0
# may be a loader/hook dylib and can therefore report arm64e while the canonical
# patch target is an arm64 executable.
#
# Derive architecture exclusively from the canonical targets themselves. Every
# target must resolve through HFAImageIndexForName. All target images must agree
# on one ARM64 subtype; otherwise fail closed and do not write the package.

s = replace_once(
    s,
    '[HFALearn v1.9.35 MainImageTruth] loaded',
    '[HFALearn v1.9.36 ArchitectureTruth] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.35 MainImageTruth] loaded',
    '[HFALearn UI v1.9.36 ArchitectureTruth] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=diagnostic-runtime jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source canonical=strict-v1 identity=sidecar main=mh-execute export=legacy-v1+igmm-report+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=diagnostic-runtime jailpatch=selector-resolver+generic-secret-decrypt scan=crash-safe original=multi-source canonical=strict-v1 identity=sidecar main=mh-execute architecture=target-derived export=legacy-v1+igmm-report+jsonl+jailpatch-jsonl',
    'update mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.35 MainImageTruth',
    'HFAMap v1.9.36 ArchitectureTruth',
    2,
    'update generic resolver markers',
)
g = replace_once(g, '@"1.9.35"', '@"1.9.36"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.35 MainImageTruth";',
    'static const char *kHFAJPVersion = "HFAMap v1.9.36 ArchitectureTruth";',
    'update profiler marker',
)
p = replace_once(p, '@"1.9.35"', '@"1.9.36"', 'update profiler json version')

r = replace_once(
    r,
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.35 MainImageTruth";',
    'static const char *kHFAJPSRVersion = "HFAMap v1.9.36 ArchitectureTruth";',
    'update selector marker',
)
r = replace_once(r, '@"1.9.35"', '@"1.9.36"', 'update selector json version')

l = replace_once(
    l,
    'HFAMap v1.9.35 Main Image Truth',
    'HFAMap v1.9.36 Architecture Truth',
    'update panel title',
)
l = replace_once(
    l,
    'Strict static-patch contract + executable-identity main resolver.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'Strict static-patch contract + target-derived architecture identity.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'update panel help',
)

old_arch = r'''#ifdef CPU_SUBTYPE_ARM64E
    const struct mach_header *header = _dyld_get_image_header(0);
    cpu_subtype_t subtype = header ? (header->cpusubtype & ~CPU_SUBTYPE_MASK) : 0;
    NSString *architecture = subtype == CPU_SUBTYPE_ARM64E ? @"arm64e" : @"arm64";
#else
    NSString *architecture = @"arm64";
#endif
'''
new_arch = r'''    NSString *architecture = nil;
    for (NSString *targetID in targets) {
        NSDictionary *target = [targets objectForKey:targetID];
        NSString *image = [target objectForKey:@"image"];
        int imageIndex = HFAImageIndexForName(image.UTF8String);
        if (imageIndex < 0) {
            HFALog("[PACKAGE-ARCH] status=fail reason=target-unresolved target=%s image=%s\n",
                   targetID.UTF8String ?: "?", image.UTF8String ?: "?");
            return;
        }
        const struct mach_header *header =
            _dyld_get_image_header((uint32_t)imageIndex);
        if (!header || header->cputype != CPU_TYPE_ARM64) {
            HFALog("[PACKAGE-ARCH] status=fail reason=non-arm64-target target=%s image=%s cputype=%d\n",
                   targetID.UTF8String ?: "?", image.UTF8String ?: "?",
                   header ? (int)header->cputype : 0);
            return;
        }
        cpu_subtype_t subtype = header->cpusubtype & ~CPU_SUBTYPE_MASK;
#ifdef CPU_SUBTYPE_ARM64E
        NSString *current = subtype == CPU_SUBTYPE_ARM64E ? @"arm64e" : @"arm64";
#else
        NSString *current = @"arm64";
#endif
        if (architecture && ![architecture isEqualToString:current]) {
            HFALog("[PACKAGE-ARCH] status=fail reason=target-architecture-mismatch first=%s current=%s target=%s image=%s\n",
                   architecture.UTF8String ?: "?", current.UTF8String ?: "?",
                   targetID.UTF8String ?: "?", image.UTF8String ?: "?");
            return;
        }
        architecture = current;
    }
    if (!architecture) {
        HFALog("[PACKAGE-ARCH] status=fail reason=no-canonical-targets\n");
        return;
    }
    HFALog("[PACKAGE-ARCH] status=pass architecture=%s targets=%u source=canonical-targets\n",
           architecture.UTF8String ?: "?", (unsigned)targets.count);
'''
s = replace_once(s, old_arch, new_arch, 'replace dyld-index-zero package architecture')

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
selector_path.write_text(r)
