from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")
generic_path = Path("hfamap/src/HFAMapGenericMenuResolver.m")
profiler_path = Path("hfamap/src/HFAMapJailpatchRuntimeProfiler.m")

s = patch_path.read_text()
l = legacy_path.read_text()
g = generic_path.read_text()
p = profiler_path.read_text()


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


# v1.9.30 JailpatchSelectorResolver
# - keep the v1.9.29 structural profiler for evidence
# - fingerprint 5 MB patch descriptors by stable public selectors/properties
# - bridge descriptor offset/data wrappers back into the mature HFA mapping pipeline
# - never depend on obfuscated classes/ivars, sample feature labels, module names, or RVAs
# - only nominate patch data when exactly one non-offset/non-signature secret wrapper exists

s = replace_once(
    s,
    '[HFALearn v1.9.29 JailpatchRuntimeProfiler] loaded',
    '[HFALearn v1.9.30 JailpatchSelectorResolver] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.29 JailpatchRuntimeProfiler] loaded',
    '[HFALearn UI v1.9.30 JailpatchSelectorResolver] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=runtime-record-profiler export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=selector-resolver export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    'update dual mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.29 JailpatchRuntimeProfiler',
    'HFAMap v1.9.30 JailpatchSelectorResolver',
    2,
    'update generic resolver version markers',
)
g = replace_once(g, '@"1.9.29"', '@"1.9.30"', 'update generic json version')

p = replace_once(
    p,
    'static const char *kHFAJPVersion = "HFAMap v1.9.29 JailpatchRuntimeProfiler";',
    'extern void HFAJailpatchResolveRecord(id,const char*,const char*);\n\nstatic const char *kHFAJPVersion = "HFAMap v1.9.30 JailpatchSelectorResolver";',
    'declare selector resolver and update profiler version',
)
p = replace_once(p, '@"1.9.29"', '@"1.9.30"', 'update profiler json version')
p = replace_once(
    p,
    '                    HFAJPProfileObject(record, identifier,\n                                       [NSString stringWithFormat:@"feature[%@].records[%lu]", identifier, (unsigned long)recordIndex], 0);',
    '                    HFAJailpatchResolveRecord(record, identifier.UTF8String, label.UTF8String);\n                    HFAJPProfileObject(record, identifier,\n                                       [NSString stringWithFormat:@"feature[%@].records[%lu]", identifier, (unsigned long)recordIndex], 0);',
    'bridge each runtime record into selector resolver',
)

l = replace_once(
    l,
    'HFAMap v1.9.29 Jailpatch Profiler',
    'HFAMap v1.9.30 Jailpatch Resolver',
    'update panel title',
)
l = replace_once(
    l,
    'Legacy resolver + Jailpatch runtime profiler enabled.\\nOpen the menu and run Auto Detect / Full Scan.',
    'Legacy resolver + Jailpatch selector resolver enabled.\\nOpen the menu, scan, then exercise visible controls.',
    'update panel help',
)

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
profiler_path.write_text(p)
