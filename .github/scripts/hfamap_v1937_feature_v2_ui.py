from pathlib import Path

trace = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
legacy = Path('hfamap/src/HFAMapLegacy.m')
generic = Path('hfamap/src/HFAMapGenericMenuResolver.m')
profiler = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
selector = Path('hfamap/src/HFAMapJailpatchSelectorResolver.m')

s = trace.read_text()
l = legacy.read_text()
g = generic.read_text()
p = profiler.read_text()
r = selector.read_text()


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)

# Version markers. This branch starts from the fully generated v1.9.36 source.
s = once(s, '[HFALearn v1.9.36 ArchitectureTruth] loaded',
         '[HFALearn v1.9.37 FeatureV2AutoLoad] loaded', 'trace marker')
l = once(l, '[HFALearn UI v1.9.36 ArchitectureTruth] loaded',
         '[HFALearn UI v1.9.37 FeatureV2AutoLoad] loaded', 'ui marker')
g = g.replace('HFAMap v1.9.36 ArchitectureTruth', 'HFAMap v1.9.37 FeatureV2AutoLoad')
g = g.replace('@"1.9.36"', '@"1.9.37"')
p = once(p,
         'static const char *kHFAJPVersion = "HFAMap v1.9.36 ArchitectureTruth";',
         'static const char *kHFAJPVersion = "HFAMap v1.9.37 FeatureV2AutoLoad";',
         'profiler marker')
p = p.replace('@"1.9.36"', '@"1.9.37"')
r = once(r,
         'static const char *kHFAJPSRVersion = "HFAMap v1.9.36 ArchitectureTruth";',
         'static const char *kHFAJPSRVersion = "HFAMap v1.9.37 FeatureV2AutoLoad";',
         'selector marker')
r = r.replace('@"1.9.36"', '@"1.9.37"')

# Keep the existing learning/floating-window UI, then attach the generated-JSON
# renderer to that same panel. Use the stable macro boundary instead of matching
# the historical extern line because earlier patch generations append declarations.
macro_anchor = '#define M0(r,o,s)'
externs = ('extern void HFAMapFeatureUIAttach(id,id); '
           'extern void HFAMapFeatureUIReloadLatest(void);\n')
l = once(l, macro_anchor, externs + macro_anchor, 'feature UI externs')

l = once(l,
         'unsigned int valid=run_full_scan();',
         'unsigned int valid=run_full_scan();HFAMapFeatureUIReloadLatest();',
         'reload generated json after scan')

l = once(l,
         'gPanel=p;gWindow=w;gMade=1;}',
         'gPanel=p;gWindow=w;gMade=1;HFAMapFeatureUIAttach(gPanel,gStatus);}',
         'attach feature UI to floating panel')

# Update the visible title/help without changing the scan behavior.
l = l.replace('HFAMap v1.9.36 Architecture Truth', 'HFAMap v1.9.37 Feature V2')
l = l.replace(
    'Strict static-patch contract + target-derived architecture identity.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'Scan → generate JSON → auto-load into this window.\\nFeature V2 controls execute through the embedded playback engine.'
)

trace.write_text(s)
legacy.write_text(l)
generic.write_text(g)
profiler.write_text(p)
selector.write_text(r)
print('patched HFAMap v1.9.37 FeatureV2AutoLoad UI integration')
