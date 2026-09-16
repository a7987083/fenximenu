from pathlib import Path

path = Path('.github/scripts/hfamap_v19370_clean_family_resolver.py')
source = path.read_text()
old = "_, _, execute_text = (*function_span(legacy, 'HFAAppLocalExecuteParser'),)"
new = "execute_start, execute_end = function_span(legacy, 'HFAAppLocalExecuteParser')\nexecute_text = legacy[execute_start:execute_end]"
if source.count(old) != 1:
    raise SystemExit('v19370 validation compatibility patch anchor mismatch')
source = source.replace(old, new, 1)
exec(compile(source, str(path), 'exec'), {'__name__': '__main__', '__file__': str(path)})

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
legacy = legacy_path.read_text()
declaration = 'extern const char *HFAAppLocalPrimaryFamily(void);\n'
if declaration not in legacy:
    anchor = 'extern const char *HFAAppLocalPrimaryImage(void);\n'
    if anchor not in legacy:
        raise SystemExit('legacy primary image declaration missing')
    legacy = legacy.replace(anchor, anchor + declaration, 1)
legacy = legacy.replace('static unsigned int run_full_scan(void){',
                        'static __attribute__((unused)) unsigned int run_full_scan(void){', 1)
legacy = legacy.replace('static void tryhook(void){',
                        'static __attribute__((unused)) void tryhook(void){', 1)
legacy_path.write_text(legacy)

# v19367 generic cleanup intentionally removed the class-registry cache. Keep
# the v19370 generation-local reset limited to state that still exists after
# that cleanup rather than reintroducing process-wide class bookkeeping.
generic_path = Path('hfamap/src/HFAMapGenericMenuResolver.m')
generic = generic_path.read_text()
generic = generic.replace('    memset(gSeenClasses, 0, sizeof(gSeenClasses));\n', '')
generic = generic.replace('    gSeenClassCount = 0;\n', '')
generic_path.write_text(generic)
