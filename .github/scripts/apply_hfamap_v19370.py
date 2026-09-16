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
legacy_path.write_text(legacy)
