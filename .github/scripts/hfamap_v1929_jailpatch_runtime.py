from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")
generic_path = Path("hfamap/src/HFAMapGenericMenuResolver.m")

s = patch_path.read_text()
l = legacy_path.read_text()
g = generic_path.read_text()


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


# v1.9.29 JailpatchRuntimeProfiler
# - preserve v1.9.28 legacy AP resolver and v1.9.27 exporters
# - profile the 5 MB jailpatch family from runtime structure, not obfuscated names
# - detect feature dictionaries by stable label + identifier semantics
# - discover the runtime-record array generically from the remaining collection value
# - recursively profile record objects, object ivars, primitive ivars, methods and block invokes
# - do not claim patch offsets/table semantics until device evidence identifies them

s = replace_once(
    s,
    '[HFALearn v1.9.28 GenericMenuResolver] loaded',
    '[HFALearn v1.9.29 JailpatchRuntimeProfiler] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.28 GenericMenuResolver] loaded',
    '[HFALearn UI v1.9.29 JailpatchRuntimeProfiler] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=probe-only export=legacy-v1+igmm-v1+jsonl',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=runtime-record-profiler export=legacy-v1+igmm-v1+jsonl+jailpatch-jsonl',
    'update dual mode marker',
)

g = replace_exact(
    g,
    'HFAMap v1.9.28 GenericMenuResolver',
    'HFAMap v1.9.29 JailpatchRuntimeProfiler',
    2,
    'update generic resolver version',
)
g = replace_once(g, '@"1.9.28"', '@"1.9.29"', 'update generic json version')

macro_anchor = '#define M0(r,o,s) ((r(*)(id,SEL))objc_msgSend)((id)(o),sel_registerName(s))\n'
l = replace_once(
    l,
    macro_anchor,
    'extern void HFAJailpatchProfileTarget(id,const char*);\n' + macro_anchor,
    'declare jailpatch profiler bridge',
)

l = replace_once(
    l,
    'static void auto_target(id o){\n    HFAGenericMenuObserveObject(o,"auto-target");\n',
    'static void auto_target(id o){\n    HFAGenericMenuObserveObject(o,"auto-target");\n    HFAJailpatchProfileTarget(o,"auto-target");\n',
    'profile auto target',
)

l = replace_once(
    l,
    'static void hooksend(id self,SEL cmd,SEL action,id target,id event){HFAGenericMenuObserveAction(self,target,action);unsigned int ev=0;',
    'static void hooksend(id self,SEL cmd,SEL action,id target,id event){HFAGenericMenuObserveAction(self,target,action);HFAJailpatchProfileTarget(target,"control-action");unsigned int ev=0;',
    'profile action target',
)

l = replace_once(
    l,
    'HFAMap v1.9.28 Generic Menu',
    'HFAMap v1.9.29 Jailpatch Profiler',
    'update panel title',
)
l = replace_once(
    l,
    'Generic AP/IGSecret resolver enabled.\\nOpen the menu and run Auto Detect / Full Scan.',
    'Legacy resolver + Jailpatch runtime profiler enabled.\\nOpen the menu and run Auto Detect / Full Scan.',
    'update panel help',
)

patch_path.write_text(s)
legacy_path.write_text(l)
generic_path.write_text(g)
