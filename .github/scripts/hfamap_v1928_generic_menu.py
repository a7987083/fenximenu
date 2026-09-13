from pathlib import Path

patch_path = Path("hfamap/src/HFAMapPatchExecutionTrace.m")
legacy_path = Path("hfamap/src/HFAMapLegacy.m")

s = patch_path.read_text()
l = legacy_path.read_text()


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, got {count}")
    return text.replace(old, new, 1)


# v1.9.28 GenericMenuResolver
# - preserves v1.9.27 target-chain behavior and both package exporters
# - adds a runtime-structure resolver for the legacy AP/IGSecret menu family
# - never keys recognition on obfuscated class/ivar names or sample RVAs
# - records a structured JSONL evidence stream beside HFAMap_Learn.log
# - recognizes the newer jailpatch metadata family only as probe-only until
#   device logs establish its record/table layout

s = replace_once(
    s,
    '[HFALearn v1.9.27 iGMMTargetChainResolver] loaded',
    '[HFALearn v1.9.28 GenericMenuResolver] loaded',
    'update core marker',
)
l = replace_once(
    l,
    '[HFALearn UI v1.9.27 iGMMTargetChainResolver] loaded',
    '[HFALearn UI v1.9.28 GenericMenuResolver] loaded',
    'update UI marker',
)
l = replace_once(
    l,
    '[DUAL-IOSGODS-MODE] legacy=unchanged igmm=runtime-target-chain export=legacy-v1+igmm-v1',
    '[DUAL-IOSGODS-MODE] legacy=generic-ap-resolver igmm=runtime-target-chain jailpatch=probe-only export=legacy-v1+igmm-v1+jsonl',
    'update dual mode marker',
)

macro_anchor = '#define M0(r,o,s) ((r(*)(id,SEL))objc_msgSend)((id)(o),sel_registerName(s))\n'
prototypes = (
    'extern void HFAGenericMenuRescan(void);\n'
    'extern void HFAGenericMenuObserveObject(id,const char*);\n'
    'extern void HFAGenericMenuObserveAction(id,id,SEL);\n'
)
l = replace_once(l, macro_anchor, prototypes + macro_anchor,
                 'declare generic menu resolver bridge')

l = replace_once(
    l,
    'static void auto_target(id o){\n',
    'static void auto_target(id o){\n    HFAGenericMenuObserveObject(o,"auto-target");\n',
    'observe auto target',
)
l = replace_once(
    l,
    'static void auto_view(id v,int depth){\n',
    'static void auto_view(id v,int depth){\n    HFAGenericMenuObserveObject(v,"ui-tree");\n',
    'observe ui tree',
)
l = replace_once(
    l,
    'static void hooksend(id self,SEL cmd,SEL action,id target,id event){unsigned int ev=0;',
    'static void hooksend(id self,SEL cmd,SEL action,id target,id event){HFAGenericMenuObserveAction(self,target,action);unsigned int ev=0;',
    'observe control action',
)
l = replace_once(
    l,
    'static void attach(id self,SEL c,id sender){(void)self;(void)c;(void)sender;gAttached=1;',
    'static void attach(id self,SEL c,id sender){(void)self;(void)c;(void)sender;gAttached=1;HFAGenericMenuRescan();',
    'run generic resolver before full scan',
)

l = replace_once(
    l,
    'HFAMap v1.8.7 Key Register',
    'HFAMap v1.9.28 Generic Menu',
    'update panel title',
)
l = replace_once(
    l,
    'Key registration is fingerprinted without table guesses.\\nOpen the menu, scan, then repeat user recognition.',
    'Generic AP/IGSecret resolver enabled.\\nOpen the menu and run Auto Detect / Full Scan.',
    'update panel help',
)

patch_path.write_text(s)
legacy_path.write_text(l)
