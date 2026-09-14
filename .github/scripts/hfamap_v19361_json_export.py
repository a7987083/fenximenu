from pathlib import Path

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
legacy = legacy_path.read_text()


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)

# v1.9.36.5 keeps the frozen v1.9.36 scan/resolver path and the
# analysis-only JSONExport behavior from v1.9.36.4. The only startup change is
# an intentional 5-second first-start delay: no HFAMap tick/tryhook/UI work is
# performed during that window. After the delayed first tick, the original
# 0.5-second repeating tick cadence is restored.
macro_anchor = '#define M0(r,o,s)'
legacy = once(
    legacy,
    macro_anchor,
    'extern BOOL HFAMapJSONExportLatest(void);\n' + macro_anchor,
    'declare JSON exporter',
)

legacy = once(
    legacy,
    'unsigned int valid=run_full_scan();',
    'unsigned int valid=run_full_scan();(void)HFAMapJSONExportLatest();',
    'export normalized analysis JSON after scan',
)

# Delay all HFAMap activity for the first 5 seconds, then immediately perform
# the first normal tick and restore the original 0.5-second repeating timer.
delayed_start = (
    'static void hfaDelayedStart(id self,SEL c,id timer){(void)c;(void)timer;'
    'tick(self,sel_registerName("tick:"),(id)0);Class t=objc_getClass("NSTimer");'
    'if(t&&self)M5(id,(id)t,"scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",'
    'double,.5,id,self,SEL,sel_registerName("tick:"),id,(id)0,BOOL,1);}\n'
)
legacy = once(
    legacy,
    '__attribute__((constructor)) static void init(void){',
    delayed_start + '__attribute__((constructor)) static void init(void){',
    'insert delayed first-start callback',
)

legacy = once(
    legacy,
    'class_addMethod(c,sel_registerName("tick:"),(IMP)tick,"v@:@");',
    'class_addMethod(c,sel_registerName("tick:"),(IMP)tick,"v@:@");'
    'class_addMethod(c,sel_registerName("hfaDelayedStart:"),(IMP)hfaDelayedStart,"v@:@");',
    'register delayed first-start callback',
)

legacy = once(
    legacy,
    'if(t&&gTarget)M5(id,(id)t,"scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",double,.5,id,gTarget,SEL,sel_registerName("tick:"),id,(id)0,BOOL,1);}',
    'if(t&&gTarget)M5(id,(id)t,"scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",double,5.0,id,gTarget,SEL,sel_registerName("hfaDelayedStart:"),id,(id)0,BOOL,0);}',
    'replace immediate repeating timer with five-second one-shot start',
)

legacy = once(
    legacy,
    'HFAMap v1.9.36 Architecture Truth',
    'HFAMap v1.9.36.5 JSON Export Delay5s',
    'update visible panel title',
)
legacy = once(
    legacy,
    'Strict static-patch contract + target-derived architecture identity.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'Stable v1.9.36 parser + evidence-preserving JSON export.\\nFirst HFA activity delayed 5s; no playback/Dobby/runtime takeover.',
    'update visible panel help',
)

legacy_path.write_text(legacy)
print('patched HFAMap v1.9.36.5 JSONExport Delay5s integration')
