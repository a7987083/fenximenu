from pathlib import Path

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
legacy = legacy_path.read_text()
trace_path = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
trace = trace_path.read_text()
exporter_path = Path('hfamap/src/HFAMapJSONExport.m')
exporter = exporter_path.read_text()


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)


def replace_function(text, signature, replacement, label):
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f'{label}: signature not found')
    brace = text.find('{', start)
    if brace < 0:
        raise SystemExit(f'{label}: opening brace not found')
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
        raise SystemExit(f'{label}: closing brace not found')
    return text[:start] + replacement + text[end:]


# v1.9.36.6 keeps the frozen v1.9.36 parser/resolver and the analysis-only
# JSONExport semantics, but removes runtime/class discovery from dyld startup.
# The menu UI still starts after the existing 5-second bootstrap. Native menu
# image probing and Objective-C class enumeration are invoked only from the
# user's Auto Detect / Full Scan action. No add-image callback is registered.
macro_anchor = '#define M0(r,o,s)'
legacy = once(
    legacy,
    macro_anchor,
    'extern BOOL HFAMapJSONExportLatest(void);\n'
    'extern void HFAPatchTracePrepareForManualScan(void);\n' + macro_anchor,
    'declare JSON exporter and manual scan preparation',
)

legacy = once(
    legacy,
    'unsigned int valid=run_full_scan();',
    'HFAPatchTracePrepareForManualScan();unsigned int valid=run_full_scan();'
    '(void)HFAMapJSONExportLatest();',
    'prepare runtime evidence only when Full Scan is pressed',
)

# Preserve the requested five-second first UI/tick delay. This delay is no
# longer relied on for crash safety; the crash-producing class discovery path
# is independently removed from startup below.
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

# The historical trace constructor performed two unsafe startup actions:
#   1) _dyld_register_func_for_add_image(HFANativeImageAdded), whose immediate
#      replay over already-loaded images can call objc_getClassList while Swift
#      metadata/class realization is still in progress;
#   2) HFAInstallDynamicRegistrationHooks(), which also enumerates all classes.
# Keep both capabilities, but expose them only as an explicit manual-scan
# preparation step. Iterate the current dyld image set directly so no persistent
# add-image callback is installed. Repeated Full Scan presses re-run discovery,
# allowing modules loaded after an earlier scan to be picked up safely.
lazy_prepare = r'''void HFAPatchTracePrepareForManualScan(void) {
    static unsigned generation;
    generation++;
    uint32_t imageCount = _dyld_image_count();
    for (uint32_t i = 0; i < imageCount; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        HFANativeImageAdded(header, slide);
    }
    unsigned registrationHooks = HFAInstallDynamicRegistrationHooks();
    HFALog("[LAZY-SCAN-PREPARE] generation=%u images=%u registrationHooks=%u nativeAPIs=%u\n",
           generation, imageCount, registrationHooks, gNativeHookAPICount);
}

'''
constructor_signature = '__attribute__((constructor)) static void HFAInit(void)'
if trace.count(constructor_signature) != 1:
    raise SystemExit(f'trace constructor: expected 1 match, got {trace.count(constructor_signature)}')
trace = once(
    trace,
    constructor_signature,
    lazy_prepare + constructor_signature,
    'insert manual-only trace preparation',
)
trace = replace_function(
    trace,
    constructor_signature,
    '__attribute__((constructor)) static void HFAInit(void) {\n}',
    'make trace constructor passive',
)

legacy = once(
    legacy,
    'HFAMap v1.9.36 Architecture Truth',
    'HFAMap v1.9.36.6 JSON Export LazyScan',
    'update visible panel title',
)
legacy = once(
    legacy,
    'Strict static-patch contract + target-derived architecture identity.\\niGMM runtime hooks remain diagnostics until a portable static equivalent is proven.',
    'Stable v1.9.36 parser + evidence-preserving JSON export.\\nRuntime/class discovery starts only when Full Scan is pressed.',
    'update visible panel help',
)

exporter = once(
    exporter,
    'HFAMapUniversal v1.9.36.4 JSONExport',
    'HFAMapUniversal v1.9.36.6 JSONExport LazyScan',
    'update analysis JSON analyzer version',
)

legacy_path.write_text(legacy)
trace_path.write_text(trace)
exporter_path.write_text(exporter)
print('patched HFAMap v1.9.36.6 JSONExport LazyScan integration')
