from pathlib import Path

trace_path = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
trace = trace_path.read_text()


def replace_function(text, signature, replacement):
    start = text.find(signature)
    if start < 0:
        raise SystemExit(f'{signature}: not found')
    brace = text.find('{', start)
    if brace < 0:
        raise SystemExit(f'{signature}: opening brace not found')
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[:start] + replacement + text[i + 1:]
    raise SystemExit(f'{signature}: closing brace not found')

anchor = '#include <string.h>\n'
decls = (
    'extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);\n'
    'extern const char *HFAAppLocalPrimaryImage(void);\n'
)
if 'HFAAppLocalCopyClassesForImage' not in trace:
    if trace.count(anchor) != 1:
        raise SystemExit(f'include anchor expected once, got {trace.count(anchor)}')
    trace = trace.replace(anchor, anchor + decls, 1)

signature = 'static unsigned HFAInstallDynamicApplyHooksForImage(const char *image)'
replacement = r'''static unsigned HFAInstallDynamicApplyHooksForImage(const char *image) {
    if (!image || !*image) return 0;
    if (gDynamicApplyInstalledImage[0] &&
        strcmp(gDynamicApplyInstalledImage, image) == 0)
        return 0;

    Class classes[512] = {0};
    unsigned classCount = HFAAppLocalCopyClassesForImage(image, classes, 512);
    unsigned candidates = 0, installed = 0;

    for (unsigned ci = 0; ci < classCount && gDynamicApplyHookCount < 64; ci++) {
        Class cls = classes[ci];
        if (!cls) continue;
        Class meta = object_getClass(cls);
        if (!meta) continue;
        unsigned methodCount = 0;
        Method *methods = class_copyMethodList(meta, &methodCount);
        for (unsigned mi = 0; methods && mi < methodCount &&
             gDynamicApplyHookCount < 64; mi++) {
            Method method = methods[mi];
            int stage = HFADynamicApplyStageForMethod(method);
            if (!stage) continue;
            IMP original = method_getImplementation(method);
            Dl_info info = {0};
            if (!original || !dladdr((void *)original, &info) ||
                !info.dli_fname || !info.dli_fbase)
                continue;
            if (strcmp(HFABase(info.dli_fname), image) != 0) continue;
            candidates++;
            SEL sel = method_getName(method);
            if (!sel || HFADynamicApplyHookFor(meta, sel)) continue;

            HFADynamicApplyHook *hook = &gDynamicApplyHooks[gDynamicApplyHookCount++];
            memset(hook, 0, sizeof(*hook));
            hook->owner = meta;
            hook->sel = sel;
            hook->original = original;
            hook->stage = (unsigned)stage;
            hook->rva = (uintptr_t)original - (uintptr_t)info.dli_fbase;
            snprintf(hook->image, sizeof(hook->image), "%s", image);

            IMP replacementIMP = stage == 1 ? (IMP)HFADynamicApplyOffset
                                             : (IMP)HFADynamicApplyResolved;
            method_setImplementation(method, replacementIMP);
            installed++;
            HFALog("[APPLOCAL-DYNAMIC-APPLY-HOOK] image=%s class=%s selector=%s stage=%s rva=%llX installed=1\n",
                   image, class_getName(cls), sel_getName(sel),
                   stage == 1 ? "offset" : "resolved",
                   (unsigned long long)hook->rva);
        }
        free(methods);
    }
    snprintf(gDynamicApplyInstalledImage, sizeof(gDynamicApplyInstalledImage),
             "%s", image);
    HFALog("[APPLOCAL-DYNAMIC-APPLY-SCAN] image=%s classes=%u candidates=%u installed=%u\n",
           image, classCount, candidates, installed);
    return installed;
}'''
trace = replace_function(trace, signature, replacement)
trace_path.write_text(trace)
print('patched dynamic apply discovery to app-local image classes')
