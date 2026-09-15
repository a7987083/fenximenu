from pathlib import Path

legacy_path = Path('hfamap/src/HFAMapLegacy.m')
trace_path = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
generic_path = Path('hfamap/src/HFAMapGenericMenuResolver.m')
exporter_path = Path('hfamap/src/HFAMapJSONExport.m')
makefile_path = Path('hfamap/Makefile')

legacy = legacy_path.read_text()
trace = trace_path.read_text()
generic = generic_path.read_text()
exporter = exporter_path.read_text()
makefile = makefile_path.read_text()


def once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    return text.replace(old, new, 1)


def function_span(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        line_start = text.rfind('\n', 0, i) + 1
        prefix = text[line_start:i].strip()
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi) and prefix and not prefix.startswith(('if', 'for', 'while', 'return')):
            depth = 0
            for j in range(brace, len(text)):
                if text[j] == '{':
                    depth += 1
                elif text[j] == '}':
                    depth -= 1
                    if depth == 0:
                        return line_start, j + 1, text[line_start:j + 1]
            raise SystemExit(f'{name}: closing brace not found')
        pos = i + len(needle)


def replace_named_function(text, name, replacement):
    start, end, old = function_span(text, name)
    return text[:start] + replacement + text[end:], old


# ---------------------------------------------------------------------------
# Legacy UI + action bridge: keep the existing floating button/window/bootstrap,
# but replace only the panel appearance with the user-approved Cyber UI.
# ---------------------------------------------------------------------------
macro_anchor = '#define M0(r,o,s)'
externs = (
    'extern id HFACyberUICreatePanel(id window);\n'
    'extern void HFACyberUIToggle(void);\n'
    'extern void HFACyberUIBringToFront(id window);\n'
    'extern void HFACyberUIAppendLog(id text);\n'
    'extern unsigned int HFAAppLocalScanCandidates(void);\n'
    'extern unsigned int HFAAppLocalInspectCandidates(void);\n'
    'extern const char *HFAAppLocalPrimaryImage(void);\n'
)
if 'extern id HFACyberUICreatePanel' not in legacy:
    legacy = once(legacy, macro_anchor, externs + macro_anchor, 'add AppLocal/Cyber declarations')

bridge = r'''unsigned int HFAAppLocalExecuteParser(void){
    gAttached=1;gFound[0]=0;
    const char*candidate=HFAAppLocalPrimaryImage();
    if(!candidate||!*candidate){HFAAppLocalScanCandidates();candidate=HFAAppLocalPrimaryImage();}
    if(candidate&&*candidate)HFAPatchTraceSetTarget(candidate);
    logf("[APPLOCAL-RESOLVE-BEGIN] primary=%s\n",candidate&&*candidate?candidate:"?");
    HFAAppLocalInspectCandidates();
    HFAPatchTracePrepareForManualScan();
    unsigned int valid=run_full_scan();
    BOOL exported=HFAMapJSONExportLatest();
    logf("[APPLOCAL-RESOLVE-END] primary=%s validMappings=%u json=%d\n",candidate&&*candidate?candidate:"?",valid,(int)exported);
    Class sc=objc_getClass("NSString");
    if(sc){
        id msg=M1(id,(id)sc,"stringWithFormat:",id,ns("[EXPORT] primary=%s validMappings=%u json=%d"),candidate&&*candidate?candidate:"?",valid,(int)exported);
        if(msg)HFACyberUIAppendLog(msg);
    }
    return valid;
}

'''
# Avoid Objective-C variadic message complexity in the compact legacy source by
# using a fixed status string for the on-screen summary instead.
bridge = bridge.replace(
    '    Class sc=objc_getClass("NSString");\n    if(sc){\n        id msg=M1(id,(id)sc,"stringWithFormat:",id,ns("[EXPORT] primary=%s validMappings=%u json=%d"),candidate&&*candidate?candidate:"?",valid,(int)exported);\n        if(msg)HFACyberUIAppendLog(msg);\n    }\n',
    '    HFACyberUIAppendLog(exported?ns("[EXPORT] JSON export completed"):ns("[EXPORT] JSON export produced no analysis file"));\n'
)
attach_start, _, _ = function_span(legacy, 'attach')
if 'unsigned int HFAAppLocalExecuteParser(void)' not in legacy:
    legacy = legacy[:attach_start] + bridge + legacy[attach_start:]

legacy, _ = replace_named_function(
    legacy,
    'attach',
    'static void attach(id self,SEL c,id sender){(void)self;(void)c;(void)sender;(void)HFAAppLocalExecuteParser();}'
)

mkui = r'''static void mkui(id w){
    if(gMade||!w)return;
    Class bc=objc_getClass("UIButton");if(!bc)return;
    id b=M0(id,(id)bc,"alloc");b=M1(id,b,"initWithFrame:",CGRect,((CGRect){{18,165},{52,52}}));
    M2(void,b,"setTitle:forState:",id,ns("HF"),u64,0);
    M1(void,b,"setBackgroundColor:",id,color(.12,.12,.15,.94));
    id ly=M0(id,b,"layer");if(ly)M1(void,ly,"setCornerRadius:",double,26);
    M3(void,b,"addTarget:action:forControlEvents:",id,gTarget,SEL,sel_registerName("tap:"),u64,TOUCHUP);
    Class pc=objc_getClass("UIPanGestureRecognizer");if(pc){id pg=M0(id,(id)pc,"alloc");pg=M2(id,pg,"initWithTarget:action:",id,gTarget,SEL,sel_registerName("pan:"));M1(void,b,"addGestureRecognizer:",id,pg);}
    M1(void,w,"addSubview:",id,b);gButton=b;
    gPanel=HFACyberUICreatePanel(w);gWindow=w;gMade=1;
}'''
legacy, _ = replace_named_function(legacy, 'mkui', mkui)

tick = r'''static void tick(id self,SEL c,id timer){
    (void)self;(void)c;(void)timer;tryhook();id w=win();if(!w)return;
    if(!gMade)mkui(w);
    if(gMade&&gWindow!=w){if(gPanel)M1(void,w,"addSubview:",id,gPanel);if(gButton)M1(void,w,"addSubview:",id,gButton);gWindow=w;}
    if(gMade){HFACyberUIBringToFront(w);if(gButton)M1(void,w,"bringSubviewToFront:",id,gButton);}
}'''
legacy, _ = replace_named_function(legacy, 'tick', tick)
legacy, _ = replace_named_function(
    legacy,
    'tap',
    'static void tap(id self,SEL c,id s){(void)self;(void)c;(void)s;HFACyberUIToggle();}'
)

legacy = legacy.replace('HFAMap v1.9.36.6 JSON Export LazyScan',
                        'HFAMap v1.9.36.7 AppLocalMenuResolver')

# ---------------------------------------------------------------------------
# Trace layer: every class operation is constrained to one selected loaded
# app-local image. There must be no process-wide objc_getClassList call left.
# ---------------------------------------------------------------------------
trace_decl_anchor = '#include <string.h>\n'
trace_decls = (
    'extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);\n'
    'extern const char *HFAAppLocalPrimaryImage(void);\n'
)
if 'HFAAppLocalCopyClassesForImage' not in trace:
    trace = once(trace, trace_decl_anchor, trace_decl_anchor + trace_decls, 'add trace app-local declarations')

safe_queries = r'''static void HFAInstallStateQueriesForImage(const char *image) {
    if (!image || !*image || strcmp(gQueryImage, image) == 0) return;
    Class classes[512] = {0};
    unsigned classCount = HFAAppLocalCopyClassesForImage(image, classes, 512);
    unsigned installed = 0;
    for (unsigned i = 0; i < classCount; i++) {
        Class cls = classes[i];
        installed += HFAInstallQueryMethods(cls);
        Class meta = object_getClass(cls);
        if (meta) installed += HFAInstallQueryMethods(meta);
    }
    snprintf(gQueryImage, sizeof(gQueryImage), "%s", image);
    HFALog("[APPLOCAL-QUERY-INSTALL] image=%s classes=%u methods=%u total=%u\n",
           image, classCount, installed, gQueryHookCount);
}'''
trace, _ = replace_named_function(trace, 'HFAInstallStateQueriesForImage', safe_queries)

safe_native = r'''static void HFAInstallNativeHookAPIsForImage(const char *image) {
    if (!image || !*image) return;
    Class classes[512] = {0};
    unsigned classCount = HFAAppLocalCopyClassesForImage(image, classes, 512);
    unsigned installed = 0;
    for (unsigned i = 0; i < classCount; i++) {
        Class cls = classes[i];
        installed += HFAInstallNativeHookAPIsOnOwner(cls, image);
        Class meta = object_getClass(cls);
        if (meta) installed += HFAInstallNativeHookAPIsOnOwner(meta, image);
    }
    HFALog("[APPLOCAL-NATIVE-HOOK-SCAN] image=%s classes=%u installed=%u totalAPIs=%u\n",
           image, classCount, installed, gNativeHookAPICount);
}'''
trace, _ = replace_named_function(trace, 'HFAInstallNativeHookAPIsForImage', safe_native)

safe_wrapper = r'''static id HFAStaticCreateSecretWrapper(const char *image,
                                       uintptr_t secretAddress) {
    if (!image || !*image || !secretAddress) return nil;
    SEL secretSel = sel_registerName("secret");
    Class classes[512] = {0};
    unsigned classCount = HFAAppLocalCopyClassesForImage(image, classes, 512);
    id result = nil;
    for (unsigned i = 0; i < classCount && !result; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        Method getter = class_getInstanceMethod(cls, secretSel);
        if (!getter) continue;
        IMP getterIMP = method_getImplementation(getter);
        Dl_info info = {0};
        if (!getterIMP || !dladdr((void *)getterIMP, &info) ||
            !info.dli_fname || strcmp(HFABase(info.dli_fname), image) != 0)
            continue;
        SEL initSel = HFAStaticSecretInitializerForClass(cls);
        if (!initSel) continue;
        id object = ((id(*)(id,SEL))objc_msgSend)((id)cls, sel_registerName("alloc"));
        if (!object) continue;
        result = ((id(*)(id,SEL,const void *))objc_msgSend)(object, initSel,
                                                           (const void *)secretAddress);
        if (result) {
            HFALog("[APPLOCAL-STATIC-NATIVE-WRAPPER] image=%s class=%s initializer=%s wrapper=%p secret=%p\n",
                   image, class_getName(cls), sel_getName(initSel), result,
                   (void *)secretAddress);
        }
    }
    return result;
}'''
trace, _ = replace_named_function(trace, 'HFAStaticCreateSecretWrapper', safe_wrapper)

safe_dynamic = r'''static unsigned HFAInstallDynamicRegistrationHooks(void) {
    HFALog("[APPLOCAL-DYNAMIC-REGISTRATION] disabled=1 reason=process-wide-class-enumeration-removed\n");
    return 0;
}'''
trace, _ = replace_named_function(trace, 'HFAInstallDynamicRegistrationHooks', safe_dynamic)

safe_prepare = r'''void HFAPatchTracePrepareForManualScan(void) {
    const char *image = HFAAppLocalPrimaryImage();
    if (!image || !*image) {
        HFALog("[APPLOCAL-PREPARE] status=no-candidate\n");
        return;
    }
    int index = HFAImageIndexForName(image);
    if (index < 0) {
        HFALog("[APPLOCAL-PREPARE] image=%s status=not-loaded\n", image);
        return;
    }
    const struct mach_header *header = _dyld_get_image_header((uint32_t)index);
    intptr_t slide = _dyld_get_image_vmaddr_slide((uint32_t)index);
    if (header) HFANativeImageAdded(header, slide);
    HFALog("[APPLOCAL-PREPARE] image=%s index=%d nativeAPIs=%u\n",
           image, index, gNativeHookAPICount);
}'''
trace, _ = replace_named_function(trace, 'HFAPatchTracePrepareForManualScan', safe_prepare)

if 'objc_getClassList' in trace:
    positions = []
    start = 0
    while True:
        i = trace.find('objc_getClassList', start)
        if i < 0: break
        positions.append(trace[max(0, i - 80):i + 120].replace('\n', ' '))
        start = i + 1
    raise SystemExit('trace still contains process-wide objc_getClassList: ' + ' || '.join(positions))

# ---------------------------------------------------------------------------
# Generic resolver: discovery/class registry work is delegated to AppLocal.
# Object-level observers remain untouched and continue to parse real menu roots.
# ---------------------------------------------------------------------------
generic_arch = r'''static void HFAArchitectureScan(void) {
    HFAGenericLog("[GENERIC-ARCH] mode=app-local-delegated processWideClassScan=0\n");
    HFAGenericJSON(@{ @"record": @"architecture", @"mode": @"app-local-delegated",
                      @"processWideClassScan": @NO });
}'''
generic, _ = replace_named_function(generic, 'HFAArchitectureScan', generic_arch)

generic_classes = r'''static void HFAClassRegistryScan(void) {
    HFAGenericLog("[GENERIC-CLASS-SCAN] generation=%u mode=disabled appLocal=1\n",
                  gScanGeneration);
}'''
generic, _ = replace_named_function(generic, 'HFAClassRegistryScan', generic_classes)
if 'objc_getClassList' in generic:
    raise SystemExit('generic resolver still contains process-wide objc_getClassList')

# Analyzer/version markers.
exporter = exporter.replace('HFAMapUniversal v1.9.36.6 JSONExport LazyScan',
                            'HFAMapUniversal v1.9.36.7 AppLocalMenuResolver')

# Build integration (idempotent in case the branch Makefile already contains it).
files_line = next((line for line in makefile.splitlines() if line.startswith('HFAMapUniversal_FILES = ')), None)
if not files_line:
    raise SystemExit('Makefile HFAMapUniversal_FILES line missing')
new_files_line = files_line
for src in ('src/HFAMapAppLocalResolver.m', 'src/HFAMapCyberUI.m'):
    if src not in new_files_line:
        new_files_line += ' ' + src
makefile = makefile.replace(files_line, new_files_line, 1)
framework_line = next((line for line in makefile.splitlines() if line.startswith('HFAMapUniversal_FRAMEWORKS = ')), None)
if not framework_line:
    raise SystemExit('Makefile framework line missing')
if 'QuartzCore' not in framework_line:
    makefile = makefile.replace(framework_line, framework_line + ' QuartzCore', 1)

legacy_path.write_text(legacy)
trace_path.write_text(trace)
generic_path.write_text(generic)
exporter_path.write_text(exporter)
makefile_path.write_text(makefile)
print('patched HFAMap v1.9.36.7 AppLocalMenuResolver + Cyber UI')
