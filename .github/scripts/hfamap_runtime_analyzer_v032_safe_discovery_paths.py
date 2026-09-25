from pathlib import Path
import re

ROOT = Path('hfamap')
SRC = ROOT / 'src'
APP = SRC / 'HFAMapAppLocalResolver.m'
GENERIC = SRC / 'HFAMapGenericMenuResolver.m'
SECRET = SRC / 'HFAMapSecretCallGraphProbe.m'
LEGACY = SRC / 'HFAMapLegacy.m'
TRACE = SRC / 'HFAMapPatchExecutionTrace.m'
CYBER = SRC / 'HFAMapCyberUI.m'
HEADER = SRC / 'HFAMapOutputPaths.h'
IMPL = SRC / 'HFAMapOutputPaths.m'


def function_span(text, name):
    needle = name + '('
    pos = 0
    while True:
        i = text.find(needle, pos)
        if i < 0:
            raise SystemExit(f'{name}: function not found')
        start = text.rfind('\n', 0, i) + 1
        brace = text.find('{', i)
        semi = text.find(';', i)
        if brace >= 0 and (semi < 0 or brace < semi):
            depth = 0
            in_str = False
            esc = False
            for j in range(brace, len(text)):
                ch = text[j]
                if in_str:
                    if esc: esc = False
                    elif ch == '\\': esc = True
                    elif ch == '"': in_str = False
                    continue
                if ch == '"': in_str = True; continue
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0: return start, j + 1
        pos = i + len(needle)


def replace_fn(text, name, replacement):
    a, b = function_span(text, name)
    return text[:a] + replacement + text[b:]


def method_span(text, signature):
    i = text.find(signature)
    if i < 0:
        raise SystemExit(f'{signature}: method not found')
    start = text.rfind('\n', 0, i) + 1
    brace = text.find('{', i)
    if brace < 0:
        raise SystemExit(f'{signature}: opening brace missing')
    depth = 0
    in_str = False
    esc = False
    for j in range(brace, len(text)):
        ch = text[j]
        if in_str:
            if esc: esc = False
            elif ch == '\\': esc = True
            elif ch == '"': in_str = False
            continue
        if ch == '"': in_str = True; continue
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: return start, j + 1
    raise SystemExit(f'{signature}: closing brace missing')


def ensure_import(text):
    if '#import "HFAMapOutputPaths.h"' in text:
        return text
    lines = text.splitlines(True)
    insert = 0
    for i, line in enumerate(lines):
        if line.startswith('#import '): insert = i + 1
    lines.insert(insert, '#import "HFAMapOutputPaths.h"\n')
    return ''.join(lines)

# 1) Discovery-only. Direct dependency load-command walking is not needed for
# locating the menu dylib and was the last completed stage in the ProDragon
# scan-crash log. Keep recursive app-local/dyld discovery, but disable this
# extra dependency expansion in the first button.
app = APP.read_text()
app = replace_fn(app, 'HFAAppLocalDependencyRecords', r'''static NSArray<NSDictionary *> *HFAAppLocalDependencyRecords(void) {
    HFAAppLocalLog(@"[DEPENDENCY-OWNERS] mode=disabled reason=discovery-only");
    return @[];
}''')
APP.write_text(app)

# 2) Every selected menu dylib must reach AutoBackend when the user explicitly
# presses Parse/Export. Previously the analyzer was attached to a legacy patch
# package branch, so runtime-only games such as Duck/Path never emitted V032.
trace = TRACE.read_text()
trace, removed = re.subn(
    r'\s*unsigned\s+v03Native\s*=\s*HFAAnalyzerV02ScanSelectedImage\(\);\s*HFALog\("\[V03-OWNERSHIP-FINALIZE\][^;]*;\s*',
    '\n', trace, count=1, flags=re.S)
if removed == 0:
    # tolerate the v02 spelling in case the generator chain changes order
    trace, removed = re.subn(
        r'\s*unsigned\s+v02Native\s*=\s*HFAAnalyzerV02ScanSelectedImage\(\);\s*HFALog\("\[V02-OWNERSHIP-FINALIZE\][^;]*;\s*',
        '\n', trace, count=1, flags=re.S)
TRACE.write_text(trace)

cyber = CYBER.read_text()
if 'extern unsigned HFAAnalyzerV02ScanSelectedImage(void);' not in cyber:
    anchor = 'extern unsigned HFAAppLocalExecuteParser(void);\n'
    if anchor not in cyber:
        raise SystemExit('CyberUI parser extern anchor missing')
    cyber = cyber.replace(anchor, anchor + 'extern unsigned HFAAnalyzerV02ScanSelectedImage(void);\n', 1)

new_export = r'''- (void)actionCyberExport:(UIButton *)sender {
    sender.enabled = NO;
    HFACyberUIAppendLog(@"\n[COMMAND] 解析并导出");
    HFACyberUIAppendLog(@"[RESOLVE] family parser starting ...");
    dispatch_async(dispatch_get_main_queue(), ^{
        unsigned valid = HFAAppLocalExecuteParser();
        HFACyberUIAppendLog([NSString stringWithFormat:@"[FAMILY-EXPORT-END] validMappings=%u", valid]);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            unsigned backends = HFAAnalyzerV02ScanSelectedImage();
            HFACyberUIAppendLog([NSString stringWithFormat:@"[AUTOBACKEND-END] backends=%u", backends]);
            dispatch_async(dispatch_get_main_queue(), ^{ sender.enabled = YES; });
        });
    });
}'''
a, b = method_span(cyber, '- (void)actionCyberExport:')
cyber = cyber[:a] + new_export + cyber[b:]
CYBER.write_text(cyber)

# 3) Route multiline Foundation path constructions missed by the first pass.
for path in (GENERIC, SECRET):
    s = path.read_text()
    s2 = re.sub(
        r'\[NSHomeDirectory\(\)\s*stringByAppendingPathComponent:@"Documents/(HFAMap_[^"]+)"\]',
        r'HFAOutputPath(@"\1")',
        s,
        flags=re.S,
    )
    if s2 != s:
        s2 = ensure_import(s2)
        path.write_text(s2)

# 4) HFAMapLegacy is deliberately Foundation-free C-style Objective-C. Expose
# one C bridge so it uses the same per-bundle output directory.
h = HEADER.read_text()
if 'HFAOutputCopyPath' not in h:
    h += '\nFOUNDATION_EXPORT void HFAOutputCopyPath(char *buffer, unsigned long capacity, const char *filename);\n'
HEADER.write_text(h)

m = IMPL.read_text()
if 'void HFAOutputCopyPath(' not in m:
    m += r'''

void HFAOutputCopyPath(char *buffer, unsigned long capacity, const char *filename) {
    if (!buffer || !capacity) return;
    buffer[0] = 0;
    @autoreleasepool {
        NSString *name = filename ? [NSString stringWithUTF8String:filename] : @"";
        NSString *path = HFAOutputPath(name ?: @"");
        const char *fs = path.fileSystemRepresentation;
        if (!fs) return;
        snprintf(buffer, (size_t)capacity, "%s", fs);
    }
}
'''
    if '#include <stdio.h>' not in m:
        m = m.replace('#import "HFAMapOutputPaths.h"', '#import "HFAMapOutputPaths.h"\n#include <stdio.h>', 1)
IMPL.write_text(m)

legacy = LEGACY.read_text()
if 'extern void HFAOutputCopyPath' not in legacy:
    anchor = 'extern FILE* fopen(const char*,const char*);'
    if anchor not in legacy:
        raise SystemExit('HFAMapLegacy extern anchor missing')
    legacy = legacy.replace(anchor, 'extern void HFAOutputCopyPath(char*,size_t,const char*); ' + anchor, 1)
legacy = replace_fn(legacy, 'initlog', r'''static void initlog(void){HFAOutputCopyPath(gLogPath,sizeof(gLogPath),"HFAMap_Learn.log");if(!gLogPath[0])return;logf("[HFALearn UI v1.8.7 KeyRegisterProbe] loaded\n");}''')
LEGACY.write_text(legacy)

# Explicit regression gates.
app = APP.read_text()
if '[DEPENDENCY-OWNERS] mode=disabled reason=discovery-only' not in app:
    raise SystemExit('discovery dependency scan was not disabled')
ui = CYBER.read_text()
scan_a, scan_b = method_span(ui, '- (void)actionCyberScan:')
scan_body = ui[scan_a:scan_b]
if 'HFAAppLocalScanCandidates()' not in scan_body:
    raise SystemExit('baseline candidate discovery missing from first button')
if 'HFAAnalyzerV02ScanSelectedImage' in scan_body or 'HFAAppLocalExecuteParser' in scan_body:
    raise SystemExit('deep resolver leaked into first button')
export_a, export_b = method_span(ui, '- (void)actionCyberExport:')
export_body = ui[export_a:export_b]
if 'HFAAppLocalExecuteParser()' not in export_body or 'HFAAnalyzerV02ScanSelectedImage()' not in export_body:
    raise SystemExit('second button does not run parser + AutoBackend')

leftovers = []
for path in list(SRC.glob('*.m')) + list(SRC.glob('*.mm')):
    if path.name == 'HFAMapOutputPaths.m':
        continue
    s = path.read_text()
    if 'Documents/HFAMap_' in s or '/Documents/HFAMap_' in s:
        leftovers.append(path.name)
if leftovers:
    raise SystemExit('direct HFAMap output paths remain: ' + ','.join(leftovers))

print('v0.3.2 safe discovery + universal AutoBackend entry + bundle output routing applied')
