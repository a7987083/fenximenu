from pathlib import Path
import re

ROOT = Path('hfamap')
SRC = ROOT / 'src'
APP = SRC / 'HFAMapAppLocalResolver.m'
GENERIC = SRC / 'HFAMapGenericMenuResolver.m'
SECRET = SRC / 'HFAMapSecretCallGraphProbe.m'
LEGACY = SRC / 'HFAMapLegacy.m'
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


def ensure_import(text):
    if '#import "HFAMapOutputPaths.h"' in text:
        return text
    lines = text.splitlines(True)
    insert = 0
    for i, line in enumerate(lines):
        if line.startswith('#import '): insert = i + 1
    lines.insert(insert, '#import "HFAMapOutputPaths.h"\n')
    return ''.join(lines)

# 1) Discovery-only: the first scan only needs app-local disk + direct dyld
# discovery. Disable recursive dependency load-command expansion, which is not
# required to identify the menu dylib and was the last recorded stage in the
# ProDragon scan-crash log.
app = APP.read_text()
app = replace_fn(app, 'HFAAppLocalDependencyRecords', r'''static NSArray<NSDictionary *> *HFAAppLocalDependencyRecords(void) {
    HFAAppLocalLog(@"[DEPENDENCY-OWNERS] mode=disabled reason=discovery-only");
    return @[];
}''')
APP.write_text(app)

# 2) Route multiline Foundation path constructions missed by the first pass.
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

# 3) HFAMapLegacy is deliberately Foundation-free C-style Objective-C. Expose
# one C bridge so it uses the same per-bundle output directory without pulling
# Foundation types into that translation unit.
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
if 'HFAAppLocalScanCandidates' not in app:
    raise SystemExit('candidate discovery missing')

leftovers = []
for path in list(SRC.glob('*.m')) + list(SRC.glob('*.mm')):
    if path.name == 'HFAMapOutputPaths.m':
        continue
    s = path.read_text()
    if 'Documents/HFAMap_' in s or '/Documents/HFAMap_' in s:
        leftovers.append(path.name)
if leftovers:
    raise SystemExit('direct HFAMap output paths remain: ' + ','.join(leftovers))

print('v0.3.2 safe discovery + complete bundle output routing applied')
