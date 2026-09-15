from pathlib import Path

path = Path('hfamap/src/HFAMapSecretCallGraphProbe.m')
s = path.read_text()

extern_anchor = '#endif\n\nstatic int gKey2PathDone;\n'
extern_decl = (
    '#endif\n\n'
    'extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);\n\n'
    'static int gKey2PathDone;\n'
)
if 'extern unsigned HFAAppLocalCopyClassesForImage' not in s:
    if s.count(extern_anchor) != 1:
        raise SystemExit(f'extern anchor expected once, got {s.count(extern_anchor)}')
    s = s.replace(extern_anchor, extern_decl, 1)

start = s.find('static void HFALogMethodsForNodes(uintptr_t base, const char *image,')
if start < 0:
    raise SystemExit('HFALogMethodsForNodes start not found')
brace = s.find('{', start)
if brace < 0:
    raise SystemExit('HFALogMethodsForNodes opening brace not found')
depth = 0
end = None
for i in range(brace, len(s)):
    if s[i] == '{':
        depth += 1
    elif s[i] == '}':
        depth -= 1
        if depth == 0:
            end = i + 1
            break
if end is None:
    raise SystemExit('HFALogMethodsForNodes closing brace not found')

replacement = r'''static void HFALogMethodsForNodes(uintptr_t base, const char *image,
                                  const uintptr_t *nodes,
                                  unsigned nodeCount) {
    if (!base || !image || !*image || !nodes || !nodeCount) return;

    Class classes[512] = {0};
    unsigned classCount = HFAAppLocalCopyClassesForImage(image, classes, 512);
    unsigned matches = 0;

    for (unsigned i = 0; i < classCount; i++) {
        Class cls = classes[i];
        if (!cls) continue;
        Class owners[2] = {cls, object_getClass(cls)};
        for (unsigned kind = 0; kind < 2; kind++) {
            if (!owners[kind]) continue;
            unsigned methodCount = 0;
            Method *methods = class_copyMethodList(owners[kind], &methodCount);
            for (unsigned m = 0; methods && m < methodCount; m++) {
                uintptr_t implementation = HFAStripPointer(
                    (uintptr_t)method_getImplementation(methods[m]));
                for (unsigned n = 0; n < nodeCount; n++) {
                    if (implementation != nodes[n]) continue;
                    HFAKey2Log("[KEY2-METHOD] kind=%c class=%s selector=%s rva=%llX\n",
                               kind ? '+' : '-',
                               class_getName(cls),
                               sel_getName(method_getName(methods[m])),
                               (unsigned long long)(implementation - base));
                    matches++;
                }
            }
            free(methods);
        }
    }
    HFAKey2Log("[KEY2-METHOD-END] image=%s classes=%u matches=%u nodes=%u\n",
               image, classCount, matches, nodeCount);
}'''

s = s[:start] + replacement + s[end:]

if 'objc_getClassList' in s:
    raise SystemExit('HFAMapSecretCallGraphProbe still contains objc_getClassList')

path.write_text(s)
print('patched SecretCallGraphProbe to app-local image class discovery')
