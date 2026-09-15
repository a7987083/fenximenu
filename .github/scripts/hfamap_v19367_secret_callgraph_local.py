from pathlib import Path

path = Path('hfamap/src/HFAMapSecretCallGraphProbe.m')
s = path.read_text()

# Remove the historical #if 0 Key2 early-listener implementation entirely.
# Although dead at compile time, it still contains a persistent
# _dyld_register_func_for_add_image path and sample-specific RiseofBerk offsets.
# v1.9.36.7 keeps no such process-wide/dyld-startup discovery even as dormant
# source: all discovery must be app-local and explicit.
dead_start = s.find('#if 0\n')
dead_end_marker = '\n#endif\n\nstatic int gKey2PathDone;\n'
if dead_start >= 0:
    dead_end = s.find(dead_end_marker, dead_start)
    if dead_end < 0:
        raise SystemExit('disabled Key2 block end not found')
    s = (
        s[:dead_start]
        + 'extern unsigned HFAAppLocalCopyClassesForImage(const char *image, Class *buffer, unsigned capacity);\n\n'
        + 'static int gKey2PathDone;\n'
        + s[dead_end + len(dead_end_marker):]
    )
elif 'extern unsigned HFAAppLocalCopyClassesForImage' not in s:
    raise SystemExit('disabled Key2 block already absent but app-local declaration missing')

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

for forbidden in ('objc_getClassList', '_dyld_register_func_for_add_image'):
    if forbidden in s:
        raise SystemExit(f'HFAMapSecretCallGraphProbe still contains {forbidden}')

path.write_text(s)
print('patched SecretCallGraphProbe to app-local image classes; removed dormant dyld listener')
