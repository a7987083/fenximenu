from pathlib import Path

p = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s = p.read_text()
marker = 'typedef int (*HFASecretDecryptFn)(void *, void *);'
proto = '''static int HFAReadable(uintptr_t address, size_t length);\nstatic int HFAFeatureLabelNumeric(const char *s);\nextern void HFAProbeKey2Path(uintptr_t getterAddress);\nextern unsigned HFAAnalyzerV02ScanSelectedImage(void);\n\n'''
if proto.strip() not in s:
    if marker not in s:
        raise SystemExit('prototype anchor missing')
    s = s.replace(marker, proto + marker, 1)
old = 'static uintptr_t HFAResolveSecretDecrypt(IMP getter, Dl_info *getterInfoOut,'
new = 'static __attribute__((unused)) uintptr_t HFAResolveSecretDecrypt(IMP getter, Dl_info *getterInfoOut,'
if old in s:
    s = s.replace(old, new, 1)
p.write_text(s)
print('v0.2 fix1: declarations inserted; legacy decrypt helper retained as unused')
