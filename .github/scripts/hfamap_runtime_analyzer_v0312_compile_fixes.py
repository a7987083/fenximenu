from pathlib import Path

P=Path('hfamap/src/HFAMapPatchExecutionTrace.m')
s=P.read_text()

replacements=[
    ('static void HFAWriteIGMMPackage(',
     'static __attribute__((unused)) void HFAWriteIGMMPackage('),
    ('static BOOL HFACanonical35TargetsResolved(',
     'static __attribute__((unused)) BOOL HFACanonical35TargetsResolved('),
    ('static void HFAPrepareNativeHooksForPackageExport(',
     'static __attribute__((unused)) void HFAPrepareNativeHooksForPackageExport('),
    ('static unsigned HFAAppendNativeHookPackageFeatures(',
     'static __attribute__((unused)) unsigned HFAAppendNativeHookPackageFeatures('),
    ('static unsigned HFAAppendVerifiedEarnToDieRogueProfile(',
     'static __attribute__((unused)) unsigned HFAAppendVerifiedEarnToDieRogueProfile('),
]

for old,new in replacements:
    if new in s:
        continue
    count=s.count(old)
    if count!=1:
        raise SystemExit(f'v0312 compile-fix expected exactly one {old!r}, got {count}')
    s=s.replace(old,new,1)

P.write_text(s)
for _,new in replacements:
    if new not in s: raise SystemExit('v0312 compile-fix missing '+new)
print('v0.3.12 superseded package helper compile markers applied')
