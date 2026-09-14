from pathlib import Path
import shutil
import subprocess

ROOT = Path('.')
TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')
GENERIC = Path('hfamap/src/HFAMapGenericMenuResolver.m')
PROFILER = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
SELECTOR = Path('hfamap/src/HFAMapJailpatchSelectorResolver.m')


def run(script):
    subprocess.run(['python3', script], check=True)


def replace_once(path, old, new, label):
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{label}: expected 1 match, got {count}')
    path.write_text(text.replace(old, new, 1))


for script in [
    '.github/scripts/hfamap_v189_patch.py',
    '.github/scripts/hfamap_v192_patch.py',
    '.github/scripts/hfamap_v193_patch.py',
    '.github/scripts/hfamap_v194_patch.py',
    '.github/scripts/hfamap_v195_patch.py',
    '.github/scripts/hfamap_v196_patch.py',
]:
    run(script)

replace_once(
    TRACE,
    '''        snprintf(definition->type, sizeof(definition->type), "%s", type);\n        HFAResolveDynamicRegistrationCandidates(identifier, type);\n        return;\n''',
    '''        snprintf(definition->type, sizeof(definition->type), "%s", type);\n        return;\n''',
    'normalize v1.9.6 feature type',
)
replace_once(
    TRACE,
    '''__attribute__((constructor)) static void HFAInit(void) {\n    HFALog("[HFALearn v1.9.6 CustomSwitchBuiltinDispatchProbe] loaded\\n");\n    HFAInstallDynamicRegistrationHooks();\n}\n''',
    '''__attribute__((constructor)) static void HFAInit(void) {\n    HFALog("[HFALearn v1.9.6 CustomSwitchBuiltinDispatchProbe] loaded\\n");\n}\n''',
    'normalize v1.9.6 constructor',
)
run('.github/scripts/hfamap_v197_patch.py')
replace_once(
    TRACE,
    '''        snprintf(definition->type, sizeof(definition->type), "%s", type);\n        if (strcmp(type, "customSwitch") == 0)\n            HFAAssociateNativeHookWithCustomSwitch(identifier);\n        return;\n''',
    '''        snprintf(definition->type, sizeof(definition->type), "%s", type);\n        HFAResolveDynamicRegistrationCandidates(identifier, type);\n        if (strcmp(type, "customSwitch") == 0)\n            HFAAssociateNativeHookWithCustomSwitch(identifier);\n        return;\n''',
    'restore v1.9.7 feature type',
)
replace_once(
    TRACE,
    '''__attribute__((constructor)) static void HFAInit(void) {\n    HFALog("[HFALearn v1.9.7 CustomSwitchNativeHookProbe] loaded\\n");\n    _dyld_register_func_for_add_image(HFANativeImageAdded);\n}\n''',
    '''__attribute__((constructor)) static void HFAInit(void) {\n    HFALog("[HFALearn v1.9.7 CustomSwitchNativeHookProbe] loaded\\n");\n    _dyld_register_func_for_add_image(HFANativeImageAdded);\n    HFAInstallDynamicRegistrationHooks();\n}\n''',
    'restore v1.9.7 constructor',
)
run('.github/scripts/hfamap_v198_patch.py')
replace_once(
    TRACE,
    '''static int64_t HFAStaticSignExtend(uint64_t value, unsigned bits) {\n''',
    '''static int HFAReadable(uintptr_t address, size_t length);\nstatic uintptr_t HFAStripCodePointer(uintptr_t value);\nstatic uintptr_t HFAResolveTrampoline(uintptr_t original);\n\nstatic int64_t HFAStaticSignExtend(uint64_t value, unsigned bits) {\n''',
    'insert v1.9.8 forward prototypes',
)

for script in [
    '.github/scripts/hfamap_v199_patch.py',
    '.github/scripts/hfamap_v1910_patch.py',
    '.github/scripts/hfamap_v1911_patch.py',
    '.github/scripts/hfamap_v1912_patch.py',
    '.github/scripts/hfamap_v1913_patch.py',
    '.github/scripts/hfamap_v1914_patch.py',
    '.github/scripts/hfamap_v1924_dual_iosgods_probe.py',
    '.github/scripts/hfamap_v1925_dual_json_export.py',
    '.github/scripts/hfamap_v1926_igmm_implementation.py',
    '.github/scripts/hfamap_v1927_target_chain.py',
    '.github/scripts/hfamap_v1928_generic_menu.py',
    '.github/scripts/hfamap_v1929_jailpatch_runtime.py',
    '.github/scripts/hfamap_v1930_jailpatch_selector.py',
    '.github/scripts/hfamap_v1931_generic_secret_decrypt.py',
    '.github/scripts/hfamap_v1932_crash_safe_full_scan.py',
]:
    run(script)

for src, dst in [
    (TRACE, Path('/tmp/HFAMapPatchExecutionTrace.before1933.m')),
    (LEGACY, Path('/tmp/HFAMapLegacy.before1933.m')),
    (GENERIC, Path('/tmp/HFAMapGenericMenuResolver.before1933.m')),
    (PROFILER, Path('/tmp/HFAMapJailpatchRuntimeProfiler.before1933.m')),
    (SELECTOR, Path('/tmp/HFAMapJailpatchSelectorResolver.before1933.m')),
]:
    shutil.copyfile(src, dst)

run('.github/scripts/hfamap_v1933_original_bytes.py')
