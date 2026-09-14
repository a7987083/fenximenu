from pathlib import Path
import shutil
import subprocess

TRACE = Path('hfamap/src/HFAMapPatchExecutionTrace.m')
LEGACY = Path('hfamap/src/HFAMapLegacy.m')
GENERIC = Path('hfamap/src/HFAMapGenericMenuResolver.m')
PROFILER = Path('hfamap/src/HFAMapJailpatchRuntimeProfiler.m')
SELECTOR = Path('hfamap/src/HFAMapJailpatchSelectorResolver.m')

subprocess.run(['python3', '.github/scripts/apply_hfamap_v1935_chain.py'], check=True)

for src, dst in [
    (TRACE, Path('/tmp/HFAMapPatchExecutionTrace.before1936.m')),
    (LEGACY, Path('/tmp/HFAMapLegacy.before1936.m')),
    (GENERIC, Path('/tmp/HFAMapGenericMenuResolver.before1936.m')),
    (PROFILER, Path('/tmp/HFAMapJailpatchRuntimeProfiler.before1936.m')),
    (SELECTOR, Path('/tmp/HFAMapJailpatchSelectorResolver.before1936.m')),
]:
    shutil.copyfile(src, dst)

subprocess.run(['python3', '.github/scripts/hfamap_v1936_architecture_truth.py'], check=True)
