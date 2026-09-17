from pathlib import Path

MAKEFILE = Path("hfamap/Makefile")
TRACE = Path("hfamap/src/HFAMapPatchExecutionTrace.m")

makefile = MAKEFILE.read_text()
source = "src/HFACanonicalMutation.m"
if source not in makefile:
    anchor = "HFAMapUniversal_FILES = "
    if anchor not in makefile:
        raise SystemExit("HFAMapUniversal_FILES anchor missing")
    makefile = makefile.replace(anchor, anchor + source + " ", 1)
    MAKEFILE.write_text(makefile)

trace = TRACE.read_text()
import_line = '#import "HFACanonicalMutation.h"\n'
if import_line not in trace:
    anchor = "#import <Foundation/Foundation.h>\n"
    if anchor not in trace:
        raise SystemExit("Foundation import anchor missing")
    trace = trace.replace(anchor, anchor + import_line, 1)

call = (
    '    HFAIngestCanonicalPackage(exportFeatures, exportTargets, @"patch-trace");\n'
    '    HFAFlushCanonicalMutations();\n'
)
if "HFAIngestCanonicalPackage(exportFeatures" not in trace:
    anchor = "    HFAWritePatchPackage(exportFeatures, exportTargets);\n"
    if anchor not in trace:
        raise SystemExit("canonical package write anchor missing")
    trace = trace.replace(anchor, call + anchor, 1)

required = (
    'HFACanonicalMutation.h',
    'HFAIngestCanonicalPackage(exportFeatures, exportTargets, @"patch-trace")',
    'HFAFlushCanonicalMutations()',
)
for token in required:
    if token not in trace:
        raise SystemExit(f"mutation IR token missing: {token}")
TRACE.write_text(trace)

print("patched v1.9.38.0 stage1: canonical mutation IR bridge")
