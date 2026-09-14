from pathlib import Path

# Kept as ordered text fragments so the generated Objective-C runtime block stays
# reviewable without turning this repository script into one oversized API write.
# The fragments concatenate to one normal Python patch script and are compiled
# before execution, so a missing/reordered fragment fails closed.
parts_dir = Path(__file__).with_name("runtime_v2_parts")
parts = sorted(parts_dir.glob("*.pyfrag"))
expected = [f"{i:02d}.pyfrag" for i in range(5)]
actual = [p.name for p in parts]
if actual != expected:
    raise SystemExit(f"runtime v2 fragments mismatch: expected={expected} actual={actual}")
source = "".join(p.read_text() for p in parts)
code = compile(source, str(Path(__file__).with_suffix(".assembled.py")), "exec")
exec(code, {"__name__": "__main__", "__file__": str(Path(__file__))})

# Clang 17 + Theos treats testing a declared function symbol as a boolean as
# -Werror=pointer-bool-conversion. Call the pinned Dobby API once instead, then
# null-check its returned version string. Keep this as an explicit generated-source
# correction until the fragment set is next consolidated.
generated = Path("hfapatch-consumer/src/HFAPatchConsumer.m")
text = generated.read_text()
old = '''    graph->bootstrapped = YES;\n    HFAPCLog(@"[RUNTIME-GRAPH] status=bootstrapped graph=%@ hooks=%u dobby=%s", graphName,\n             graph->installedCount, DobbyBuildVersion ? DobbyBuildVersion() : "?");\n'''
new = '''    graph->bootstrapped = YES;\n    const char *dobbyVersion = DobbyBuildVersion();\n    HFAPCLog(@"[RUNTIME-GRAPH] status=bootstrapped graph=%@ hooks=%u dobby=%s", graphName,\n             graph->installedCount, dobbyVersion ? dobbyVersion : "?");\n'''
if text.count(old) != 1:
    raise SystemExit(f"DobbyBuildVersion compile fix: expected 1 match, got {text.count(old)}")
generated.write_text(text.replace(old, new, 1))
print("applied Clang pointer-bool fix for DobbyBuildVersion")
