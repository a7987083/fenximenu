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
