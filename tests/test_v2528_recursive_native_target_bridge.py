from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "hfamap/src/HFAMapRecursiveNativeTargetResolver.mm").read_text()
BRIDGE = (ROOT / "hfamap/src/HFAMapNativeConsumerTargetBridge.mm").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
BUILD = (ROOT / "hfamap/src/HFAMapBuildInfo.mm").read_text()

def test_recursive_resolver_is_linked():
    assert "HFAMapRecursiveNativeTargetResolver.mm" in MAKE
    assert "HFAMapResolveRecursiveNativeTarget" in BRIDGE
    assert '#import "HFAMapRecursiveNativeTargetResolver.h"' in BRIDGE

def test_bounded_fail_closed_traversal():
    for token in (
        "kHFAMaxRecursiveDepth",
        "cycle-detected",
        "ambiguous-multiple-next-targets",
        "no-structural-next-target",
        "unique-next-target",
        "bounded-executable-only+unique-edge-only+cycle-detection+fail-closed",
    ):
        assert token in RESOLVER

def test_supported_arm64_trampoline_forms():
    for token in (
        "direct-B",
        "direct-BL-RET",
        "ADRP+ADD+BR",
        "ADRP+LDR+BR",
        "LDR-literal+BR",
    ):
        assert token in RESOLVER

def test_read_only_and_il2cpp_handoff():
    assert "mach_vm_read_overwrite" in RESOLVER
    assert "HFAIL2CPPMethodForRuntimeAddress" in RESOLVER
    assert "HFAIL2CPPMethodContainingRuntimeAddress" in RESOLVER
    for forbidden in ("mach_vm_write(", "vm_write(", "DobbyHook(", "MSHookFunction("):
        assert forbidden not in RESOLVER

def test_bridge_accepts_recursive_unity_target():
    assert "recursiveTargetEvidence" in BRIDGE
    assert "recursiveResolvedTarget" in BRIDGE
    assert "native-consumer-target-bridge/v2" in BRIDGE

def test_version_advanced():
    assert ('return @"2.5.28-dev";' in BUILD or 'return @"2.5.29-dev";' in BUILD)
    assert ('2.5.28-dev-recursive-native-target-bridge' in BUILD or '2.5.29-dev-generic-lua-template-resolver' in BUILD)
