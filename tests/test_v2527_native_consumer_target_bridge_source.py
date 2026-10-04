from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapNativeConsumerTargetBridge.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
BUILD = (ROOT / "hfamap/src/HFAMapBuildInfo.mm").read_text()

def test_bridge_is_linked():
    assert "HFAMapNativeConsumerTargetBridge.mm" in MAKE
    assert '#import "HFAMapNativeConsumerTargetBridge.h"' in CORE
    assert "HFAMapResolveNativeConsumerTargets" in CORE

def test_bridge_is_read_only():
    assert "mach_vm_read_overwrite" in SRC
    assert '@"memoryWritten":@NO' in SRC
    assert '@"consumerInvoked":@NO' in SRC

def test_bridge_correlates_unity_target_to_il2cpp():
    assert "HFAIL2CPPMethodForRuntimeAddress" in SRC
    assert "HFAIL2CPPMethodContainingRuntimeAddress" in SRC
    assert "unique-unity-live-pointee" in SRC
    assert "ambiguous-multiple-unity-live-pointees" in SRC

def test_version_advanced():
    assert ('return @"2.5.27-dev";' in BUILD or 'return @"2.5.28-dev";' in BUILD)
