from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapGenericRuntimeTemplateResolver.mm").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
BUILD = (ROOT / "hfamap/src/HFAMapBuildInfo.mm").read_text()

def test_v2530_build_identity():
    assert "HFAMapVersion2530.mm" in MAKE
    assert 'return @"2.5.30-dev";' in BUILD
    assert '2.5.30-dev-decrypt-wrapper-semantic-resolver' in BUILD

def test_length_is_terminator_driven_not_mov_w2_driven():
    assert "HFADecodeSTRBWZRUnsigned" in SRC
    assert "post-call-strb-wzr" in SRC
    assert "terminatorRVA" in SRC
    assert "outputRegister" in SRC

def test_register_dataflow_tracks_callee_saved_paths():
    assert "HFAResolveRegisterState" in SRC
    assert "HFADecodeMOVRegister" in SRC
    assert "HFADecodeADR" in SRC
    assert "HFADecodeADRP" in SRC
    assert "HFADecodeADD" in SRC
    assert "HFADecodeLDRLiteralX" in SRC

def test_shared_core_suppresses_singleton_false_positives():
    assert "coreCounts" in SRC
    assert "coreCounts[w.core] >= 2" in SRC

def test_runtime_reader_remains_read_only():
    assert "vm_read_overwrite" in SRC
    assert '@"memoryWritten": @NO' in SRC
    assert '@"unknownCodeInvoked": @NO' in SRC
    for forbidden in ("mach_vm_write(", "vm_write(", "DobbyHook(", "MSHookFunction("):
        assert forbidden not in SRC

def test_schema_and_policy_advanced():
    assert "com.hfa.generic-runtime-template/v2" in SRC
    assert "shared-core+post-call-nul-terminator+callee-saved-dataflow+read-only-runtime-plaintext+fail-closed" in SRC
