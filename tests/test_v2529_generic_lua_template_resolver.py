from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapGenericRuntimeTemplateResolver.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
BUILD = (ROOT / "hfamap/src/HFAMapBuildInfo.mm").read_text()

def test_generic_template_resolver_is_linked():
    assert "HFAMapGenericRuntimeTemplateResolver.mm" in MAKE
    assert '#import "HFAMapGenericRuntimeTemplateResolver.h"' in CORE
    assert "HFAMapResolveGenericRuntimeTemplates" in CORE

def test_read_only_contract():
    assert "vm_read_overwrite" in SRC
    assert '@"memoryWritten": @NO' in SRC
    assert '@"unknownCodeInvoked": @NO' in SRC
    for forbidden in ("mach_vm_write(", "vm_write(", "DobbyHook(", "MSHookFunction(", "method_setImplementation"):
        assert forbidden not in SRC

def test_generic_wrapper_core_discovery():
    for token in (
        "HFAFindWrappers",
        "HFADecodeBL",
        "HFADecodeADRP",
        "HFADecodeADD",
        "HFADecodeMOVW2Imm",
        "coreCounts",
    ):
        assert token in SRC

def test_plaintext_output_and_lua_scoring():
    assert "RuntimeTemplates.json" in SRC
    assert "plaintext-recovered" in SRC
    assert "HFALuaScore" in SRC
    assert "plaintextResolvedCount" in SRC
    assert "runtimeTemplateEvidence" in CORE

def test_no_sample_specific_hardcodes():
    for forbidden in (
        "Aniimo",
        "libaniimo",
        "0x4000",
        "0xEA60",
        "0xEABC",
        "0xEB18",
        "god",
        "hits",
        "nocd",
    ):
        assert forbidden not in SRC

def test_version_advanced():
    assert 'return @"2.5.29-dev";' in BUILD
    assert '2.5.29-dev-generic-lua-template-resolver' in BUILD
