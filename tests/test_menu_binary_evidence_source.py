from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
IMAGE_PROBE = (ROOT / "hfamap/src/HFAMapImageProbe.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
CYBER = (ROOT / "hfamap/src/HFAMapCyberUI.m").read_text()
IL2CPP = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()


class MenuBinaryEvidenceSourceTests(unittest.TestCase):
    def test_memorypatch_backend_fingerprints_are_present(self):
        for token in (
            "MemoryPatch", "createWithHex", "createWithBytes", "createWithAsm",
            "CodePatch", "ActiveCodePatch offset:", "machoPath",
            "get_OrigBytes", "get_PatchBytes", "get_CurrBytes",
            "findHexFirst", "findIdaPatternFirst", "asm_arch", "asm_code",
        ):
            self.assertIn(token, IMAGE_PROBE)
        self.assertIn('@"patchBackends"', IMAGE_PROBE)
        self.assertIn('@"menuFamily"', IMAGE_PROBE)
        self.assertIn('@"analysisCapabilities"', IMAGE_PROBE)
        self.assertNotIn('family = @"memorypatch-menu"', IMAGE_PROBE)

    def test_stripped_inventory_is_attached(self):
        self.assertIn('com.hfa.menu-binary-evidence/v3', IMAGE_PROBE)
        self.assertIn('HFAMapInventoryStrippedObjCActions', IMAGE_PROBE)
        self.assertIn('@"strippedObjCInventory"', IMAGE_PROBE)
        self.assertIn('@"canonicalEligible": @NO', IMAGE_PROBE)

    def test_v238_runtime_probe_source_remains_historical_only(self):
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyHook")', IL2CPP)
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyDestroy")', IL2CPP)
        self.assertNotIn('DobbyInstrument', IL2CPP)
        self.assertNotIn('direct-method-entry', IL2CPP)

    def test_two_button_ui_controls_are_present(self):
        self.assertIn('扫描菜单模块', CYBER)
        self.assertIn('解析并导出', CYBER)
        self.assertNotIn('1. Search Menu', ENTRY)
        self.assertNotIn('4. Static Analyze Dylib', ENTRY)


if __name__ == "__main__":
    unittest.main()
