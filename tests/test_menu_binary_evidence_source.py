from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
IMAGE_PROBE = (ROOT / "hfamap/src/HFAMapImageProbe.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
IL2CPP = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()


class MenuBinaryEvidenceSourceTests(unittest.TestCase):
    def test_memorypatch_family_fingerprints_are_present(self):
        for token in (
            "MemoryPatch", "createWithHex", "createWithBytes", "createWithAsm",
            "CodePatch", "ActiveCodePatch offset:", "machoPath",
        ):
            self.assertIn(token, IMAGE_PROBE)
        self.assertIn('family = @"memorypatch-menu"', IMAGE_PROBE)
        self.assertIn('@"patchPrimitiveScore"', IMAGE_PROBE)

    def test_evidence_is_analysis_only(self):
        self.assertIn('com.hfa.menu-binary-evidence/v1', IMAGE_PROBE)
        self.assertIn('@"patchPrimitiveEvidenceOnly": @YES', IMAGE_PROBE)
        self.assertIn('@"canonicalEligible": @NO', IMAGE_PROBE)

    def test_v238_runtime_probe_is_preserved(self):
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyHook")', IL2CPP)
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyDestroy")', IL2CPP)
        self.assertNotIn('DobbyInstrument', IL2CPP)
        self.assertNotIn('direct-method-entry', IL2CPP)

    def test_ui_is_v240(self):
        self.assertIn('HFAMap v2.4.0-dev Menu Binary Evidence', ENTRY)


if __name__ == "__main__":
    unittest.main()
