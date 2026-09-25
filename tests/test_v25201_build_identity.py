from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HFAMAP = ROOT / "hfamap"
GEN = HFAMAP / "tools/generate_v25201_build_identity.py"
MAKE = (HFAMAP / "Makefile").read_text()
BUILD = (HFAMAP / "src/HFAMapBuildInfo.mm").read_text()

class BuildIdentity25201Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["python3", str(GEN)])
        cls.entry = (HFAMAP / "src/HFAMapEntry25201.mm").read_text()
        cls.diag = (HFAMAP / "src/HFAMapDiagnostics25201.mm").read_text()

    def test_single_build_identity(self):
        self.assertIn('HFAMapBuildVersion(void)', BUILD)
        self.assertIn('HFAMapBuildComponent(void)', BUILD)
        self.assertIn('HFAMapBuildPolicy(void)', BUILD)
        self.assertIn('HFAMapDisplayVersion()', self.entry)
        self.assertIn('HFAMapBuildVersion()', self.entry)
        self.assertNotIn('HFAMap v2.5.7-dev', self.entry)
        self.assertNotIn('[HFAMap] v2.5.7', self.entry)

    def test_diagnostics_use_current_build_identity(self):
        for token in ('HFAMapBuildVersion()', 'HFAMapBuildComponent()', 'HFAMapBuildPolicy()'):
            self.assertIn(token, self.diag)
        self.assertNotIn('2.5.8-dev-universal-imported-dylib-evidence', self.diag)
        self.assertNotIn('UNIVERSAL-ONLY', self.diag)

    def test_makefile_uses_generated_successors(self):
        self.assertIn('V25201_BUILD_IDENTITY_GENERATED', MAKE)
        self.assertIn('src/HFAMapEntry25201.mm', MAKE)
        self.assertIn('src/HFAMapDiagnostics25201.mm', MAKE)
        self.assertIn('src/HFAMapBuildInfo.mm', MAKE)
        files = MAKE.split('HFAMapUniversal_FILES = ', 1)[1].split('\n', 1)[0]
        self.assertNotIn(' src/HFAMapEntry.mm ', f' {files} ')
        self.assertNotIn(' src/HFAMapDiagnostics.mm ', f' {files} ')

    def test_component_versions_remain_historical_evidence(self):
        self.assertIn('componentVersion', BUILD)

if __name__ == '__main__':
    unittest.main()
