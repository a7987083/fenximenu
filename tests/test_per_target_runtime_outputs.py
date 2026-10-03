from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
OUT_H = (ROOT / "hfamap/src/HFAMapOutputName.h").read_text()
OUT = (ROOT / "hfamap/src/HFAMapOutputName.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
PROBE = (ROOT / "hfamap/src/HFAMapRuntimeProbe.mm").read_text()
TRACE = (ROOT / "hfamap/src/HFAExactRuntimeMethodTrace.mm").read_text()
DIAG = (ROOT / "hfamap/src/HFAMapDiagnostics.mm").read_text()

class PerTargetRuntimeOutputTests(unittest.TestCase):
    def test_runtime_probe_uses_target_directory(self):
        self.assertIn('HFAOutputDirectoryPath()', PROBE)
        self.assertIn('RuntimeProbe.json', PROBE)
        self.assertNotIn('NSSearchPathForDirectoriesInDomains(NSDocumentDirectory', PROBE)

    def test_exact_trace_uses_target_directory(self):
        self.assertIn('HFAOutputDirectoryPath()', TRACE)
        self.assertIn('ExactRuntimeMethods.json', TRACE)
        self.assertNotIn('NSSearchPathForDirectoriesInDomains(NSDocumentDirectory', TRACE)

    def test_preselection_diagnostics_are_adopted(self):
        self.assertIn('HFAAdoptRootOutputsIntoCurrentDirectory', OUT_H)
        self.assertIn('Diagnostics.jsonl', OUT)
        self.assertIn('Diagnostics.log', OUT)
        self.assertIn('RuntimeProbe.json', OUT)
        self.assertIn('ExactRuntimeMethods.json', OUT)
        self.assertIn('HFASetOutputTargetFileName(nil)', CORE)
        self.assertGreaterEqual(CORE.count('HFAAdoptRootOutputsIntoCurrentDirectory()'), 2)

    def test_diagnostics_use_target_directory(self):
        self.assertIn('HFAOutputDirectoryPath()', DIAG)

if __name__ == "__main__":
    unittest.main()
