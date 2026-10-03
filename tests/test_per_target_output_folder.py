from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
OUT_H = (ROOT / "hfamap/src/HFAMapOutputName.h").read_text()
OUT = (ROOT / "hfamap/src/HFAMapOutputName.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
DIAG = (ROOT / "hfamap/src/HFAMapDiagnostics.mm").read_text()

class PerTargetOutputFolderTests(unittest.TestCase):
    def test_output_folder_preserves_target_filename(self):
        self.assertIn("HFASetOutputTargetFileName", OUT_H)
        self.assertIn("fileName.lastPathComponent", OUT)
        self.assertIn("stringByAppendingPathComponent:target", OUT)
        self.assertIn("createDirectoryAtPath:directory", OUT)

    def test_all_main_outputs_use_target_directory(self):
        self.assertIn("HFAOutputDirectoryPath()", CORE)
        self.assertIn("HFAOutputDirectoryPath()", DIAG)
        self.assertIn('HFAOutputFileName(@"Process.jsonl")', CORE)
        self.assertIn('HFAOutputFileName(@"Diagnostics.log")', DIAG)
        self.assertIn('HFAOutputFileName(@"Diagnostics.jsonl")', DIAG)

    def test_candidate_selection_switches_output_folder(self):
        self.assertGreaterEqual(CORE.count("HFASetOutputTargetFileName("), 3)
        self.assertIn('@"outputDirectory": HFAOutputDirectoryPath()', CORE)

if __name__ == "__main__":
    unittest.main()
