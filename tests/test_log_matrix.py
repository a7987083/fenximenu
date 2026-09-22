import json
import tempfile
import unittest
from pathlib import Path

from tools.hfamap_log_matrix import build_matrix


class LogMatrixTests(unittest.TestCase):
    def test_buttons_and_rejection_reasons_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = {
                "status": "complete",
                "candidate": {
                    "image": "Menu.dylib",
                    "menuUUID": "TEST-UUID",
                    "family": "legacy-ap",
                    "hostBundleID": "com.example.game",
                    "hostVersion": "1.0",
                    "hostBuild": "1",
                },
                "registry": [{
                    "name": "God Mode",
                    "identifier": "god",
                    "type": "customSwitch",
                    "sourceClass": "NSDictionary",
                    "descriptorEvidence": [{"class": "PatchDescriptor"}],
                }],
                "features": [],
                "unresolved": [{"reason": "missing-offset"}],
            }
            (root / "Game_HFAMap_Analysis.json").write_text(
                json.dumps(payload), encoding="utf-8")
            matrix = build_matrix(root)
            self.assertEqual(1, matrix["gameCount"])
            self.assertEqual(1, matrix["buttonCount"])
            self.assertEqual(0, matrix["validatedPatchCount"])
            game = matrix["games"][0]
            self.assertEqual({"missing-offset": 1}, game["unresolvedReasons"])
            self.assertEqual(["PatchDescriptor"], game["buttons"][0]["descriptorClasses"])


if __name__ == "__main__":
    unittest.main()
