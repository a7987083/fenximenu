import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "tools/build_artifact_name.py"
spec = importlib.util.spec_from_file_location("artifact_name", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BuildArtifactNameTests(unittest.TestCase):
    def test_prefers_display_name(self):
        self.assertEqual("My_Game", module.app_name({
            "CFBundleDisplayName": "My Game", "CFBundleExecutable": "game_bin"}))

    def test_falls_back_to_executable(self):
        self.assertEqual("game_bin", module.app_name({
            "CFBundleDisplayName": "  ", "CFBundleExecutable": "game_bin"}))

    def test_missing_both_fails(self):
        with self.assertRaises(ValueError): module.app_name({})


if __name__ == "__main__": unittest.main()
