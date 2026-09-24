from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapLoadedMenuFeatureEnumerator.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapLoadedMenuFeatureEnumerator.h").read_text()
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()

class LoadedMenuFeatureEnumeratorSourceTests(unittest.TestCase):
    def test_module_and_output_are_wired(self):
        self.assertIn("HFAMapLoadedMenuFeatureEnumerator.mm", MAKEFILE)
        self.assertIn("HFAMapEnumerateLoadedMenuFeatures", HDR)
        self.assertIn("HFAMapEnumerateLoadedMenuFeatures", BUNDLE)
        self.assertIn("LoadedMenuFeatureInventory.json", SRC)
        self.assertIn("com.hfa.loaded-menu-feature-inventory/v1", SRC)

    def test_view_tree_does_not_require_target_action(self):
        self.assertIn("UIApplication.sharedApplication.windows", SRC)
        self.assertIn("menuOwnedControl", SRC)
        self.assertIn("statefulFeatureCandidate", SRC)
        self.assertIn("HFAEnumLabelForControl", SRC)
        self.assertIn("featureCandidates", SRC)

    def test_reference_inspired_multipath_is_present(self):
        for token in ("targetActionInventory", "objcSuperclassMethodFingerprint",
                      "blockInvokeInventory", "managerPatchObjectShapeInventory",
                      "HFAEnumMethodFingerprint", "HFAEnumBlockEvidence",
                      "managerCandidates", "patchObjectCandidates"):
            self.assertIn(token, SRC)

    def test_block_path_is_read_only(self):
        self.assertIn("vm_read_overwrite", SRC)
        self.assertIn('@"blockInvoked": @NO', SRC)
        self.assertIn('@"patchMethodInvoked": @NO', SRC)
        self.assertIn('@"memoryWritten": @NO', SRC)
        for forbidden in ("DobbyHook", "MSHookFunction", "vm_write", "mach_vm_write"):
            self.assertNotIn(forbidden, SRC)

    def test_object_graph_is_bounded(self):
        for token in ("kHFAEnumMaxViews", "kHFAEnumMaxControls", "kHFAEnumMaxObjectFields",
                      "kHFAEnumMaxGraphNodes", "kHFAEnumMaxGraphDepth", "kHFAEnumMaxContainerItems"):
            self.assertIn(token, SRC)

    def test_no_sample_specific_feature_names_or_offsets(self):
        for forbidden in ("RogueLegend", "Damage Multiplier", "Defence Multiplier", "God Mode",
                          "Skip Battles", "VIP Enabled", "0x31AFD14", "0x3593500"):
            self.assertNotIn(forbidden, SRC)

    def test_v2513_marker_is_compiled(self):
        self.assertIn("HFAMapVersion2513.mm", MAKEFILE)
        self.assertIn("HFAMap v2.5.13", BUNDLE)

if __name__ == "__main__":
    unittest.main()
