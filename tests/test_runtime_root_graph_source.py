from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapRuntimeRootGraphResolver.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapRuntimeRootGraphResolver.h").read_text()
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class RuntimeRootGraphSourceTests(unittest.TestCase):
    def test_read_only_rooted_policy(self):
        self.assertIn("UNIVERSAL-ROOTED-READ-ONLY-NO-SAMPLE-SPECIAL-CASES", SRC)
        for forbidden in ("RogueLegend", "CheatGetMoney", "God Mode", "0x31AFD14", "0x3593500", "DobbyHook", "DobbyInstrument", "MemoryPatch::Modify"):
            self.assertNotIn(forbidden, SRC)
        self.assertIn('@"unknownSelectorInvoked":@NO', SRC)
        self.assertIn('@"memoryWritten":@NO', SRC)
        self.assertIn('@"gameStateWritten":@NO', SRC)

    def test_ui_targets_are_runtime_roots(self):
        for token in ("UIApplication.sharedApplication.windows", "control.allTargets", "actionsForTarget:target", "method_getImplementation", "HFAControlLabel", "ui-control-target-action"):
            self.assertIn(token, SRC)

    def test_objc_fingerprint_and_backing_ivars(self):
        for token in ("class_getSuperclass", "class_copyMethodList", "class_copyIvarList", "class_copyPropertyList", "property_getAttributes", "HFAPropertyBackingIvarName", "object_getIvar"):
            self.assertIn(token, SRC)

    def test_foundation_containers_are_bounded(self):
        for token in ("NSArray.class", "NSDictionary.class", "NSSet.class", "kHFARootMaxContainerItems", "kHFARootMaxDepth", "kHFARootMaxNodes"):
            self.assertIn(token, SRC)

    def test_address_context_is_evidence_not_truth(self):
        for token in ("dladdr", "_dyld_image_count", "_dyld_register_func_for_add_image", "rva-candidate-unverified", "runtime-va-proven-to-loaded-image-rva", "addressSemantics"):
            self.assertIn(token, SRC)
        self.assertIn('@"verified":@NO', SRC)
        self.assertIn('@"canonicalEligible":@NO', SRC)

    def test_descriptor_candidates_require_runtime_values(self):
        self.assertIn("HFADescriptorClassification", SRC)
        self.assertIn("hasRuntimeValue", SRC)
        self.assertIn("patch-object-candidate", SRC)
        self.assertIn("descriptor-candidate", SRC)

    def test_bundle_wires_graph_and_v259(self):
        self.assertIn("HFAMapResolveRuntimeRootGraph", BUNDLE)
        self.assertIn("HFAMapPersistRuntimeRootGraph", BUNDLE)
        self.assertIn("RuntimeRootGraph.json", SRC)
        self.assertIn("HFAMap v2.5.9", BUNDLE)
        self.assertIn("HFAMapRuntimeRootGraphResolver.mm", MAKEFILE)
        self.assertIn("HFAMapVersion259.mm", MAKEFILE)


if __name__ == "__main__":
    unittest.main()
