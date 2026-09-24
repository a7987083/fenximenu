from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapFeatureOwnershipCorrelator.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
VERSION = (ROOT / "hfamap/src/HFAMapVersion2514.mm").read_text()

class FeatureOwnershipCorrelatorTests(unittest.TestCase):
    def test_module_is_compiled(self):
        self.assertIn("HFAMapFeatureOwnershipCorrelator.mm", MAKEFILE)
        self.assertIn("HFAMapVersion2514.mm", MAKEFILE)

    def test_exact_edge_policy(self):
        self.assertIn("EXACT-OBJECT-EDGE-ONLY-NO-NEARBY-BLOCK-PROPAGATION", SRC)
        self.assertIn("feature-control-ivar", SRC)
        self.assertIn("exact-action-target-ivar", SRC)
        self.assertIn("nearbySuperviewBlockRejected", SRC)
        self.assertIn("sharedGraphBlockWithoutEdgeRejected", SRC)

    def test_action_imp_is_analyzed_without_invocation(self):
        self.assertIn("HFAMapAnalyzeStrippedActionIMP", SRC)
        self.assertIn('actionInvoked\": @NO', SRC)
        self.assertIn('invokedByAnalyzer\": @NO', SRC)
        self.assertIn("editing-changed", SRC)

    def test_inventory_consumer_is_generic(self):
        self.assertIn("LoadedMenuFeatureInventory.json", SRC)
        for forbidden in ("Damage Multiplier", "Defence Multiplier", "God Mode", "0x3929C0", "0x31AFD14", "0x3593500"):
            self.assertNotIn(forbidden, SRC)

    def test_safety_boundary(self):
        for forbidden in ("DobbyHook", "MSHookFunction", "mach_vm_write", "vm_write", "objc_msgSend"):
            self.assertNotIn(forbidden, SRC)
        for token in ('blockInvoked\": @NO', 'memoryWritten\": @NO', 'gameStateWritten\": @NO'):
            self.assertIn(token, SRC)

    def test_version_marker(self):
        self.assertIn("2.5.14-dev-feature-ownership-correlator", VERSION)

if __name__ == "__main__":
    unittest.main()
