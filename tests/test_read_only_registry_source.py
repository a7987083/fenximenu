from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()
IMAGE_PROBE = (ROOT / "hfamap/src/HFAMapImageProbe.mm").read_text()


class ReadOnlyRegistryTests(unittest.TestCase):
    def test_click_path_hook_is_absent_from_active_sources(self):
        self.assertNotIn("DescriptorObserver", MAKEFILE + CORE)
        self.assertNotIn("method_setImplementation", RESOLVER)
        self.assertNotIn("HFAMapArmDescriptorCapture", CORE)

    def test_registry_requires_name_and_identifier_and_preserves_children(self):
        self.assertIn("HFARegistryRecord", RESOLVER)
        self.assertIn('@"identifier"', RESOLVER)
        self.assertIn('@"label"', RESOLVER)
        self.assertIn('@"same-feature-dictionary"', RESOLVER)
        self.assertIn('@"FeatureRegistry.json"', CORE)

    def test_canonical_rejects_missing_image_or_unmatched_original_bytes(self):
        self.assertIn('@"target-image-missing"', RESOLVER)
        self.assertIn('@"original-bytes-missing-or-length-mismatch"', RESOLVER)
        self.assertIn('@"original-bytes-do-not-match-live-image"', RESOLVER)
        self.assertIn('isEqualToData:original', RESOLVER)

    def test_descriptor_ivar_offsets_cannot_be_mistaken_for_patch_addresses(self):
        self.assertIn('@"offsetSemantics": @"objc-instance-ivar-only"', RESOLVER)
        self.assertIn("HFAReadOnlyDescriptorEvidence(dictionary, candidateImage)", RESOLVER)
        self.assertIn("records.count >= 16", RESOLVER)
        self.assertIn("values.count >= 48", RESOLVER)
        self.assertIn("HFACandidateOwnedObject(object, candidateImage)", RESOLVER)
        self.assertIn("LC_UUID", IMAGE_PROBE)
        self.assertIn('@"menuUUID"', IMAGE_PROBE)


if __name__ == "__main__":
    unittest.main()
