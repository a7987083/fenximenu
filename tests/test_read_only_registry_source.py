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
        self.assertIn("HFAReadOnlyDescriptorEvidence(dictionary, candidateImage, execImages)", RESOLVER)
        self.assertIn("records.count >= 16", RESOLVER)
        self.assertIn("values.count >= 48", RESOLVER)
        self.assertIn("HFACandidateOwnedObject(object, candidateImage)", RESOLVER)
        self.assertIn("LC_UUID", IMAGE_PROBE)
        self.assertIn('@"menuUUID"', IMAGE_PROBE)

    def test_cross_image_wrapper_metadata_does_not_invoke_getter(self):
        self.assertIn("HFAImplementationLocation", RESOLVER)
        self.assertIn('@"wrapperClassImage"', RESOLVER)
        self.assertIn('@"implementationUUID"', RESOLVER)
        self.assertIn('@"rawIvarEvidence"', RESOLVER)
        self.assertIn('@"invoked"] = @NO', RESOLVER)
        self.assertNotIn("objc_msgSend", RESOLVER)

    def test_generic_secret_decode_uses_unique_current_image_fingerprint(self):
        self.assertIn("HFAUniqueDecryptCandidateForIMP", RESOLVER)
        self.assertIn("0xD105C3FFU", RESOLVER)
        self.assertIn("0xB9400408U", RESOLVER)
        self.assertIn("0x53187D00U", RESOLVER)
        self.assertIn('matches == 1 ? @"unique"', RESOLVER)
        self.assertNotIn("getter + 0xD00", RESOLVER)
        self.assertNotIn("getter+0xD00", RESOLVER)

    def test_decoded_patch_still_requires_live_original_bytes(self):
        self.assertIn("HFACanonicalPatchFromDecoded", RESOLVER)
        self.assertIn('[@"canonicalPatch"]', RESOLVER)
        self.assertIn('@"targetUUID"', RESOLVER)
        self.assertIn('@"live-original-bytes-captured-before-mutation"', RESOLVER)
        self.assertIn("[original isEqualToData:patch]", RESOLVER)

    def test_target_image_inventory_matches_discovery_ceiling(self):
        self.assertIn("kHFAMaxLoadedImages = 2048", RESOLVER)
        self.assertNotIn("MIN(_dyld_image_count(), 512U)", RESOLVER)

    def test_pointer_ivar_capture_is_bounded_and_read_only(self):
        self.assertIn("HFAPointerMemoryEvidence", RESOLVER)
        self.assertIn("vm_read_overwrite", RESOLVER)
        self.assertIn("uint8_t bytes[256]", RESOLVER)
        self.assertIn("lengthCandidate <= 4096U", RESOLVER)
        self.assertIn('@"written": @NO', RESOLVER)
        self.assertNotIn("vm_write", RESOLVER)

    def test_jailpatch_owner_is_located_without_invocation(self):
        self.assertIn('objc_getClass("C4M0Manager")', RESOLVER)
        self.assertIn('class_copyMethodList', RESOLVER)
        self.assertIn('object_getClass((id)owner)', RESOLVER)
        self.assertIn('"loadConfig:"', RESOLVER)
        self.assertIn('@"jailpatch-runtime-owner"', RESOLVER)
        self.assertIn('@"runtimeEvidence"', CORE)
        self.assertNotIn("method_invoke", RESOLVER)


if __name__ == "__main__":
    unittest.main()
