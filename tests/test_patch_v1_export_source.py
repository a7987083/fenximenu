from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
EXPORTER = (ROOT / "hfamap/src/HFAMapPatchV1.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class PatchV1ExportSourceTests(unittest.TestCase):
    def test_exporter_is_compiled_and_written_separately(self):
        self.assertIn("src/HFAMapPatchV1.mm", MAKEFILE)
        self.assertIn('HFAOutputFileName(@"Canonical.hfapatch.json")', CORE)
        self.assertIn("HFAMapBuildPatchV1PackageWithReport(features", CORE)

    def test_exact_v1_schema_fields_are_present(self):
        for token in (
            '@"com.hfa.patch/v1"', '@"package"', '@"shortVersion"',
            '@"buildVersion"', '@"architectures"', '@"bundleIdentifier"',
            '@"targets"', '@"features"', '@"defaultEnabled"', '@"patches"',
            '@"original"', '@"enabled"', '@"offset"', '@"target"',
        ):
            self.assertIn(token, EXPORTER)

    def test_only_byte_validated_canonical_features_are_exported(self):
        self.assertIn('feature[@"canonicalEligible"]', EXPORTER)
        self.assertIn('@"byte-validated"', EXPORTER)
        self.assertIn("HFAValidOffset", EXPORTER)
        self.assertIn("original.length != enabled.length", EXPORTER)

    def test_cross_feature_shared_offsets_are_preserved_and_reported(self):
        self.assertNotIn('@"conflicting-patches-for-target-offset"', EXPORTER)
        self.assertNotIn("slotSignatures", EXPORTER)
        self.assertIn('@"sharedPatchSites"', EXPORTER)
        self.assertIn('@"same-offset"', EXPORTER)
        self.assertIn('@"overlapping-range"', EXPORTER)
        self.assertIn('HFAOriginalsAgreeInOverlap', EXPORTER)

    def test_exact_duplicates_are_scoped_to_one_feature(self):
        self.assertIn("groupSignatures", EXPORTER)
        self.assertIn('record[@"target"], record[@"offset"], record[@"enabled"]', EXPORTER)
        self.assertIn('@"deduplicatedCount"', EXPORTER)

    def test_inconsistent_original_overlap_rejects_only_affected_records(self):
        self.assertIn('@"inconsistent-original-overlap"', EXPORTER)
        self.assertIn("NSMutableIndexSet *rejected", EXPORTER)
        self.assertIn('@"status": rejected.count ? @"partial" : @"complete"', EXPORTER)

    def test_report_and_stale_canonical_cleanup_are_wired(self):
        self.assertIn('Canonical.shared-sites.json', CORE)
        self.assertIn('HFAMapBuildPatchV1PackageWithReport', CORE)
        self.assertIn('HFARemoveOutput(canonicalName)', CORE)
        self.assertIn('NSDataWritingAtomic', CORE)

    def test_package_identity_and_architecture_are_runtime_derived(self):
        self.assertIn("NSBundle.mainBundle.bundleIdentifier", EXPORTER)
        self.assertIn('info[@"CFBundleShortVersionString"]', EXPORTER)
        self.assertIn("_dyld_get_image_header(0)", EXPORTER)
        self.assertIn("CPU_SUBTYPE_ARM64E", EXPORTER)


if __name__ == "__main__":
    unittest.main()
