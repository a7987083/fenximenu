from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKE = (ROOT / "hfamap/Makefile").read_text()
SRC = (ROOT / "hfamap/src/HFAMapMenuImplementationInventory.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapMenuImplementationInventory.h").read_text()
VER = (ROOT / "hfamap/src/HFAMapVersion2520.mm").read_text()
GEN = ROOT / "hfamap/tools/generate_v2520_integration.py"


class MenuImplementationInventory2520Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(GEN)], check=True)
        cls.scanner = (ROOT / "hfamap/src/HFAMapBundleRootScanner2520.mm").read_text()
        cls.catalog = (ROOT / "hfamap/src/HFAMapStaticCatalog2520.mm").read_text()

    def test_build_wires_v2520_modules(self):
        self.assertIn('src/HFAMapVersion2520.mm', MAKE)
        self.assertTrue('src/HFAMapMenuImplementationInventory.mm' in MAKE or
                        'src/HFAMapMenuImplementationInventory25201.mm' in MAKE)
        self.assertTrue('src/HFAMapBundleRootScanner2520.mm' in MAKE or
                        'src/HFAMapBundleRootScanner2521.mm' in MAKE)
        self.assertIn('src/HFAMapStaticCatalog2520.mm', MAKE)
        self.assertIn('generate_v2520_integration.py', MAKE)

    def test_runtime_method_path_reuses_existing_analyzers(self):
        self.assertIn('HFAMapAnalyzeStrippedActionIMP', SRC)
        self.assertIn('methodPointerToken', SRC)
        self.assertIn('menu-action-il2cpp-correlation', SRC)
        self.assertIn('exact-method-pointer', SRC)
        self.assertIn('containing-method-range', SRC)
        self.assertIn('runtimeMethods', SRC)

    def test_patch_path_reuses_byte_validated_deep_analyze_records(self):
        for token in ('canonicalEligible', 'byte-validated', 'targetImage', 'offset', 'original', 'patch'):
            self.assertIn(token, SRC)
        self.assertIn('deep-analyze-menu-canonical-feature', SRC)
        self.assertIn('memoryPatches', SRC)

    def test_state_mutation_is_candidate_not_claimed_write(self):
        self.assertIn('state-mutation-candidate', SRC)
        self.assertIn('stateMutationCandidateIsNotProofOfWrite', SRC)
        self.assertNotIn('DobbyHook', SRC)
        self.assertNotIn('MSHookFunction', SRC)

    def test_loaded_dylib_scan_persists_inventory(self):
        self.assertIn('HFAMapBuildMenuImplementationInventory', self.scanner)
        self.assertIn('HFAMapPersistMenuImplementationInventory', self.scanner)
        self.assertIn('menuImplementationRuntimeMethodCount', self.scanner)
        self.assertIn('menuImplementationStateMutationCandidateCount', self.scanner)

    def test_static_catalog_is_app_named(self):
        self.assertIn('HFAHostAppName()', self.catalog)
        self.assertIn('%@_HFAMap', self.catalog)
        self.assertIn('%@_HFAMap_StaticCatalog_%@.json', self.catalog)
        self.assertNotIn('stringByAppendingPathComponent:@"HFAMap"] stringByAppendingPathComponent:@"Catalogs"', self.catalog)

    def test_output_schema_and_version(self):
        self.assertIn('com.hfa.menu-implementation-inventory/v1', SRC)
        self.assertIn('MenuImplementationInventory.json', SRC)
        self.assertIn('2.5.20-dev-menu-implementation-inventory', VER + SRC)
        self.assertIn('READ-ONLY-UNIFIED-PATCH-RUNTIME-METHOD-STATE-MUTATION-EVIDENCE', VER)
        self.assertIn('HFAMapBuildMenuImplementationInventory', HDR)

    def test_no_sample_specific_inputs(self):
        corpus = SRC + self.scanner + self.catalog
        for forbidden in ('RogueLegend', 'Path of Kings', 'Dragon Fever', 'Rise of Berk',
                          '0xB96A54', '0xB96B2C', '0x3593500', '0x31AFD14'):
            self.assertNotIn(forbidden, corpus)


if __name__ == '__main__':
    unittest.main()
