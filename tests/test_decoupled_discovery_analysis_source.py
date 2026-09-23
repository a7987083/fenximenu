from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAST = (ROOT / "hfamap/src/HFAMapFastDiscovery.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class DecoupledDiscoveryAnalysisTests(unittest.TestCase):
    def test_fast_discovery_scans_full_loaded_list_without_deep_analysis(self):
        self.assertIn('full-list-first-no-deep-analysis', FAST)
        self.assertIn('_dyld_image_count()', FAST)
        self.assertIn('processedFullImageList', FAST)
        self.assertIn('deepAnalysisPerformed', FAST)
        for forbidden in ('HFAMapAnalyzeMenuBinary', 'HFAMapInventoryStrippedObjCActions',
                          'HFAIL2CPPBuildMethodIndex', 'HFAMapAnalyzeStrippedActionIMP'):
            self.assertNotIn(forbidden, FAST)

    def test_core_exposes_three_independent_phases(self):
        self.assertIn('HFAMapRunMenuDiscovery', CORE)
        self.assertIn('HFAMapRunSelectedDeepAnalysis', CORE)
        self.assertIn('HFAMapArmLastSelectedRuntimeProbe', CORE)
        self.assertIn('globalRediscoveryPerformed', CORE)
        self.assertIn('@NO', CORE)
        self.assertIn('run-discovery-first', CORE)

    def test_ui_has_static_catalog_button_without_changing_three_runtime_phases(self):
        self.assertIn('1. Search Menu', ENTRY)
        self.assertIn('2. Deep Analyze Menu', ENTRY)
        self.assertIn('3. Runtime Probe (8s)', ENTRY)
        self.assertIn('4. Static Analyze Dylib', ENTRY)
        self.assertIn('HFAMap v2.5.7-dev', ENTRY)
        self.assertNotIn('HFAMap v2.5.3-dev Static Catalog', ENTRY)

    def test_fast_module_is_compiled(self):
        self.assertIn('src/HFAMapFastDiscovery.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
