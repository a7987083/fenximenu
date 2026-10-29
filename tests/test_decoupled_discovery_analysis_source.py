from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAST = (ROOT / "hfamap/src/HFAMapFastDiscovery.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
CYBER = (ROOT / "hfamap/src/HFAMapCyberUI.m").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class DecoupledDiscoveryAnalysisTests(unittest.TestCase):
    def test_fast_discovery_resolves_preferred_target_from_loaded_images(self):
        self.assertIn('preferred-image-path-lightweight-only', FAST)
        self.assertIn('Frameworks/UnityFramework.framework', FAST)
        self.assertIn('NSBundle.mainBundle.executablePath', FAST)
        self.assertIn('unity-framework-absent-main-executable-fallback', FAST)
        self.assertIn('target-not-loaded', FAST)
        self.assertIn('targetSelectedByPath', FAST)
        self.assertIn('_dyld_image_count()', FAST)
        self.assertIn('processedFullImageList', FAST)
        self.assertIn('deepAnalysisPerformed', FAST)
        self.assertNotIn('HFAFastAppOwnedPath(path)', FAST)
        self.assertNotIn('HFAFastExcludedImage(path)', FAST)
        for forbidden in ('HFAMapAnalyzeMenuBinary', 'HFAMapInventoryStrippedObjCActions',
                          'HFAIL2CPPBuildMethodIndex', 'HFAMapAnalyzeStrippedActionIMP'):
            self.assertNotIn(forbidden, FAST)

    def test_path_selected_target_bypasses_weak_score_rejection_without_becoming_patch_eligible(self):
        selector = CORE[CORE.index('static NSDictionary *HFASelectCandidate'):
                        CORE.index('void HFAMapArmLastSelectedRuntimeProbe')]
        self.assertLess(selector.index('targetSelectedByPath'), selector.index('unsignedIntValue] < 50'))
        self.assertIn('@"canonicalEligible": @NO', FAST)
        self.assertIn('targetSelectionPolicy', FAST)

    def test_core_exposes_three_independent_phases(self):
        self.assertIn('HFAMapRunMenuDiscovery', CORE)
        self.assertIn('HFAMapRunSelectedDeepAnalysis', CORE)
        self.assertIn('HFAMapArmLastSelectedRuntimeProbe', CORE)
        self.assertIn('globalRediscoveryPerformed', CORE)
        self.assertIn('@NO', CORE)
        self.assertIn('run-discovery-first', CORE)

    def test_ui_exposes_two_button_flow_while_backend_keeps_three_phases(self):
        self.assertIn('扫描菜单模块', CYBER)
        self.assertIn('解析并导出', CYBER)
        self.assertIn('HFAMapRunMenuDiscovery', CYBER)
        self.assertIn('HFAMapRunSelectedDeepAnalysis', CYBER)
        self.assertIn('HFAMapArmLastSelectedRuntimeProbe', CYBER)
        self.assertNotIn('1. Search Menu', ENTRY)
        self.assertNotIn('4. Static Analyze Dylib', ENTRY)

    def test_fast_module_is_compiled(self):
        self.assertIn('src/HFAMapFastDiscovery.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
