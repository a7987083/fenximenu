from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAMapFeatureHandlerResolver.mm").read_text()
HEADER = (ROOT / "hfamap/src/HFAMapFeatureHandlerResolver.h").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class FeatureHandlerResolverSourceTests(unittest.TestCase):
    def test_known_feature_relationship_seeds_analysis(self):
        for token in (
            'HFAMapAnalyzeFeatureHandlerSnapshot',
            'actionSeeds',
            'controlToken',
            'target',
            'exact-action-seed-object-graph',
            'known-feature-object-graph-to-block-invoke-only',
        ):
            self.assertIn(token, SOURCE + HEADER)

    def test_runtime_method_descriptor_is_structural_not_sample_specific(self):
        for token in (
            'com.hfa.runtime-method-descriptor/v1',
            'assembly-like',
            'qualified-type-like',
            'identifier-like',
            'indirectCallCount',
            'runtime-method-descriptor-candidate',
            'HFAIL2CPPMethodContainingRuntimeAddress',
        ):
            self.assertIn(token, SOURCE)
        for forbidden in ('CheatGetMoney', 'CheatLevelUp', 'XPHero', '0xB8B608', '0xB8BA50'):
            self.assertNotIn(forbidden, SOURCE)

    def test_object_graph_is_bounded_and_read_only(self):
        for token in (
            'kHFAHandlerMaxNodes = 48',
            'kHFAHandlerMaxDepth = 2',
            'kHFAHandlerMaxBlocks = 24',
            'kHFAHandlerMaxInstructions = 256',
            'blockInvokedByAnalyzer',
            'selectorInvokedByAnalyzer',
            'memoryWritten',
        ):
            self.assertIn(token, SOURCE)
        self.assertNotIn('objc_msgSend(', SOURCE)
        self.assertNotIn('DobbyHook', SOURCE)
        self.assertNotIn('vm_write', SOURCE)

    def test_deep_analysis_exports_handler_graph(self):
        self.assertIn('featureHandlerGraph', CORE)
        self.assertIn('feature-handler-graph', CORE)
        self.assertIn('src/HFAMapFeatureHandlerResolver.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
