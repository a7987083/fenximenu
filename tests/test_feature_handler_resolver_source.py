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
            'exact-action-seed-feature-ownership-graph',
            'exact-ui-action-to-sender-relative-descriptor-handler-object-graph',
        ):
            self.assertIn(token, SOURCE + HEADER)

    def test_runtime_method_descriptor_is_structural_not_sample_specific(self):
        for token in (
            'com.hfa.runtime-method-descriptor/v2',
            'assembly-like',
            'qualified-type-like',
            'identifier-like',
            'indirectCallCount',
            'runtime-method-descriptor-candidate',
            'HFAIL2CPPMethodContainingRuntimeAddress',
            'feature-owned-descriptor-to-block-invoke-structural-evidence',
        ):
            self.assertIn(token, SOURCE)
        for forbidden in ('CheatGetMoney', 'CheatLevelUp', 'XPHero', '0xB8B608', '0xB8BA50'):
            self.assertNotIn(forbidden, SOURCE)

    def test_object_graph_is_bounded_and_read_only(self):
        for token in (
            'kHFAHandlerMaxNodes = 96',
            'kHFAHandlerMaxDepth = 4',
            'kHFAHandlerMaxBlocks = 32',
            'kHFAHandlerMaxDescriptors = 48',
            'kHFAHandlerMaxInstructions = 320',
            'blocksInvoked',
            'selectorsInvoked',
            'memoryWritten',
        ):
            self.assertIn(token, SOURCE)
        self.assertNotIn('objc_msgSend(', SOURCE)
        self.assertNotIn('DobbyHook', SOURCE)
        self.assertNotIn('vm_write', SOURCE)

    def test_descriptor_ownership_is_generic_and_feature_scoped(self):
        for token in (
            'com.hfa.feature-ownership/v1',
            'descriptorCandidates',
            'exactLabelDescriptorCount',
            'descriptorOwnedBlockCount',
            'featureOwnedRuntimeMethodCandidateCount',
            'sender.superview',
            '.allTargets',
            'kbuttontaphandler',
            'verify-style-known-feature-ownership-descriptor-to-callback-no-global-method-guessing',
            'no-sample-name-no-sample-rva-no-known-method-input',
        ):
            self.assertIn(token, SOURCE)

    def test_deep_analysis_exports_handler_graph(self):
        self.assertIn('com.hfa.feature-handler-graph/v2', SOURCE)
        self.assertIn('featureHandlerGraph', CORE)
        self.assertIn('feature-handler-graph', CORE)
        self.assertIn('src/HFAMapFeatureHandlerResolver.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
