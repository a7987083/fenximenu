from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'hfamap/src/HFAMapFeatureDispatcherSliceResolver.mm').read_text()
MAKE = (ROOT / 'hfamap/Makefile').read_text()
BUILD = (ROOT / 'hfamap/src/HFAMapBuildInfo.mm').read_text()

class FeatureDispatcherSlicing2522Tests(unittest.TestCase):
    def test_feature_seeded_provenance_is_reused_without_reexecution(self):
        for token in ('entrySeededProvenance', 'entryDerivedArgumentCount', 'feature-sender-x2',
                      'feature-entry-derived-branch', 'reexecutesHandlerCFG', 'knownGameOffsetsUsedAsInput'):
            self.assertIn(token, SRC)
        self.assertNotIn('HFAMapResolveHandlerBranchProvenance(', SRC)
        self.assertNotIn('HFAMapAnalyzeStrippedActionIMP(', SRC)

    def test_downstream_targets_are_feature_scoped(self):
        for token in ('targetFeatureUseCounts', 'featureUseCount', 'featureExclusive',
                      'sharedAcrossFeatures', 'sharedTargetDowngraded', 'featureExclusiveTargetUpgraded'):
            self.assertIn(token, SRC)

    def test_runtime_method_correlation_is_attached_when_available(self):
        for token in ('HFAIL2CPPMethodForRuntimeAddress', 'HFAIL2CPPMethodContainingRuntimeAddress',
                      'exact-method-pointer', 'containing-method-range', 'il2cppMethod'):
            self.assertIn(token, SRC)

    def test_output_and_build_identity(self):
        self.assertIn('FeatureDispatcherSlices.json', SRC)
        self.assertIn('com.hfa.feature-dispatcher-slices/v1', SRC)
        self.assertIn('src/HFAMapFeatureDispatcherSliceResolver.mm', MAKE)
        self.assertIn('src/HFAMapVersion2522.mm', MAKE)
        self.assertIn('2.5.22-dev', BUILD)

    def test_read_only_generic_boundary(self):
        corpus = SRC
        for forbidden in ('DobbyHook', 'MSHookFunction', 'mach_vm_write(', 'vm_write(',
                          '0xB96A54', '0xB96B2C', 'RogueLegend', 'Path of Kings', 'Random Dice'):
            self.assertNotIn(forbidden, corpus)

if __name__ == '__main__':
    unittest.main()
