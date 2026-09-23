from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
IL2CPP = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbeSafe.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
DIAG = (ROOT / "hfamap/src/HFAMapDiagnostics.mm").read_text()


class FeatureDirectedRuntimeMethodTests(unittest.TestCase):
    def test_feature_directed_path_does_not_require_hook(self):
        self.assertIn('gHFASafeSessionActive', IL2CPP)
        self.assertIn('featureDirectedAnalysisRequiresHook', IL2CPP)
        self.assertIn('@NO', IL2CPP)
        self.assertIn('if (!active) return;', IL2CPP)

    def test_exact_control_target_action_is_analyzed(self):
        for token in (
            'HFASafeFeatureDirectedAnalyses',
            'control.allTargets',
            'UIControlEventTouchUpInside',
            'UIControlEventValueChanged',
            'class_getInstanceMethod',
            'method_getImplementation',
            'HFAMapAnalyzeStrippedActionIMP',
            'HFAMapAnalyzeFeatureCallbackContext',
            'contextSeededAnalysis',
            'exact-user-activated-control-target-action',
            'feature-directed-method-correlation-observed',
        ):
            self.assertIn(token, IL2CPP)

    def test_read_only_boundary_is_preserved(self):
        self.assertIn('@"selectorInvokedByProbe": @NO', IL2CPP)
        self.assertIn('@"impReplaced": @NO', IL2CPP)
        self.assertIn('@"memoryWritten": @NO', IL2CPP)
        self.assertIn('feature-directed-read-only-correlation-no-inline-backend-no-il2cpp-export-hook', IL2CPP)
        for forbidden in ('DobbyHook', 'DobbyDestroy', 'DobbyInstrument', 'il2cpp_runtime_invoke', 'vm_write'):
            self.assertNotIn(forbidden, IL2CPP)

    def test_version_markers(self):
        self.assertIn('2.5.7-dev-crash-safe-runtime-probe', DIAG)
        self.assertIn('featureDirectedCorrelationCount', ENTRY)


if __name__ == '__main__':
    unittest.main()
