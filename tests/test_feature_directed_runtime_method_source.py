from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
IL2CPP = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
DIAG = (ROOT / "hfamap/src/HFAMapDiagnostics.mm").read_text()


class FeatureDirectedRuntimeMethodTests(unittest.TestCase):
    def test_feature_directed_path_does_not_require_hook(self):
        self.assertIn('gHFAIL2CPPSessionActive', IL2CPP)
        self.assertIn('featureDirectedAnalysisRequiresHook', IL2CPP)
        self.assertIn('@NO', IL2CPP)
        self.assertIn('if (!gHFAIL2CPPSessionActive) return;', IL2CPP)
        self.assertNotIn('void HFAIL2CPPRuntimeProbeMarkInteraction(NSString *label, NSString *controlToken) {\n    if (!gHFAIL2CPPArmed) return;', IL2CPP)

    def test_exact_control_target_action_is_analyzed(self):
        for token in (
            'HFAFeatureDirectedAnalyses',
            'control.allTargets',
            'UIControlEventTouchUpInside',
            'UIControlEventValueChanged',
            'class_getInstanceMethod',
            'method_getImplementation',
            'HFAMapAnalyzeStrippedActionIMP',
            'HFAMapAnalyzeFeatureCallbackContext',
            'contextSeededAnalysis',
            'exact-user-activated-control-target-action',
            'verify-style-known-callback-downstream-x0-target-x1-cmd-x2-sender',
            'feature-directed-method-correlation-observed',
        ):
            self.assertIn(token, IL2CPP)

    def test_read_only_boundary_is_preserved(self):
        self.assertIn('@"selectorInvokedByProbe": @NO', IL2CPP)
        self.assertIn('@"impReplaced": @NO', IL2CPP)
        self.assertIn('@"memoryWritten": @NO', IL2CPP)
        self.assertIn('feature-directed-read-only-correlation-independent-of-hook-backend', IL2CPP)
        self.assertNotIn('DobbyInstrument', IL2CPP)
        self.assertNotIn('direct-method-entry', IL2CPP)
        self.assertNotIn('vm_write', IL2CPP)

    def test_version_markers(self):
        self.assertIn('2.5.1-dev-generic-feature-handler-method-descriptor', DIAG)
        self.assertIn('HFAMap v2.5.1-dev Generic Handler', ENTRY)
        self.assertIn('featureDirectedCorrelationCount', ENTRY)


if __name__ == '__main__':
    unittest.main()
