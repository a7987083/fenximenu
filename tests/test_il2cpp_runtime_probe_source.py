from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbeSafe.mm").read_text()
RUNTIME = (ROOT / "hfamap/src/HFAMapRuntimeProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class IL2CPPRuntimeProbeSourceTests(unittest.TestCase):
    def test_no_inline_hook_backend(self):
        for forbidden in ('DobbyHook', 'DobbyDestroy', 'DobbyInstrument', 'il2cpp_runtime_invoke', 'vm_write'):
            self.assertNotIn(forbidden, SOURCE)
        self.assertIn('no-inline-hook-no-il2cpp-export-hook', SOURCE)
        self.assertIn('@"hookInstalled": @NO', SOURCE)
        self.assertIn('@"memoryWritten": @NO', SOURCE)

    def test_feature_directed_read_only_chain(self):
        for token in (
            'control.allTargets',
            'class_getInstanceMethod',
            'method_getImplementation',
            'HFAMapAnalyzeStrippedActionIMP',
            'HFAMapAnalyzeFeatureCallbackContext',
            'feature-directed-method-correlation-observed',
        ):
            self.assertIn(token, SOURCE)

    def test_existing_probe_embeds_evidence(self):
        self.assertIn('HFAIL2CPPRuntimeProbeArm', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeMarkInteraction', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeStop', RUNTIME)
        self.assertIn('@"il2cppRuntimeProbe"', RUNTIME)

    def test_probe_is_bounded(self):
        self.assertIn('kHFASafeMaxInteractions = 64', SOURCE)
        self.assertIn('kHFASafeMaxFeatureAnalyses = 64', SOURCE)
        self.assertIn('kHFASafeMaxActionsPerInteraction = 16', SOURCE)

    def test_build_includes_safe_module_only(self):
        self.assertIn('src/HFAIL2CPPRuntimeProbeSafe.mm', MAKEFILE)
        self.assertNotIn('src/HFAIL2CPPRuntimeProbe.mm', MAKEFILE)


if __name__ == "__main__":
    unittest.main()
