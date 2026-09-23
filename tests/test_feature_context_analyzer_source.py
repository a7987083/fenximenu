from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = (ROOT / "hfamap/src/HFAMapFeatureContextAnalyzer.mm").read_text()
HEADER = (ROOT / "hfamap/src/HFAMapFeatureContextAnalyzer.h").read_text()
RUNTIME = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class FeatureContextAnalyzerSourceTests(unittest.TestCase):
    def test_exact_callback_context_is_seeded_from_known_relationship(self):
        for token in (
            'HFAMapAnalyzeFeatureCallbackContext',
            'com.hfa.feature-context/v1',
            'objc-target-self',
            'objc-selector-cmd',
            'exact-ui-control-sender',
            'exact-callback-arm64-abi-x0-target-x1-selector-x2-sender',
        ):
            self.assertIn(token, CONTEXT + HEADER)

    def test_context_analysis_is_bounded_and_read_only(self):
        for token in (
            'kHFAContextMaxInstructions = 768',
            'kHFAContextMaxBlocks = 64',
            'kHFAContextMaxDepth = 10',
            'read-only-bounded-context-seeded-no-hook-no-selector-invocation-no-memory-write',
        ):
            self.assertIn(token, CONTEXT)
        self.assertNotIn('objc_msgSend(', CONTEXT)
        self.assertNotIn('method_invoke', CONTEXT)
        self.assertNotIn('DobbyHook', CONTEXT)
        self.assertNotIn('vm_write', CONTEXT)

    def test_objc_metadata_and_method_range_are_correlated(self):
        for token in (
            'object_getClass',
            'class_getSuperclass',
            'evaluatedWithoutSelectorInvocation',
            'HFAIL2CPPMethodContainingRuntimeAddress',
            'il2cppMethodLinks',
            'verify.dylib-descriptor-callback-downstream-plus-h5gg-method-range',
        ):
            self.assertIn(token, CONTEXT)

    def test_runtime_probe_prefers_exact_context_chain(self):
        for token in (
            'contextSeededAnalysis',
            'contextSeededCorrelationCount',
            'contextResolvedConditionalCount',
            'verify-style-known-callback-downstream-x0-target-x1-cmd-x2-sender',
        ):
            self.assertIn(token, RUNTIME)

    def test_module_is_compiled(self):
        self.assertIn('src/HFAMapFeatureContextAnalyzer.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
