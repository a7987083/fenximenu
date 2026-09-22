from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()
RUNTIME = (ROOT / "hfamap/src/HFAMapRuntimeProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class IL2CPPRuntimeProbeSourceTests(unittest.TestCase):
    def test_requires_reversible_backend(self):
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyHook")', SOURCE)
        self.assertIn('dlsym(RTLD_DEFAULT, "DobbyDestroy")', SOURCE)
        self.assertIn('reversible-hook-backend-unavailable', SOURCE)

    def test_observes_resolver_and_invoke_chain(self):
        for symbol in (
            "il2cpp_class_from_name",
            "il2cpp_class_get_method_from_name",
            "il2cpp_runtime_invoke",
        ):
            self.assertIn(symbol, SOURCE)
        self.assertIn('runtime-method-call-observed', SOURCE)
        self.assertIn('method-resolved-invocation-not-observed', SOURCE)

    def test_original_calls_continue(self):
        self.assertIn('original ? original(image, namespaze, name)', SOURCE)
        self.assertIn('original ? original(klass, name, argumentCount)', SOURCE)
        self.assertIn('original ? original(method, object, arguments, exception)', SOURCE)
        self.assertNotIn('Memory.patchCode', SOURCE)
        self.assertIn('@"gameStateWritten": @NO', SOURCE)
        self.assertIn('@"hookInstalled": @(gHFAIL2CPPInstalledTargets.count > 0)', SOURCE)
        self.assertIn('@"hooksRestored": @(restoreFailures == 0)', SOURCE)

    def test_probe_is_bounded(self):
        self.assertIn('kHFAIL2CPPMaxEvents = 256', SOURCE)
        self.assertIn('kHFAIL2CPPMaxMappings = 256', SOURCE)
        self.assertIn('kHFAIL2CPPCorrelationWindow = 1.5', SOURCE)

    def test_existing_probe_embeds_evidence(self):
        self.assertIn('HFAIL2CPPRuntimeProbeArm', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeMarkInteraction', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeStop', RUNTIME)
        self.assertIn('@"il2cppRuntimeProbe"', RUNTIME)

    def test_build_includes_module(self):
        self.assertIn('src/HFAIL2CPPRuntimeProbe.mm', MAKEFILE)


if __name__ == "__main__":
    unittest.main()
