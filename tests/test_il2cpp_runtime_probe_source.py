from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()
RESOLVER = (ROOT / "hfamap/src/HFAIL2CPPResolver.mm").read_text()
RUNTIME = (ROOT / "hfamap/src/HFAMapRuntimeProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class IL2CPPRuntimeProbeSourceTests(unittest.TestCase):
    def test_embeds_reversible_backend(self):
        self.assertIn('DobbyInstrument((void *)pointer', SOURCE)
        self.assertIn('DobbyDestroy(value.pointerValue)', SOURCE)
        self.assertIn('embedded-dobby-instrument-reversible', SOURCE)
        self.assertIn('vendor/dobby/lib/libdobby.a', MAKEFILE)

    def test_observes_resolver_and_invoke_chain(self):
        for symbol in (
            "il2cpp_class_from_name",
            "il2cpp_class_get_method_from_name",
            "il2cpp_runtime_invoke",
        ):
            self.assertIn(symbol, SOURCE)
        self.assertIn('runtime-method-call-observed', SOURCE)
        self.assertIn('method-resolved-invocation-not-observed', SOURCE)
        self.assertIn('direct-method-entry', SOURCE)

    def test_original_calls_continue(self):
        self.assertIn('original ? original(image, namespaze, name)', SOURCE)
        self.assertIn('original ? original(klass, name, argumentCount)', SOURCE)
        self.assertIn('original ? original(method, object, arguments, exception)', SOURCE)
        self.assertNotIn('Memory.patchCode', SOURCE)
        self.assertIn('@"gameStateWritten": @NO', SOURCE)
        self.assertIn('@"hookInstalled": @(gHFAIL2CPPInstalledTargets.count > 0)', SOURCE)
        self.assertIn('@"hooksRestored": @(restoreFailures == 0)', SOURCE)

    def test_probe_is_bounded(self):
        self.assertIn('kHFAIL2CPPMaxEvents = 512', SOURCE)
        self.assertIn('kHFAIL2CPPMaxMappings = 256', SOURCE)
        self.assertIn('kHFAIL2CPPMaxDirectInstruments = 96', SOURCE)
        self.assertIn('kHFAIL2CPPCorrelationWindow = 1.5', SOURCE)

    def test_unitxp_resolver_core_is_bounded_and_fail_closed(self):
        for token in (
            'UnitXP_SP3-Moonstone@a3b8db8651eaea23ec0ae7e5fca497e8f67bcf6c',
            'il2cpp_domain_get_assemblies', 'il2cpp_image_get_class_count',
            'il2cpp_class_get_methods', 'il2cpp_method_get_pointer',
            'kHFAIL2CPPResolverMaxClasses = 12000',
            'kHFAIL2CPPResolverMaxMethods = 180000',
            'required-il2cpp-enumeration-exports-unavailable',
            'HFAExecutableLocation', 'MethodInfo[%lu]',
        ):
            self.assertIn(token, RESOLVER)
        self.assertIn('src/HFAIL2CPPResolver.mm', MAKEFILE)

    def test_existing_probe_embeds_evidence(self):
        self.assertIn('HFAIL2CPPRuntimeProbeArm', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeMarkInteraction', RUNTIME)
        self.assertIn('HFAIL2CPPRuntimeProbeStop', RUNTIME)
        self.assertIn('@"il2cppRuntimeProbe"', RUNTIME)

    def test_build_includes_module(self):
        self.assertIn('src/HFAIL2CPPRuntimeProbe.mm', MAKEFILE)


if __name__ == "__main__":
    unittest.main()
