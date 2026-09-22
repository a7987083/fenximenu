from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "hfamap/src/HFAIL2CPPMethodIndex.mm").read_text()
ACTION = (ROOT / "hfamap/src/HFAMapStrippedActionAnalyzer.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class IL2CPPMethodIndexSourceTests(unittest.TestCase):
    def test_method_index_is_bounded_and_read_only(self):
        for token in (
            'kHFAMaxAssemblies = 512', 'kHFAMaxClasses = 4096',
            'kHFAMaxMethods = 32768', 'kHFAMaxMethodsPerClass = 1024',
            'read-only-il2cpp-metadata-enumeration-no-runtime-invoke-no-hook-no-memory-write',
            'assembly-csharp-not-found', 'required-il2cpp-exports-unavailable',
        ):
            self.assertIn(token, INDEX)
        self.assertNotIn('il2cpp_runtime_invoke(', INDEX)
        self.assertNotIn('DobbyHook', INDEX)
        self.assertNotIn('vm_write', INDEX)

    def test_method_pointer_resolution_prefers_export_and_validates_fallback(self):
        self.assertIn('il2cpp_method_get_pointer', INDEX)
        self.assertIn('methodinfo-first-word-readonly-fallback', INDEX)
        self.assertIn('HFAExecutablePointer', INDEX)
        self.assertIn('implementationOffsetFromLoadBase', INDEX)

    def test_action_analyzer_correlates_bl_and_blr(self):
        self.assertIn('BLR Xn', ACTION)
        self.assertIn('0xd63f0000U', ACTION)
        self.assertIn('exact-method-pointer-address', ACTION)
        self.assertIn('assembly-csharp-method-pointer-correlation', ACTION)
        self.assertIn('@"il2cppMethodIndex"', ACTION)
        self.assertIn('@"il2cppCorrelationCount"', ACTION)
        self.assertIn('com.hfa.stripped-action/v2', ACTION)

    def test_module_is_compiled(self):
        self.assertIn('src/HFAIL2CPPMethodIndex.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
