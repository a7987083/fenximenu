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
        self.assertNotIn('mach/mach_vm.h', INDEX)

    def test_method_pointer_resolution_matches_m44_resolver_strategy(self):
        self.assertIn('il2cpp_method_get_pointer', INDEX)
        self.assertIn('MethodInfo[%lu]', INDEX)
        self.assertIn('uintptr_t words[2]', INDEX)
        self.assertIn('HFAExecutableUnityAddress', INDEX)
        self.assertIn('VM_PROT_EXECUTE', INDEX)
        self.assertIn('implementationOffsetFromLoadBase', INDEX)
        self.assertIn('@"methodPointerFallback": @YES', INDEX)
        self.assertIn('@"unityExecutableSegmentValidation": @YES', INDEX)

    def test_action_analyzer_correlates_bl_blr_and_br(self):
        self.assertIn('0xd63f0000U', ACTION)
        self.assertIn('0xd61f0000U', ACTION)
        self.assertIn('@"blr-register"', ACTION)
        self.assertIn('@"br-register"', ACTION)
        self.assertIn('exact-method-pointer-address', ACTION)
        self.assertIn('assembly-csharp-method-pointer-correlation', ACTION)
        self.assertIn('@"il2cppMethodIndex"', ACTION)
        self.assertIn('@"il2cppCorrelationCount"', ACTION)
        self.assertIn('com.hfa.stripped-action/v4', ACTION)

    def test_module_is_compiled(self):
        self.assertIn('src/HFAIL2CPPMethodIndex.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
