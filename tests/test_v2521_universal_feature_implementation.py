from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HFAMAP = ROOT / "hfamap"


class UniversalFeatureImplementation2521Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["python3", str(HFAMAP / "tools/generate_v2520_integration.py")])
        subprocess.check_call(["python3", str(HFAMAP / "tools/generate_v2521_async_enrichment.py")])
        subprocess.check_call(["python3", str(HFAMAP / "tools/generate_v2521_il2cpp_deadline.py")])
        cls.scanner = (HFAMAP / "src/HFAMapBundleRootScanner2521.mm").read_text()
        cls.method = (HFAMAP / "src/HFAIL2CPPMethodIndex2521.mm").read_text()
        cls.ranges = (HFAMAP / "src/HFAIL2CPPMethodRangeIndex2521.mm").read_text()
        cls.make = (HFAMAP / "Makefile").read_text()
        cls.build = (HFAMAP / "src/HFAMapBuildInfo.mm").read_text()

    def test_ui_ready_no_longer_waits_for_implementation_inventory(self):
        self.assertIn('menu-implementation-enrichment', self.scanner)
        self.assertIn('ASYNC-POST-UI-FEATURE-IMPLEMENTATION-ENRICHMENT', self.scanner)
        self.assertIn('@"uiBlocking": @NO', self.scanner)
        self.assertIn('dispatch_get_global_queue(QOS_CLASS_UTILITY, 0)', self.scanner)
        self.assertNotIn('@"menuImplementationInventory":@(implementationInventory!=nil)', self.scanner)

    def test_full_universal_feature_inventory_is_still_persisted(self):
        self.assertIn('HFAMapBuildMenuImplementationInventory', self.scanner)
        self.assertIn('HFAMapPersistMenuImplementationInventory', self.scanner)
        for token in ('runtimeMethodCount', 'memoryPatchCount', 'stateMutationCandidateCount'):
            self.assertIn(token, self.scanner)

    def test_method_index_checks_deadline_inside_method_loop(self):
        marker = 'for (NSUInteger mi = 0; mi < kHFAMaxMethodsPerClass'
        pos = self.method.index(marker)
        window = self.method[pos:pos + 420]
        self.assertIn('NSDate.date.timeIntervalSince1970 > deadline', window)
        self.assertIn('timedOut = YES; break;', window)

    def test_range_index_checks_deadline_inside_method_loop(self):
        marker = 'for (NSUInteger mi = 0; mi < kHFARangeMaxMethodsPerClass'
        pos = self.ranges.index(marker)
        window = self.ranges[pos:pos + 460]
        self.assertIn('NSDate.date.timeIntervalSince1970 > deadline', window)
        self.assertIn('timedOut = YES; break;', window)

    def test_makefile_compiles_successors_only(self):
        self.assertIn('V2521_ASYNC_ENRICHMENT_GENERATED', self.make)
        self.assertIn('V2521_IL2CPP_DEADLINE_GENERATED', self.make)
        self.assertIn('src/HFAMapBundleRootScanner2521.mm', self.make)
        self.assertIn('src/HFAIL2CPPMethodIndex2521.mm', self.make)
        self.assertIn('src/HFAIL2CPPMethodRangeIndex2521.mm', self.make)
        files = self.make.split('HFAMapUniversal_FILES = ', 1)[1].split('\n', 1)[0]
        self.assertNotIn(' src/HFAMapBundleRootScanner2520.mm ', f' {files} ')
        self.assertNotIn(' src/HFAIL2CPPMethodIndex.mm ', f' {files} ')
        self.assertNotIn(' src/HFAIL2CPPMethodRangeIndex.mm ', f' {files} ')

    def test_build_identity_matches_delivery(self):
        self.assertIn('2.5.21-dev', self.build)
        self.assertIn('2.5.21-dev-universal-feature-implementation', self.build)
        self.assertIn('FAST-UI-ASYNC-UNIVERSAL-FEATURE-IMPLEMENTATION', self.build)

    def test_read_only_boundary_preserved(self):
        corpus = self.scanner + self.method + self.ranges
        for forbidden in ('DobbyHook', 'MSHookFunction', 'mach_vm_write(', 'vm_write('):
            self.assertNotIn(forbidden, corpus)


if __name__ == '__main__':
    unittest.main()
