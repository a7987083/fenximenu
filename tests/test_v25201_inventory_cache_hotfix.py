from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
HFAMAP = ROOT / "hfamap"
GEN = HFAMAP / "tools/generate_v25201_inventory_cache.py"
MAKEFILE = (HFAMAP / "Makefile").read_text()
VERSION = (HFAMAP / "src/HFAMapVersion25201.mm").read_text()


class InventoryCacheHotfix25201Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["python3", str(GEN)])
        cls.source = (HFAMAP / "src/HFAMapMenuImplementationInventory25201.mm").read_text()

    def test_shared_implementation_cache_is_wired(self):
        self.assertIn('NSMutableDictionary *analysisCache', self.source)
        self.assertIn('analysisCache[analysisKey]', self.source)
        self.assertIn('action-cache-hit', self.source)
        self.assertIn('sharedImplementationAnalysisCached', self.source)

    def test_inventory_has_global_budget_and_fail_closed_skip(self):
        self.assertIn('kHFAImplementationMaxUniqueActions', self.source)
        self.assertIn('kHFAImplementationAnalysisBudgetSeconds', self.source)
        self.assertIn('action-skipped-budget', self.source)
        self.assertIn('inventory-budget-skipped', self.source)
        self.assertIn('analysisTruncated', self.source)

    def test_diagnostics_expose_action_progress(self):
        for token in ('menu-implementation-inventory', 'action-analysis-start',
                      'action-analysis-complete', 'action-cache-hit'):
            self.assertIn(token, self.source)

    def test_makefile_uses_successor_only(self):
        self.assertIn('V25201_INVENTORY_GENERATED', MAKEFILE)
        self.assertIn('src/HFAMapMenuImplementationInventory25201.mm', MAKEFILE)
        files = MAKEFILE.split('HFAMapUniversal_FILES = ', 1)[1].split('\n', 1)[0]
        self.assertNotIn(' src/HFAMapMenuImplementationInventory.mm ', f' {files} ')

    def test_read_only_boundary(self):
        for forbidden in ('DobbyHook', 'MSHookFunction', 'mach_vm_write(', 'vm_write('):
            self.assertNotIn(forbidden, self.source)
        self.assertIn('memoryWritten', self.source)

    def test_version_marker(self):
        self.assertIn('2.5.20.1-dev-inventory-cache-hotfix', VERSION)
        self.assertIn('READ-ONLY-BOUNDED-SHARED-IMPLEMENTATION-CACHE', VERSION)


if __name__ == '__main__':
    unittest.main()
