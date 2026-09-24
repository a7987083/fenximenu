from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
VERSION = (ROOT / "hfamap/src/HFAMapVersion2512.mm").read_text()


class DirectedRetryStabilizationTests(unittest.TestCase):
    def test_bounded_retry_policy(self):
        self.assertIn('kHFADirectedRetryCount = 3', BUNDLE)
        self.assertIn('500000', BUNDLE)
        self.assertIn('1500000', BUNDLE)
        self.assertIn('HFAResolveDirectedWithRetry', BUNDLE)
        self.assertIn('HFADirectedResultUsable', BUNDLE)

    def test_each_attempt_re_resolves_live_directed_graph(self):
        self.assertIn('HFAMapResolveDirectedDescriptors(path, rootGraph', BUNDLE)
        self.assertIn('featureCount', BUNDLE)
        self.assertIn('resolvedFeatureCount', BUNDLE)
        self.assertIn('descriptorCandidateCount', BUNDLE)
        self.assertIn('stabilization', BUNDLE)
        self.assertIn('BOUNDED-LIVE-UI-RETRY', BUNDLE)

    def test_secret_collection_runs_after_final_directed_result(self):
        self.assertLess(BUNDLE.index('HFAResolveDirectedWithRetry'),
                        BUNDLE.index('HFAMapResolveSecretWrapperEvidence(path,directed'))
        self.assertIn('directedRetryAttempts', BUNDLE)
        self.assertIn('secretWrapperEvidenceCount', BUNDLE)

    def test_version_marker_is_compiled(self):
        self.assertIn('src/HFAMapVersion2512.mm', MAKEFILE)
        self.assertIn('2.5.12-dev-directed-retry-stabilization', VERSION)
        self.assertIn('HFAMap v2.5.12', BUNDLE)

    def test_no_new_hook_or_memory_write_path(self):
        for forbidden in ('DobbyHook', 'MSHookFunction', 'vm_write', 'mach_vm_write'):
            self.assertNotIn(forbidden, BUNDLE)


if __name__ == '__main__':
    unittest.main()
