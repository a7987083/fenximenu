from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
DIAGNOSTICS = (ROOT / "hfamap/src/HFAMapDiagnostics.mm").read_text()
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()


class JailpatchRuntimeEvidenceSourceTests(unittest.TestCase):
    def test_runtime_semantics_are_separate_from_static_patch_contract(self):
        for token in (
            'com.hfa.igmm.runtime/v1',
            'RuntimeActions.json',
            'runtimeRecords',
            'normalizedExecutionPrimitive',
            'normalizedCanonicalReason',
            'runtime-action-not-static-bytes',
            'runtime-value-not-static-bytes',
            'runtime-toggle-not-static-bytes',
        ):
            self.assertIn(token, CORE + RESOLVER)
        self.assertIn('staticPatchContractUnchanged', CORE)
        self.assertIn('if (offsetCandidate || patchCandidate) return nil', RESOLVER)

    def test_jailpatch_owner_inventory_is_bounded_and_location_aware(self):
        for token in (
            'kHFAMaxRuntimeMethods = 192',
            'class_copyMethodList',
            'class_copyPropertyList',
            'class_copyIvarList',
            'implementationUUID',
            'implementationOffsetFromLoadBase',
            'candidateScore',
            'inventoryTruncated',
            'objc-instance-ivar-only',
        ):
            self.assertIn(token, RESOLVER)

    def test_runtime_evidence_remains_read_only(self):
        self.assertIn('metadata-only-no-selector-invocation-no-hook-no-memory-write', RESOLVER)
        self.assertIn('@"invoked": @NO', RESOLVER)
        self.assertIn('@"written": @NO', RESOLVER)
        self.assertIn('@"hookInstalled": @NO', RESOLVER)
        for forbidden in ('method_setImplementation', 'method_invoke', 'objc_msgSend', 'vm_write'):
            self.assertNotIn(forbidden, RESOLVER)

    def test_known_selectors_are_evidence_not_required_interface(self):
        self.assertIn('loadConfig:', RESOLVER)
        self.assertIn('loadPolicies', RESOLVER)
        self.assertIn('inventoried-no-exact-methods', RESOLVER)
        self.assertIn('known-exact-selector', RESOLVER)

    def test_version_and_ui_are_advanced(self):
        self.assertIn('2.4.3-dev-runtime-action-correlator', DIAGNOSTICS)
        self.assertIn('HFAMap v2.4.3-dev Runtime Action Correlator', ENTRY)


if __name__ == "__main__":
    unittest.main()
