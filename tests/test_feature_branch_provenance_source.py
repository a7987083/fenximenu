from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROV = (ROOT / 'hfamap/src/HFAMapFeatureBranchProvenance.mm').read_text()
HANDLER = (ROOT / 'hfamap/src/HFAMapHandlerBranchProvenanceResolver.mm').read_text()
MAKEFILE = (ROOT / 'hfamap/Makefile').read_text()
VERSION = (ROOT / 'hfamap/src/HFAMapVersion2515.mm').read_text()


class FeatureBranchProvenanceSourceTests(unittest.TestCase):
    def test_entry_abi_is_seeded_from_exact_action_context(self):
        self.assertIn('x0-target/self', PROV)
        self.assertIn('x1-_cmd', PROV)
        self.assertIn('x2-sender/control', PROV)
        self.assertIn('HFABPEntryTarget', HANDLER)
        self.assertIn('HFABPEntrySelector', HANDLER)
        self.assertIn('HFABPEntrySender', HANDLER)

    def test_shared_target_blocks_are_downgraded(self):
        self.assertIn('targetFeatureUseCounts', PROV)
        self.assertIn('sharedActionTargetBlockDowngraded', PROV)
        self.assertIn('sharedTargetBlocksAreNotFeatureOwned', PROV)
        self.assertIn('sharedTargetBlocks', PROV)

    def test_branch_and_call_provenance_is_bounded(self):
        for token in ('kHFABPMaxInstructions', 'kHFABPMaxBlocks', 'kHFABPMaxDepth', 'kHFABPMaxCalls', 'kHFABPMaxBranches'):
            self.assertIn(token, HANDLER)
        for token in ('entryDerivedBranchCount', 'entryDerivedCallCount', 'branches', 'calls'):
            self.assertIn(token, HANDLER)

    def test_output_and_modules_are_wired(self):
        self.assertIn('FeatureBranchProvenance.json', PROV)
        self.assertIn('src/HFAMapHandlerBranchProvenanceResolver.mm', MAKEFILE)
        self.assertIn('src/HFAMapFeatureBranchProvenance.mm', MAKEFILE)
        self.assertIn('src/HFAMapVersion2515.mm', MAKEFILE)
        self.assertIn('2.5.15-dev-shared-target-branch-provenance', VERSION)

    def test_no_sample_specific_addresses_or_names(self):
        for forbidden in ('0x3929C0', '0x398F58', '0x31AFD14', '0x3593500', 'Damage Multiplier', 'Defence Multiplier', 'God Mode'):
            self.assertNotIn(forbidden, PROV + HANDLER)

    def test_read_only_boundary(self):
        for forbidden in ('DobbyHook', 'MSHookFunction', 'vm_write', 'mach_vm_write'):
            self.assertNotIn(forbidden, PROV + HANDLER)
        self.assertIn('actionInvoked', PROV)
        self.assertIn('memoryWritten', PROV)


if __name__ == '__main__':
    unittest.main()
