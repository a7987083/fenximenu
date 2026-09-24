from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapSenderDerivedProvenanceResolver.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
VER = (ROOT / "hfamap/src/HFAMapVersion2516.mm").read_text()

class SenderDerivedProvenanceTests(unittest.TestCase):
    def test_module_is_compiled(self):
        self.assertIn('src/HFAMapSenderDerivedProvenanceResolver.mm', MAKEFILE)
        self.assertIn('src/HFAMapVersion2516.mm', MAKEFILE)
        self.assertIn('2.5.16-dev-sender-derived-provenance', VER)

    def test_objc_entry_sender_seed_is_explicit(self):
        self.assertIn('HFASDRootSender', SRC)
        self.assertIn('initial[2]=HFASDEntryReg(HFASDRootSender', SRC)
        self.assertIn('@"senderToken"', SRC)
        self.assertIn('@"targetToken"', SRC)
        self.assertIn('@"selector"', SRC)

    def test_sender_field_load_provenance_supports_x_and_w_loads(self):
        self.assertIn('0xf9400000U', SRC)
        self.assertIn('0xb9400000U', SRC)
        self.assertIn('0xf8400000U', SRC)
        self.assertIn('0xb8400000U', SRC)
        self.assertIn('HFASDFieldLoad', SRC)
        self.assertIn('fieldOffset', SRC)

    def test_calls_and_branches_export_sender_dependency(self):
        self.assertIn('senderDerivedArguments', SRC)
        self.assertIn('senderDerivedCalls', SRC)
        self.assertIn('senderDerivedBranches', SRC)
        self.assertIn('cbz-cbnz', SRC)
        self.assertIn('tbz-tbnz', SRC)
        self.assertIn('b-cond', SRC)
        self.assertIn('HFASDConditionEvidence', SRC)

    def test_call_result_is_candidate_not_claimed_truth(self):
        self.assertIn('HFASDConfidenceCandidate', SRC)
        self.assertIn('HFASDCallResultFromArgs', SRC)
        self.assertIn('candidate', SRC)

    def test_output_and_safety(self):
        self.assertIn('SenderDerivedProvenance.json', SRC)
        self.assertIn('READ-ONLY-SENDER-FIELD-CALL-BRANCH-PROVENANCE', SRC)
        for forbidden in ('DobbyHook', 'MSHookFunction', 'mach_vm_write', 'vm_write'):
            self.assertNotIn(forbidden, SRC)

    def test_no_sample_specific_inputs(self):
        for forbidden in ('0x3929C0', '0xB96B2C', '0xB96A54', '0x31AFD14', '0x3593500', 'Damage Multiplier', 'Defence Multiplier', 'God Mode'):
            self.assertNotIn(forbidden, SRC)

if __name__ == '__main__':
    unittest.main()
