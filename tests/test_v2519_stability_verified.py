from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
LOAD_GEN = ROOT / 'hfamap/tools/generate_v2519_loaded_safe.py'
SEND_GEN = ROOT / 'hfamap/tools/generate_v2519_sender_safe.py'
MAKE = (ROOT / 'hfamap/Makefile').read_text()
VER = (ROOT / 'hfamap/src/HFAMapVersion2519.mm').read_text()


class StabilityVerified2519Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(LOAD_GEN)], check=True)
        subprocess.run([sys.executable, str(SEND_GEN)], check=True)
        cls.loaded = (ROOT / 'hfamap/src/HFAMapLoadedDylibEvidenceResolver2519.mm').read_text()
        cls.sender = (ROOT / 'hfamap/src/HFAMapSenderDerivedProvenanceResolver2519.mm').read_text()

    def test_loaded_global_pointer_objc_probe_is_fail_closed(self):
        self.assertIn('DISABLED-UNTRUSTED-GLOBAL-POINTER-FAIL-CLOSED', self.loaded)
        self.assertNotIn('object_getClass((id)(uintptr_t)value)', self.loaded)
        self.assertIn('HFAReadableCString(value)', self.loaded)
        self.assertIn('HFAImageRelation(value, images)', self.loaded)

    def test_helper_cfg_is_not_enqueued_into_caller_cfg(self):
        self.assertNotIn('HFASDEnqueue(queue,scheduled,t,depth+1,regs,stack,cond,info.dli_fbase);HFASDReg ret=HFASDCallResultFromArgs', self.sender)
        self.assertIn('HFASDSummarizeHelperReturn', self.sender)

    def test_candidate_call_result_does_not_become_verified_sender_truth(self):
        self.assertIn('r.confidence != HFASDConfidenceCandidate', self.sender)
        self.assertIn('HFASDConfidenceCandidate', self.sender)
        self.assertIn('senderDerivedHelperReturnCount', self.sender)

    def test_saturation_is_explicit_fail_closed_evidence(self):
        self.assertIn('analysisTruncated', self.sender)
        self.assertIn('provenanceConfidence', self.sender)
        self.assertIn('incomplete', self.sender)
        self.assertIn('bounded-complete', self.sender)

    def test_build_wires_only_hardened_generated_resolvers(self):
        self.assertIn('generate_v2519_loaded_safe.py', MAKE)
        self.assertIn('generate_v2519_sender_safe.py', MAKE)
        self.assertIn('HFAMapLoadedDylibEvidenceResolver2519.mm', MAKE)
        self.assertIn('HFAMapSenderDerivedProvenanceResolver2519.mm', MAKE)
        self.assertNotIn(' src/HFAMapLoadedDylibEvidenceResolver.mm ', MAKE)
        self.assertNotIn(' src/HFAMapSenderDerivedProvenanceResolver2518.mm ', MAKE)

    def test_version_and_read_only_boundary(self):
        self.assertIn('2.5.19-dev-stability-verified-helper-return', VER)
        self.assertIn('READ-ONLY-FAIL-CLOSED-VERIFIED-HELPER-RETURN-PROVENANCE', VER)
        corpus = self.loaded + self.sender + VER
        for forbidden in ('DobbyHook', 'MSHookFunction', 'mach_vm_write', 'vm_write'):
            self.assertNotIn(forbidden, corpus)
        for forbidden in ('0xB96A54', '0xB96B2C', '0x3929C0', 'Damage Multiplier', 'Defence Multiplier'):
            self.assertNotIn(forbidden, corpus)


if __name__ == '__main__':
    unittest.main()
