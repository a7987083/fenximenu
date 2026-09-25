from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "hfamap/tools/generate_v2518_helper_summary.py"
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
VER = (ROOT / "hfamap/src/HFAMapVersion2518.mm").read_text()

class InterproceduralHelperSummary2518Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, str(GEN)], check=True)
        cls.src = (ROOT / "hfamap/src/HFAMapSenderDerivedProvenanceResolver2518.mm").read_text()

    def test_build_uses_generated_2518_resolver(self):
        self.assertIn('V2518_GENERATED', MAKEFILE)
        self.assertIn('src/HFAMapSenderDerivedProvenanceResolver2518.mm', MAKEFILE)
        self.assertNotIn('src/HFAMapSenderDerivedProvenanceResolver2517.mm src/', MAKEFILE)

    def test_helper_summary_is_bounded_and_memoized(self):
        self.assertIn('HFASDSummarizeHelperReturn', self.src)
        self.assertIn('interprocDepth > 2', self.src)
        self.assertIn('decoded<768', self.src)
        self.assertIn('seen.count<48', self.src)
        self.assertIn('HFASDHelperSignature', self.src)
        self.assertIn('memo[sig]', self.src)

    def test_caller_register_state_seeds_callee(self):
        self.assertIn('memcpy(init,callerRegs,sizeof(init))', self.src)
        self.assertIn('callerRegs[31]', self.src)
        self.assertIn('HFASDRegsData(init)', self.src)

    def test_ret_x0_is_summarized_and_returned_to_caller(self):
        self.assertIn('HFASDReg r=regs[0]', self.src)
        self.assertIn('senderDerivedReturn', self.src)
        self.assertIn('summarized=HFASDSummarizeHelperReturn', self.src)
        self.assertIn('if(summarized.kind!=HFASDUnknown)ret=summarized', self.src)
        self.assertIn('HFASDClobberCallerSaved(regs,ret)', self.src)

    def test_summary_evidence_is_exported(self):
        self.assertIn('helperSummaryCount', self.src)
        self.assertIn('helperSummaries', self.src)
        self.assertIn('senderDerivedHelperReturnCount', self.src)
        self.assertIn('READ-ONLY-INTERPROCEDURAL-HELPER-RETURN-PROVENANCE', self.src)

    def test_version_marker_and_no_sample_specific_inputs(self):
        self.assertIn('2.5.18-dev-interprocedural-helper-summary', VER)
        for forbidden in ('0xB96A54','0xB96B2C','0x3929C0','Damage Multiplier','Defence Multiplier','God Mode'):
            self.assertNotIn(forbidden, self.src)

    def test_safety_boundary_preserved(self):
        for forbidden in ('DobbyHook','MSHookFunction','mach_vm_write','vm_write'):
            self.assertNotIn(forbidden, self.src)

if __name__ == '__main__':
    unittest.main()
