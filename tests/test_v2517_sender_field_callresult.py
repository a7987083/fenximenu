from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GEN = (ROOT / "hfamap/tools/generate_v2517_sender_resolver.py").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
VER = (ROOT / "hfamap/src/HFAMapVersion2517.mm").read_text()


class SenderFieldCallResult2517Tests(unittest.TestCase):
    def test_generator_restores_stack_spills(self):
        self.assertIn('rn==31', GEN)
        self.assertIn('stack[@((int64_t)imm)]', GEN)
        self.assertIn('memcpy(&n,saved.bytes,sizeof(n))', GEN)
        self.assertIn('stack reload handled by the unified LDR branch', GEN)

    def test_cfg_key_keeps_callee_saved_provenance(self):
        for token in ('regs[8].root', 'regs[19].root', 'regs[20].root', 'regs[21].root',
                      'regs[19].kind', 'regs[20].kind', 'regs[19].fieldOffset', 'regs[20].fieldOffset'):
            self.assertIn(token, GEN)

    def test_build_uses_generated_resolver(self):
        self.assertIn('generate_v2517_sender_resolver.py', MAKE)
        self.assertIn('HFAMapSenderDerivedProvenanceResolver2517.mm', MAKE)
        self.assertNotIn(' src/HFAMapSenderDerivedProvenanceResolver.mm ', MAKE)
        self.assertIn('src/HFAMapVersion2517.mm', MAKE)

    def test_version_and_policy(self):
        self.assertIn('2.5.17-dev-sender-field-callresult', VER)
        self.assertIn('READ-ONLY-SENDER-FIELD-STACK-CALLRESULT-BRANCH-PROVENANCE', VER)

    def test_no_sample_specific_rvas_or_write_hooks(self):
        corpus = GEN + VER
        for forbidden in ('0x3929C0', '0xB96A54', '0xB96B2C', '0x31AFD14',
                          'DobbyHook', 'MSHookFunction', 'mach_vm_write', 'vm_write'):
            self.assertNotIn(forbidden, corpus)


if __name__ == '__main__':
    unittest.main()
