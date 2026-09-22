import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapGenericSecretObserver.m").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class GenericSecretObserverSourceTests(unittest.TestCase):
    def test_is_built(self):
        self.assertIn("src/HFAMapGenericSecretObserver.m", MAKEFILE)

    def test_no_fixed_delta_or_path_specific_target(self):
        self.assertNotIn("getter + 0xD00", SRC)
        self.assertNotIn("0x1204", SRC)
        self.assertNotIn("Path of Kings", SRC)
        self.assertNotIn("libpathofkings", SRC)
        self.assertNotIn("0x2129A4", SRC)
        self.assertNotIn("0x4B6848", SRC)

    def test_unique_text_fingerprint_gate(self):
        self.assertIn("HFADecryptFingerprint", SRC)
        self.assertIn("0xD105C3FFu", SRC)
        self.assertIn("0xB9400408u", SRC)
        self.assertIn("0x53187D00u", SRC)
        self.assertIn("matches == 1u", SRC)
        self.assertIn("HFATextRangeForImage", SRC)

    def test_runtime_evidence_contains_needed_provenance(self):
        self.assertIn("[SECRET-PLAINTEXT]", SRC)
        self.assertIn("descriptorRVA=%llX", SRC)
        self.assertIn("keySlot=%u", SRC)
        self.assertIn("decryptRVA=%llX", SRC)
        self.assertIn("callerRVA=%llX", SRC)
        self.assertIn("flags >> 24", SRC)

    def test_preserves_original_getter_and_uses_scratch_copy(self):
        self.assertIn("original)(self, _cmd)", SRC)
        self.assertIn("malloc(blobSize)", SRC)
        self.assertIn("HFASafeRead((uintptr_t)secret, copy, blobSize)", SRC)
        self.assertIn("rawKeysLogged=0", SRC)


if __name__ == "__main__":
    unittest.main()
