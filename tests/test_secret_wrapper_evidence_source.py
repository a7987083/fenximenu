from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapSecretWrapperEvidenceResolver.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapSecretWrapperEvidenceResolver.h").read_text()
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class SecretWrapperEvidenceSourceTests(unittest.TestCase):
    def test_module_is_wired(self):
        self.assertIn("HFAMapSecretWrapperEvidenceResolver.mm", MAKEFILE)
        self.assertIn("HFAMapResolveSecretWrapperEvidence", HDR)
        self.assertIn("HFAMapResolveSecretWrapperEvidence", BUNDLE)
        self.assertIn("SecretWrapperEvidence.json", SRC)

    def test_read_only_policy(self):
        self.assertIn("UNIVERSAL-SECRET-WRAPPER-READ-ONLY-NO-INTERNAL-CALLS", SRC)
        for forbidden in ("objc_msgSend", "DobbyHook", "MSHookFunction", "method_setImplementation", "vm_write", "mach_vm_write"):
            self.assertNotIn(forbidden, SRC)
        self.assertIn('@"secretGetterInvoked": @NO', SRC)
        self.assertIn('@"decryptRoutineInvoked": @NO', SRC)
        self.assertIn('@"memoryWritten": @NO', SRC)

    def test_secret_blob_is_bounded_and_structural(self):
        for token in ("class_copyIvarList", "ivar_getTypeEncoding", "vm_read_overwrite", "length <= 0x10000u", "kHFASecretMaxBlobPrefix"):
            self.assertIn(token, SRC)
        self.assertIn("plausibleSecretBlob", SRC)
        self.assertIn("cipherPrefixHex", SRC)

    def test_decrypt_code_is_observed_not_executed(self):
        for token in ("method_getImplementation", "dladdr", "__TEXT", "__text", "D105C3FF", "B9400408", "53187D00", "candidateCodeHex"):
            self.assertIn(token, SRC)
        self.assertIn("fingerprintVerifiedAlgorithm", SRC)
        self.assertIn("uniqueCandidate", SRC)

    def test_upstream_descriptor_identity_is_preserved(self):
        for token in ("descriptorToken", "identifierStrings", "fieldName", "fieldRole", "wrapperToken", "wrapperClass"):
            self.assertIn(token, SRC)

    def test_version_marker_is_wired(self):
        self.assertIn("HFAMapVersion2511.mm", MAKEFILE)
        self.assertIn("HFAMap v2.5.11", BUNDLE)


if __name__ == "__main__":
    unittest.main()
