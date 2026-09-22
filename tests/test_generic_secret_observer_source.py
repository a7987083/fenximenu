import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFE = (ROOT / "hfamap/src/HFAMapGenericSecretObserverSafe.m").read_text()
UNSAFE = (ROOT / "hfamap/src/HFAMapGenericSecretObserver.m").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class GenericSecretObserverSourceTests(unittest.TestCase):
    def test_safe_hotfix_is_built_instead_of_global_scanner(self):
        self.assertIn("src/HFAMapGenericSecretObserverSafe.m", MAKEFILE)
        self.assertNotIn("src/HFAMapGenericSecretObserver.m", MAKEFILE)

    def test_safe_hotfix_forbids_process_wide_objc_realization(self):
        for forbidden in (
            "objc_getClassList",
            "_dyld_register_func_for_add_image",
            "method_setImplementation",
            "HFAInstallSecretHooks",
            "HFASecretDecryptFn",
        ):
            self.assertNotIn(forbidden, SAFE)
        self.assertIn("safe-disabled-global-scan", SAFE)
        self.assertIn("objcGetClassList=0", SAFE)
        self.assertIn("dyldCallback=0", SAFE)
        self.assertIn("swizzle=0", SAFE)
        self.assertIn("decryptInvoke=0", SAFE)

    def test_unsafe_research_source_is_retained_but_not_built(self):
        # Keep the original research implementation for audit/handoff only.
        self.assertIn("HFADecryptFingerprint", UNSAFE)
        self.assertIn("[SECRET-PLAINTEXT]", UNSAFE)
        self.assertIn("objc_getClassList", UNSAFE)
        self.assertNotIn("src/HFAMapGenericSecretObserver.m", MAKEFILE)

    def test_no_path_specific_target_in_safe_runtime(self):
        for forbidden in (
            "Path of Kings",
            "libpathofkings",
            "0x2129A4",
            "0x4B6848",
            "getter + 0xD00",
            "0x1204",
        ):
            self.assertNotIn(forbidden, SAFE)

    def test_runtime_identity_marks_crash_hotfix(self):
        self.assertIn("[SECRET-OBSERVER] version=2.4.3", SAFE)
        self.assertIn("mode=safe-disabled-global-scan", SAFE)


if __name__ == "__main__":
    unittest.main()
