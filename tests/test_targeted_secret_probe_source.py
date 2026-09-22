from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapTargetedSecretProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()


class TargetedSecretProbeSourceTests(unittest.TestCase):
    def test_probe_is_built_and_explicitly_armed(self):
        self.assertIn("src/HFAMapTargetedSecretProbe.mm", MAKEFILE)
        self.assertIn("HFAMapArmTargetedSecretProbe(nil, 8.0)", ENTRY)
        self.assertIn("Arm Targeted Runtime Probe (8s)", ENTRY)

    def test_no_process_wide_objc_or_dyld_auto_scan(self):
        for forbidden in (
            "objc_getClassList",
            "_dyld_register_func_for_add_image",
            "__attribute__((constructor))",
        ):
            self.assertNotIn(forbidden, SRC)

    def test_selected_image_scope_is_mandatory(self):
        self.assertIn("objc_copyClassNamesForImage", SRC)
        self.assertIn("HFAPathMatchesSelected", SRC)
        self.assertIn("HFAClassOwnSecretMethod", SRC)
        self.assertIn("secretCandidates", SRC)
        self.assertIn("selected-image-only-explicit-arm-temporary-hook", SRC)

    def test_hook_lifecycle_restores_original_imp(self):
        self.assertIn("method_setImplementation(method, (IMP)HFATargetedSecretReplacement)", SRC)
        self.assertIn("method_setImplementation(local[i].method, local[i].original)", SRC)
        self.assertIn("HFAMapStopTargetedSecretProbe(@\"timeout\")", SRC)

    def test_decrypt_resolver_has_no_fixed_getter_delta(self):
        self.assertNotIn("getter + 0xD00", SRC)
        self.assertNotIn("0x1204", SRC)
        self.assertNotIn("0x2129A4", SRC)
        for token in ("0xD105C3FFU", "0xB9400408U", "0x53187D00U", "matches == 1U"):
            self.assertIn(token, SRC)

    def test_runtime_log_contains_provenance(self):
        for token in (
            "[TARGETED-SECRET-PROBE]",
            "[TARGETED-SECRET]",
            "getterRVA=%llX",
            "decryptRVA=%llX",
            "keySlot=%u",
            "plain=%s",
            "validHexRVA=%d",
        ):
            self.assertIn(token, SRC)


if __name__ == "__main__":
    unittest.main()
