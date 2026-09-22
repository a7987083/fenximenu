from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = (ROOT / "hfamap/src/HFAMapStrippedActionAnalyzer.mm").read_text()
INVENTORY = (ROOT / "hfamap/src/HFAMapObjCActionInventory.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class StrippedActionAnalyzerSourceTests(unittest.TestCase):
    def test_arm64_reference_and_call_instructions_are_supported(self):
        for token in (
            "ADRP Xd", "ADR Xd", "ADD (immediate)", "LDR Xt",
            "MOVZ 64-bit", "MOVK 64-bit", "BL imm26", "BLR Xn",
            'cbz-cbnz', 'tbz-tbnz',
        ):
            self.assertIn(token, ACTION)

    def test_register_provenance_is_bounded_and_noncanonical(self):
        self.assertIn("kHFAActionMaxInstructions = 512", ACTION)
        self.assertIn("kHFAActionMaxCalls = 64", ACTION)
        self.assertIn("arm64-x0-x7-candidate", ACTION)
        self.assertIn("local-dataflow-candidate", ACTION)
        self.assertIn("read-only-local-dataflow-no-hook-no-callback-invocation-no-memory-write", ACTION)
        self.assertIn('@"canonicalEligible": @NO', ACTION)

    def test_objc_inventory_does_not_require_function_symbols(self):
        for token in (
            "objc_copyClassNamesForImage", "class_copyMethodList", "method_getImplementation",
            "kHFAInventoryMaxClasses = 512", "kHFAInventoryMaxMethods = 256",
            "HFAMapAnalyzeStrippedActionIMP",
        ):
            self.assertIn(token, INVENTORY)
        self.assertNotIn("LC_SYMTAB", INVENTORY)

    def test_modules_are_compiled(self):
        self.assertIn("src/HFAMapStrippedActionAnalyzer.mm", MAKEFILE)
        self.assertIn("src/HFAMapObjCActionInventory.mm", MAKEFILE)
        self.assertIn("src/HFAIL2CPPMethodIndex.mm", MAKEFILE)


if __name__ == "__main__":
    unittest.main()
