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
            "BR Xn", "MOV Xd, Xm", "LDR Xt, literal", "LDUR Xt",
            'cbz-cbnz', 'tbz-tbnz', 'b-cond',
        ):
            self.assertIn(token, ACTION)

    def test_cfg_is_bounded_and_noncanonical(self):
        for token in (
            "kHFAActionMaxInstructions = 2048",
            "kHFAActionMaxInstructionsPerBlock = 96",
            "kHFAActionMaxBlocks = 96",
            "kHFAActionMaxDepth = 12",
            "kHFAActionMaxCalls = 128",
            "bounded-cfg-worklist",
            "same-image-helper-traversal",
            "cfg-dataflow-candidate",
            "read-only-bounded-cfg-no-hook-no-callback-invocation-no-memory-write",
        ):
            self.assertIn(token, ACTION)
        self.assertIn('@"canonicalEligible": @NO', ACTION)

    def test_indirect_dispatch_is_recorded_and_correlated(self):
        self.assertIn("0xd61f0000U", ACTION)
        self.assertIn("0xd63f0000U", ACTION)
        self.assertIn('indirectBranches', ACTION)
        self.assertIn('unresolvedIndirectBranchCount', ACTION)
        self.assertIn('exact-method-pointer-address', ACTION)
        self.assertIn('assembly-csharp-method-pointer-correlation', ACTION)
        self.assertIn('verify.dylib-arm64-relocation-and-register-context-coverage', ACTION)

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
