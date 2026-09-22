from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = (ROOT / "hfamap/src/HFAMapMenuBinaryAnalyzer.mm").read_text()
IMAGE = (ROOT / "hfamap/src/HFAMapImageProbe.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class MenuBinaryCallGraphSourceTests(unittest.TestCase):
    def test_symbol_and_linkedit_parser_is_bounded(self):
        for token in (
            "LC_SYMTAB",
            "SEG_LINKEDIT",
            "kHFAMenuMaxSymbols = 200000",
            "kHFAMenuMaxFunctions = 4096",
            "kHFAMenuMaxFunctionBytes = 4096",
            "invalid-linkedit-bounds",
        ):
            self.assertIn(token, ANALYZER)

    def test_patch_primitives_are_structurally_named(self):
        for token in (
            "MemoryPatch13createWithHex",
            "MemoryPatch15createWithBytes",
            "MemoryPatch13createWithAsm",
            "MemoryPatch6Modify",
            "MemoryPatch7Restore",
            "_CodePatch",
        ):
            self.assertIn(token, ANALYZER)

    def test_arm64_direct_bl_edges_are_recovered(self):
        self.assertIn("0xfc000000U", ANALYZER)
        self.assertIn("0x94000000U", ANALYZER)
        self.assertIn('arm64-direct-bl', ANALYZER)
        self.assertIn('directPatchCallEdges', ANALYZER)
        self.assertIn('callerRVA', ANALYZER)
        self.assertIn('callsiteRVA', ANALYZER)
        self.assertIn('primitiveRVA', ANALYZER)

    def test_entry_and_dispatcher_symbols_are_inventoried(self):
        for token in ("setupModMenu", "offset:patch:", "machoPath", "initialValue"):
            self.assertIn(token, ANALYZER)
        self.assertIn('objc_msgSend$', ANALYZER)
        self.assertIn('dispatcherSymbols', ANALYZER)
        self.assertIn('kHFAMenuMaxDispatcherSymbols = 256', ANALYZER)

    def test_patch_argument_evidence_is_bounded_and_noncanonical(self):
        for token in (
            'kHFAMenuArgumentWindowBytes = 32',
            'kHFAMenuMaxArgumentEvidence = 8',
            'movz-immediate-candidate',
            'argumentEvidence',
            'candidate-only-no-abi-binding',
            'near-callsite-immediate-candidates-not-proven-arguments',
        ):
            self.assertIn(token, ANALYZER)
        self.assertIn('@"canonicalEligible": @NO', ANALYZER)
        self.assertIn('@"analysisOnly": @YES', ANALYZER)

    def test_menu_family_is_separate_from_patch_backend(self):
        self.assertIn('com.hfa.menu-binary-evidence/v2', IMAGE)
        self.assertIn('@"menuFamily"', IMAGE)
        self.assertIn('@"patchBackends"', IMAGE)
        self.assertIn('@"legacy-ap"', IMAGE)
        self.assertIn('@"jailpatch"', IMAGE)
        legacy_index = IMAGE.index('legacy >= 30 && legacy > jail')
        backend_index = IMAGE.index('NSMutableOrderedSet *patchBackends')
        self.assertLess(legacy_index, backend_index)
        self.assertNotIn('family = @"memorypatch-menu"', IMAGE)

    def test_analysis_is_attached_but_noncanonical(self):
        self.assertIn('HFAMapAnalyzeMenuBinary(header, slide, deadline)', IMAGE)
        self.assertIn('@"menuCallGraph"', IMAGE)
        self.assertIn('@"directPatchCallEdgeCount"', IMAGE)
        self.assertIn('@"canonicalEligible": @NO', ANALYZER)
        self.assertIn('@"patchPrimitiveEvidenceOnly": @YES', IMAGE)

    def test_module_is_compiled_and_v239_path_stays_absent(self):
        self.assertIn('src/HFAMapMenuBinaryAnalyzer.mm', MAKEFILE)
        runtime = (ROOT / "hfamap/src/HFAIL2CPPRuntimeProbe.mm").read_text()
        self.assertNotIn('DobbyInstrument', runtime)
        self.assertNotIn('direct-method-entry', runtime)


if __name__ == "__main__":
    unittest.main()
