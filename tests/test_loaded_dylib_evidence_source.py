from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapLoadedDylibEvidenceResolver.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapLoadedDylibEvidenceResolver.h").read_text()
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class LoadedDylibEvidenceSourceTests(unittest.TestCase):
    def test_universal_policy_is_explicit(self):
        self.assertIn('UNIVERSAL / 通用 ONLY', HDR)
        self.assertIn('UNIVERSAL-ONLY-READ-ONLY-NO-SAMPLE-SPECIAL-CASES', SRC)
        for forbidden in ('RogueLegend', 'CheatGetMoney', 'God Mode', 'FreeShop', '0x31AFD14', '0x3593500'):
            self.assertNotIn(forbidden, SRC)

    def test_loaded_image_is_resolved_without_loading_it(self):
        self.assertIn('_dyld_image_count()', SRC)
        self.assertIn('_dyld_get_image_name', SRC)
        self.assertIn('_dyld_get_image_header', SRC)
        self.assertIn('_dyld_get_image_vmaddr_slide', SRC)
        self.assertIn('ambiguous-loaded-basename', SRC)
        self.assertIn('selected-dylib-not-loaded', SRC)
        self.assertNotIn('dlopen(', SRC)

    def test_objc_metadata_inventory_is_read_only_and_bounded(self):
        for token in (
            'objc_copyClassNamesForImage', 'class_copyMethodList', 'class_copyIvarList',
            'class_copyPropertyList', 'method_getImplementation', 'ivar_getOffset',
            'kHFALoadedMaxClasses', 'kHFALoadedMaxMethods', 'kHFALoadedMaxIvars',
            'kHFALoadedMaxProperties', 'implementationRVAHex', 'structuralFields',
        ):
            self.assertIn(token, SRC)
        for forbidden in ('objc_msgSend', 'method_setImplementation', 'method_invoke', 'vm_write', 'DobbyHook', 'DobbyInstrument'):
            self.assertNotIn(forbidden, SRC)
        self.assertIn('@"memoryWritten": @NO', SRC)
        self.assertIn('@"selectorInvoked": @NO', SRC)
        self.assertIn('@"objectInstanceDereferenced": @NO', SRC)

    def test_picker_runs_static_and_loaded_evidence_together(self):
        self.assertIn('HFAMapAnalyzeImportedDylibEvidence', BUNDLE)
        self.assertIn('HFAMapResolveLoadedDylibEvidence', BUNDLE)
        self.assertIn('HFAMapPersistLoadedDylibEvidence', BUNDLE)
        self.assertIn('loadedRuntimeEvidence', BUNDLE)
        self.assertIn('LoadedDylibEvidenceResolver.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
