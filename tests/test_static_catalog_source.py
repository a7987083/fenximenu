from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAMapStaticCatalog.mm").read_text()
HEADER = (ROOT / "hfamap/src/HFAMapStaticCatalog.h").read_text()
BRIDGE = (ROOT / "hfamap/src/HFAMapStaticCatalogBridge.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class StaticCatalogSourceTests(unittest.TestCase):
    def test_game_root_picker_and_offline_read_only_analysis(self):
        for token in (
            'HFAMapListSandboxRootDylibs',
            'NSHomeDirectory()',
            'enumerationRoot',
            'game root',
            'HFAMapStaticCatalogAnalyzeFile',
            'NSDataReadingMappedIfSafe',
            'analysisMode',
            'offline-file-read-only-no-dlopen',
            '4. Static Analyze Dylib',
        ):
            self.assertIn(token, SOURCE + HEADER + ENTRY)
        self.assertNotIn('dlopen(', SOURCE)
        self.assertNotIn('NSBundle bundleWithPath', SOURCE)

    def test_macho_identity_and_function_catalog_are_generic(self):
        for token in (
            'LC_UUID',
            'LC_FUNCTION_STARTS',
            'CPU_TYPE_ARM64',
            'com.hfa.static-catalog/v1',
            'com.hfa.static-runtime-method/v1',
            'assembly-like',
            'qualified-type-like',
            'identifier-like',
            'indirectCallCount',
            'callbackRVA',
            'no-sample-name-no-sample-rva-no-known-method-input',
        ):
            self.assertIn(token, SOURCE)
        for forbidden in ('CheatGetMoney', 'CheatLevelUp', 'XPHero', '0xB8B608', '0xB8BA50'):
            self.assertNotIn(forbidden, SOURCE + BRIDGE)

    def test_same_session_registration_and_runtime_lookup(self):
        for token in (
            'HFAMapStaticCatalogRegisterAndPersist',
            'gHFAStaticCatalog',
            'HFAMapStaticCatalogCurrent',
            'HFAMapStaticCatalogLookup',
            'same-session-static-catalog-rva',
            'HFAMapStaticCatalogAnnotateHandlerGraph',
            'staticCatalogMatchedBlockCount',
            'staticCatalogMatchedRuntimeMethodCount',
            'runtime-handler-rva-to-same-session-static-catalog',
        ):
            self.assertIn(token, SOURCE + BRIDGE + CORE)

    def test_build_includes_static_catalog_modules(self):
        self.assertIn('src/HFAMapStaticCatalog.mm', MAKEFILE)
        self.assertIn('src/HFAMapStaticCatalogBridge.mm', MAKEFILE)


if __name__ == '__main__':
    unittest.main()
