from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "hfamap/src/HFAMapDirectedDescriptorResolver.mm").read_text()
HDR = (ROOT / "hfamap/src/HFAMapDirectedDescriptorResolver.h").read_text()
BUNDLE = (ROOT / "hfamap/src/HFAMapBundleRootScanner.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class DirectedDescriptorSourceTests(unittest.TestCase):
    def test_universal_read_only_policy(self):
        self.assertIn('UNIVERSAL-DIRECTED-READ-ONLY-NO-SAMPLE-SPECIAL-CASES', SRC)
        for forbidden in ('RogueLegend', 'Damage Multiplier', 'Defence Multiplier', 'God Mode',
                          'Skip Battles', 'VIP Enabled', '0x31AFD14', '0x3593500',
                          'DobbyHook', 'method_setImplementation', 'vm_write', 'objc_msgSend'):
            self.assertNotIn(forbidden, SRC)
        self.assertIn('@"unknownSelectorInvoked": @NO', SRC)
        self.assertIn('@"memoryWritten": @NO', SRC)
        self.assertIn('@"gameStateWritten": @NO', SRC)

    def test_real_ui_controls_and_targets_seed_graph(self):
        for token in ('UIApplication.sharedApplication.windows', 'control.allTargets',
                      'control.superview', 'seedObjects', 'kHFADirectedMaxDepth = 8',
                      'kHFADirectedMaxNodes = 1024'):
            self.assertIn(token, SRC)

    def test_feature_keys_come_from_runtime_objects(self):
        self.assertIn('control-object-string', SRC)
        self.assertIn('target-object-string', SRC)
        self.assertIn('featureKeys', SRC)
        self.assertIn('HFANormalizedKeyDD', SRC)
        self.assertIn('descriptorMatches', SRC)
        self.assertIn('runtime-descriptor-correlated', SRC)

    def test_descriptor_shape_understands_wrapper_objects(self):
        for token in ('address-field', 'patch-field', 'target-image-field',
                      'signature-field', 'manager-field', 'roleObjects',
                      'patch-descriptor-candidate'):
            self.assertIn(token, SRC)
        self.assertIn('@"verified": @NO', SRC)
        self.assertIn('@"canonicalEligible": @NO', SRC)

    def test_foundation_containers_are_bounded(self):
        self.assertIn('kHFADirectedMaxContainerItems = 96', SRC)
        for cls in ('NSArray.class', 'NSDictionary.class', 'NSSet.class'):
            self.assertIn(cls, SRC)

    def test_bundle_wires_directed_output(self):
        self.assertIn('HFAMapDirectedDescriptorResolver.mm', MAKEFILE)
        self.assertIn('HFAMapResolveDirectedDescriptors', BUNDLE)
        self.assertIn('HFAMapPersistDirectedDescriptors', BUNDLE)
        self.assertIn('HFAMap v2.5.10', BUNDLE)
        self.assertIn('DirectedDescriptors.json', SRC)
        self.assertIn('com.hfa.directed-descriptor/v1', SRC)


if __name__ == '__main__':
    unittest.main()
