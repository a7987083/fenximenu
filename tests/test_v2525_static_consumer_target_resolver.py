from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "hfamap/src/HFAMapFeatureHandlerResolver.mm").read_text()
CONSUMER = (ROOT / "hfamap/src/HFAMapStaticConsumerTargetResolver.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
MAKE = (ROOT / "hfamap/Makefile").read_text()
BUILD = (ROOT / "hfamap/src/HFAMapBuildInfo.mm").read_text()


class StaticConsumerTargetResolver2525Tests(unittest.TestCase):
    def test_direct_native_action_is_structurally_resolved(self):
        for token in (
            "direct-native-call", "dyld_get_image_vmaddr_slide",
            "preferredTargetRVA", "instanceRequiredByCallPath",
            "dyld-slide-plus-preferred-vm-rva",
            "HFAIL2CPPMethodForRuntimeAddress",
        ):
            self.assertIn(token, HANDLER)
        for forbidden in ("DobbyHook(", "MSHookFunction(", "method_setImplementation",
                          "mach_vm_write(", "vm_write("):
            self.assertNotIn(forbidden, HANDLER)

    def test_shared_consumer_uses_exact_identifier_xrefs(self):
        for token in (
            "com.hfa.static-native-consumer/v1", "shared-native-consumer",
            "exact-feature-identifier", "static-text-xref",
            "same-native-function-boundary", "operationCandidates",
            "floatMultiplyCount", "floatDivideCount",
            "conditional-early-return",
        ):
            self.assertIn(token, CONSUMER)
        for forbidden in ("Path of Kings", "HPController", "0x3BF6D90",
                          "Damage Multiplier", "Defence Multiplier", "God Mode"):
            self.assertNotIn(forbidden, CONSUMER)

    def test_core_exports_static_consumer_evidence(self):
        self.assertIn("HFAMapResolveStaticNativeConsumers", CORE)
        self.assertIn("staticNativeConsumerEvidence", CORE)
        self.assertIn("static-native-consumer", CORE)

    def test_build_identity_and_sources(self):
        self.assertIn("src/HFAMapStaticConsumerTargetResolver.mm", MAKE)
        self.assertIn("src/HFAMapVersion2525.mm", MAKE)
        self.assertTrue("2.5.25-dev" in BUILD or "2.5.27-dev" in BUILD)
        self.assertTrue("2.5.25-dev-static-consumer-target-resolver" in BUILD or
                        "2.5.27-dev-native-consumer-target-bridge" in BUILD)


if __name__ == "__main__":
    unittest.main()
