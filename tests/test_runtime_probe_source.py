from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()
PROBE = (ROOT / "hfamap/src/HFAMapRuntimeProbe.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
ENTRY = (ROOT / "hfamap/src/HFAMapEntry.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class RuntimeProbeSourceTests(unittest.TestCase):
    def test_block_semantic_classifier_is_bounded_and_noncanonical(self):
        for token in (
            "HFAClassifyBlockInvoke", "HFAResolveARM64StubTarget",
            "nonsemantic-logging-block", "runtime-action-dispatch-chain",
            "runtime-action-target-resolved", "preferredTargetRVA",
            "image-slide-plus-preferred-vm-rva", "nestedBlock",
            '@"canonicalEligible": @NO', '@"instructionWindowBytes"',
        ):
            self.assertIn(token, RESOLVER)
        for forbidden in (
            "method_setImplementation", "MSHookFunction(", "header.invoke(",
            "mach_vm_write", "vm_write",
        ):
            self.assertNotIn(forbidden, RESOLVER)

    def test_runtime_probe_is_explicit_bounded_and_reversible(self):
        for token in (
            "kHFAProbeMaxViews = 768", "kHFAProbeMaxControls = 128",
            "kHFAProbeMaxEvents = 32", "MAX(2.0, MIN(duration, 15.0))",
            "3. Runtime Probe (8s)", "targetListModifiedTemporarily",
            "targetListRestored", "removeTarget:target",
            "RuntimeProbe.json", "runtime-probe-event",
        ):
            self.assertIn(token, PROBE + ENTRY)

    def test_probe_distinguishes_and_bounds_click_switch_and_slider_events(self):
        for token in (
            "kHFAProbeMaxCallbacks = 256", '"touch-up-inside"', '"value-changed"',
            '"slider-value-changed"', '"switch-value-changed"',
            '"ambiguous-control-activation"', 'record[@"registeredControlEvents"]',
            'record[@"sliderSampleCount"]', 'record[@"sliderFirstValue"]',
            'record[@"sliderLastValue"]', 'record[@"sliderMinValue"]',
            'record[@"sliderMaxValue"]', '@"sliderEventsCoalesced": @YES',
            '@"callbackCount"', '@"com.hfa.runtime-probe/v2"',
            "HFAProbeControlHasSidecarAction", '@"targetRestoreFailureCount"',
            '@"targetListRestored": @(targetRestoreFailureCount == 0)',
        ):
            self.assertIn(token, PROBE)

    def test_custom_control_state_is_read_only_bounded_and_diffed(self):
        for token in (
            "kHFAProbeMaxStateClasses = 8", "kHFAProbeMaxStateIvars = 32",
            "HFAProbeStateLikeIvarName", "HFAProbeReadScalarIvar",
            "class_copyIvarList", "ivar_getOffset", "vm_read_overwrite",
            'stateSnapshotMode', 'stateAtArm', 'stateImmediate', 'stateSettled',
            'stateChangesAtCallback', 'stateChangesAfterEvent',
            'unknownAccessorInvoked', 'objectIvarDereferenced',
        ):
            self.assertIn(token, PROBE)
        for forbidden in ("valueForKey:", "performSelector:", "objc_msgSend"):
            self.assertNotIn(forbidden, PROBE)

    def test_scan_exports_exact_control_action_entry_provenance(self):
        for token in (
            'actionSeeds', 'exact-control-target-action', 'action-entry',
            'selected-menu-action-entry', 'actionProvenanceEvidence',
            'selectorInvokedByAnalyzer', 'registeredControlEvent', 'actionSinkClass',
            'unresolved-action-sink', 'deferred-runtime-action',
        ):
            self.assertIn(token, RESOLVER + CORE)

    def test_probe_observes_user_events_without_replacing_original_action(self):
        for token in (
            '@"originalActionContinues": @YES', '@"unknownSelectorInvoked": @NO',
            '@"impReplaced": @NO', '@"hookInstalled": @NO',
            '@"memoryWritten": @NO', "actionsForTarget:target",
        ):
            self.assertIn(token, PROBE)
        for forbidden in (
            "method_setImplementation", "class_replaceMethod", "objc_msgSend",
            "MSHookFunction(", "LHHookFunctions(", "dispatch_sync",
        ):
            self.assertNotIn(forbidden, PROBE)

    def test_probe_is_wired_to_last_policy_selected_menu(self):
        self.assertIn("gHFALastSelectedCandidate", CORE)
        self.assertIn("selected[@\"image\"]", CORE)
        self.assertIn("HFAMapArmRuntimeProbeForCandidate", CORE)
        self.assertIn("candidateIdentity", PROBE)
        self.assertIn('candidate[@"menuUUID"]', PROBE)
        self.assertIn("src/HFAMapRuntimeProbe.mm", MAKEFILE)

    def test_mrc_process_lifetime_and_arm_state_are_explicit(self):
        self.assertIn("[[NSMutableArray alloc] init]", PROBE)
        self.assertIn("gHFAProbeCompletion = [completion copy]", PROBE)
        self.assertIn("[completion release]", PROBE)
        self.assertIn("gHFAProbeGeneration", PROBE)
        self.assertIn("if (gHFAProbeArmed)", PROBE)


if __name__ == "__main__":
    unittest.main()
