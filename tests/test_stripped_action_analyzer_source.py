from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = (ROOT / "hfamap/src/HFAMapStrippedActionAnalyzer.mm").read_text()
INVENTORY = (ROOT / "hfamap/src/HFAMapObjCActionInventory.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()


class StrippedActionAnalyzerSourceTests(unittest.TestCase):
    def test_arm64_reference_and_call_instructions_are_supported(self):
        for token in (
            "0x90000000U", "0x10000000U", "0x91000000U", "0xf9400000U",
            "0xd2800000U", "0xf2800000U", "0x94000000U", "0xd63f0000U",
            "0xd61f0000U", "0xaa0003e0U", "0x58000000U", "0xf8400000U",
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
            "read-only-bounded-cfg-no-hook-no-selector-invocation-no-memory-write",
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
        self.assertIn('assembly-csharp-containing-method-range', ACTION)
        self.assertIn('verify.dylib-native-dispatch-register-context-plus-h5gg-1.9.6-offset-to-method', ACTION)

    def test_objc_runtime_targets_are_classified_without_invocation(self):
        for token in (
            'com.hfa.stripped-action/v6', 'HFARuntimeTargetClassification',
            'objc-runtime-dispatch', 'objcRuntimeDispatchCount', 'objcRuntimeDispatches',
            'dlsym-known-objc-runtime-match', 'x1-selector-candidate',
            'x0-receiver-provenance', 'bounded-x1-cstring-read',
            'objc_msgSend', 'objc_opt_isKindOfClass',
        ):
            self.assertIn(token, ACTION)
        self.assertNotIn('objc_msgSend(', ACTION)
        self.assertNotIn('method_invoke', ACTION)

    def test_call_return_and_objc_message_chain_are_explicit(self):
        for token in (
            'HFARegCallResult', 'HFAClobberCallerSaved', 'arm64-call-return-clobber-model',
            'HFASummarizeSameImageTailStub', 'objc-message-send-stub',
            'objc-message-chain', 'messageChains', 'objcMessageChainCount',
            'arm64-x0-return-provenance', 'returnProvenance',
        ):
            self.assertIn(token, ACTION)

    def test_post_call_stack_and_type_branch_provenance_are_explicit(self):
        for token in (
            'kHFAMaxStackSlots = 64', 'post-call-register-provenance',
            'post-call-stack-slot-provenance', 'str-uimm-sp-provenance',
            'stur-sp-provenance', 'condition-provenance', 'type-branch-resolver',
            'typeBranches', 'typeBranchCount', 'cmp-immediate', 'cmp-register',
            'csel-provenance', 'type-or-call-result-zero-test',
            'cmp-subs-conditioned-type-branch',
        ):
            self.assertIn(token, ACTION)

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
        self.assertIn("src/HFAIL2CPPMethodRangeIndex.mm", MAKEFILE)


if __name__ == "__main__":
    unittest.main()
