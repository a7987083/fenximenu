import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "hfamap/src/HFAMapHookSemantic.mm").read_text()
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()
MAKEFILE = (ROOT / "hfamap/Makefile").read_text()
FIXTURE = json.loads((ROOT / "tests/menu_hook_field_flow_fixture.json").read_text())


def decode_flow(words, field):
    words = [int(word, 16) for word in words]
    load = words[0]
    if load & 0xFFC00000 != 0xBD400000:
        return None
    load_field = ((load >> 10) & 0xFFF) * 4
    value_reg = load & 31
    base_reg = (load >> 5) & 31
    if load_field != field or base_reg == 31:
        return None
    arithmetic = words[1]
    if arithmetic & 0xFFE0FC00 != 0x1E203800:
        return None
    if arithmetic & 31 != value_reg or (arithmetic >> 5) & 31 != value_reg:
        return None
    store = words[2]
    if store & 0xFFC00000 != 0xBD000000:
        return None
    if ((store >> 10) & 0xFFF) * 4 != field:
        return None
    if store & 31 != value_reg or (store >> 5) & 31 != base_reg:
        return None
    return arithmetic.to_bytes(4, "little").hex().upper()


def coverage_complete(*, eligible_segments=1, complete_segments=1,
                      eligible_bytes=4096, scanned_bytes=4096,
                      failed_chunks=0, truncated_segments=0,
                      timed_out=False, candidate_limit_hit=False):
    return (eligible_segments > 0 and complete_segments == eligible_segments
            and not timed_out and failed_chunks == 0
            and truncated_segments == 0 and not candidate_limit_hit
            and scanned_bytes == eligible_bytes)


class MenuHookSemanticSourceTests(unittest.TestCase):
    def test_resolver_is_compiled_and_exported(self):
        self.assertIn("src/HFAMapHookSemantic.mm", MAKEFILE)
        self.assertIn("HFAMapResolveHookSemanticFeatures", RESOLVER)
        self.assertIn('hookSemanticEvidence', RESOLVER + CORE)
        self.assertIn('menu-hook-callback-field-dataflow', SOURCE)

    def test_menu_mapping_uses_exact_bounded_structural_evidence(self):
        for token in (
            "HFAExactCStringAddresses",
            "HFACFStringAddresses",
            "LC_FUNCTION_STARTS",
            "HFAIsConditionalBranch",
            "bounded-constant-field-write",
            "kHFAMaxSemanticMappings = 32",
            "fieldOffset > 0x4000U",
        ):
            self.assertIn(token, SOURCE)

    def test_target_flow_requires_same_field_registers_and_unique_candidate(self):
        for token in (
            "0xbd400000U",
            "0x1e203800U",
            "0xbd000000U",
            "HFAIsStrS(store, field, valueReg, baseReg)",
            "matches.count != 1",
            "unique-field-flow-candidate",
            "same-menu-callback-field-consensus",
            "kHFAMaxSharedCallbackTargetSpan = 0x8000ULL",
            "kHFAMaxCandidatesPerField = 32",
            "kHFAMaxExecutableBytes",
        ):
            self.assertIn(token, SOURCE)

    def test_canonical_output_requires_complete_target_scan(self):
        for token in (
            'target-scan-incomplete',
            'coverageComplete',
            'eligibleSegments > 0',
            'completeSegments == eligibleSegments',
            '!timedOut',
            '!failedChunks',
            '!truncatedSegments',
            '!candidateLimitHit',
            'scannedBytes == eligibleBytes',
            'scanCoverageComplete',
            '[features removeAllObjects]',
            '[resolvedIdentifiers removeAllObjects]',
        ):
            self.assertIn(token, SOURCE)
        incomplete_gate = SOURCE.index('if (!scanCoverageComplete)')
        canonical_emit = SOURCE.index('[features addObject:feature]')
        self.assertLess(incomplete_gate, canonical_emit)

    def test_coverage_model_accepts_only_full_success(self):
        self.assertTrue(coverage_complete())
        self.assertFalse(coverage_complete(eligible_segments=0, complete_segments=0,
                                           eligible_bytes=0, scanned_bytes=0))
        self.assertFalse(coverage_complete(failed_chunks=1))
        self.assertFalse(coverage_complete(truncated_segments=1,
                                           complete_segments=0,
                                           scanned_bytes=2048))
        self.assertFalse(coverage_complete(timed_out=True))
        self.assertFalse(coverage_complete(candidate_limit_hit=True))
        self.assertFalse(coverage_complete(scanned_bytes=4092))

    def test_coverage_diagnostics_expose_each_fail_closed_reason(self):
        for token in (
            '@"eligibleSegments"', '@"completeSegments"', '@"eligibleBytes"',
            '@"attemptedBytes"', '@"scannedBytes"', '@"failedChunks"',
            '@"truncatedSegments"', '@"candidateLimitHit"',
            '@"deadlineExceeded"', '@"scanCoverage"',
        ):
            self.assertIn(token, SOURCE)

    def test_fixture_accepts_only_valid_load_fsub_store_flows(self):
        for case in FIXTURE["cases"]:
            result = decode_flow(case["words"], int(case["field"], 16))
            self.assertEqual(result is not None, case["accepted"], case["name"])
            if result is not None:
                self.assertEqual(result, case["expectedOriginalLE"])
                self.assertEqual(case["expectedEnabled"], "1F2003D5")

    def test_duplicate_target_candidates_fail_closed(self):
        candidates = ["candidate-a", "candidate-b"]
        self.assertNotEqual(len(candidates), 1)
        self.assertIn('ambiguous-target-field-flow', SOURCE)

    def test_same_callback_peer_field_removes_isolated_false_candidate(self):
        candidates = {
            0xB8: [("UnityFramework", 19, 0x1C5234C),
                   ("UnityFramework", 19, 0x2D98AC8)],
            0xBC: [("UnityFramework", 19, 0x2D9887C)],
        }
        filtered = [candidate for candidate in candidates[0xB8]
                    if any(peer[0] == candidate[0] and peer[1] == candidate[1]
                           and abs(peer[2] - candidate[2]) <= 0x8000
                           for peer in candidates[0xBC])]
        self.assertEqual(filtered, [("UnityFramework", 19, 0x2D98AC8)])

    def test_feature_dedup_is_scoped_to_identifier(self):
        self.assertIn('enriched[@"identifier"], enriched[@"targetImage"]', RESOLVER)
        self.assertIn('feature[@"identifier"],', RESOLVER)
        self.assertIn('hookFeature[@"identifier"]', RESOLVER)

    def test_runtime_path_is_observation_only(self):
        for token in ('@"memoryWritten": @NO', '@"selectorInvoked": @NO',
                      '@"hookInstalled": @NO'):
            self.assertIn(token, SOURCE)
        for forbidden in ("vm_write", "mach_vm_write", "method_setImplementation",
                          "MSHookFunction("):
            self.assertNotIn(forbidden, SOURCE)

    def test_no_earntodie_build_identity_or_known_patch_rva_is_an_input(self):
        for forbidden in (
            "2D98AC8",
            "2D9887C",
            "8654D76C-B760-34FC-BEE0-FE70AE8C95C8",
            "com.notdoppler.earntodierogue",
        ):
            self.assertNotIn(forbidden, SOURCE)


if __name__ == "__main__":
    unittest.main()
