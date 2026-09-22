from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()
CORE = (ROOT / "hfamap/src/HFAMapCore.mm").read_text()


def decode_block_header(raw):
    if len(raw) < 32:
        return None
    isa, flags, reserved, invoke, descriptor = struct.unpack("<QiiQQ", raw[:32])
    if not invoke or invoke & 3:
        return None
    return {
        "isa": isa,
        "flags": flags & 0xFFFFFFFF,
        "invoke": invoke,
        "descriptor": descriptor,
        "is_global": bool(flags & (1 << 28)),
        "has_signature": bool(flags & (1 << 30)),
    }


class BlockProvenanceSourceTests(unittest.TestCase):
    def test_block_abi_header_layout_and_flags(self):
        raw = struct.pack("<QiiQQ", 0x1000, (1 << 28) | (1 << 30), 0,
                          0x12345678, 0x87654320)
        decoded = decode_block_header(raw)
        self.assertEqual(decoded["invoke"], 0x12345678)
        self.assertTrue(decoded["is_global"])
        self.assertTrue(decoded["has_signature"])
        self.assertIsNone(decode_block_header(raw[:24]))
        self.assertIsNone(decode_block_header(struct.pack("<QiiQQ", 1, 0, 0, 3, 4)))

    def test_probe_is_bounded_read_only_and_exports_provenance(self):
        for token in (
            "HFABlockLiteralHeader", "HFAReadOnlyBlockProvenance",
            "sizeof(header)", "invokeInstructionPrefix", "menu-invoke-resolved",
            "ownerIvarOffset", "same-ui-target-object-graph",
            "blockProvenanceRecords", "menuBlockInvokes",
            "blockProvenanceEvidence", "missing-offset-block",
        ):
            self.assertIn(token, RESOLVER + CORE)
        for token in ('@"invoked": @NO', '@"copied": @NO', '@"released": @NO',
                      '@"hookInstalled": @NO', '@"memoryWritten": @NO',
                      '@"canonicalEligible": @NO'):
            self.assertIn(token, RESOLVER)

    def test_probe_does_not_invoke_or_mutate_blocks(self):
        for forbidden in (
            "Block_copy(", "Block_release(", "_Block_copy(", "_Block_release(",
            "header.invoke(", "mach_vm_write", "vm_write", "MSHookFunction(",
        ):
            self.assertNotIn(forbidden, RESOLVER)

    def test_dyld_stub_resolution_has_symbol_table_independent_fallback(self):
        self.assertIn('dlsym(RTLD_DEFAULT, known[index])', RESOLVER)
        self.assertIn('"_dyld_get_image_vmaddr_slide"', RESOLVER)
        self.assertIn('"dyld_get_image_vmaddr_slide"', RESOLVER)
        self.assertIn('if (address && (uintptr_t)address == symbolAddress)', RESOLVER)


if __name__ == "__main__":
    unittest.main()
