import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("triage", ROOT / "tools/hfamap_macho_triage.py")
TRIAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TRIAGE
SPEC.loader.exec_module(TRIAGE)


def fixture(tokens: bytes) -> bytes:
    section_offset = 32 + 72 + 80
    cmdsize = 72 + 80
    header = struct.pack("<8I", TRIAGE.MH_MAGIC_64, 0x0100000C, 0, 6, 1, cmdsize, 0, 0)
    segment = struct.pack("<II16sQQQQIIII", TRIAGE.LC_SEGMENT_64, cmdsize, b"__TEXT\0" * 2,
                          0, 0x10000, 0, section_offset + len(tokens), 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__cstring\0\0\0\0\0\0", b"__TEXT\0" * 2,
                          0x1000, len(tokens), section_offset, 0, 0, 0, 0, 0, 0, 0)
    return header + segment + section + tokens


class MachOTriageTests(unittest.TestCase):
    def analyze(self, tokens: bytes):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.dylib"
            path.write_bytes(fixture(tokens))
            return TRIAGE.analyze(path)

    def test_legacy_family_requires_ui_and_descriptor_evidence(self):
        result = self.analyze(b"addButtonWithTitle:\0customSwitch\0APPatchItem\0APSubpatchManager\0")
        self.assertEqual("legacy-ap", result["family"])
        self.assertGreaterEqual(result["score"], 50)

    def test_jailpatch_family(self):
        result = self.analyze(b"addButtonWithTitle:\0customSwitch\0JailpatchConfigValidator\0OffsetInstruction\0")
        self.assertEqual("jailpatch", result["family"])

    def test_descriptor_strings_without_menu_ui_are_not_candidates(self):
        result = self.analyze(b"JailpatchConfigValidator\0OffsetInstruction\0")
        self.assertEqual("unknown", result["family"])
        self.assertEqual(0, result["score"])

    def test_truncated_command_is_rejected(self):
        with self.assertRaises(TRIAGE.ParseError):
            TRIAGE.parse_macho(struct.pack("<8I", TRIAGE.MH_MAGIC_64, 0, 0, 0, 1, 8, 0, 0) + b"\x19\0\0\0\xff\xff\xff\xff")


if __name__ == "__main__":
    unittest.main()
