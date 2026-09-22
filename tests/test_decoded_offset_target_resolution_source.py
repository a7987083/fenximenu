from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()


def decoded_offset(text: str) -> int:
    value = text.strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    if not value or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError(value)
    return int(value, 16)


def unique_range_target(address: int, patch_length: int, images: list[dict]):
    matches = []
    for image in images:
        vmaddr, size = image["vmaddr"], image["vmsize"]
        if address < vmaddr:
            continue
        delta = address - vmaddr
        if delta > size or patch_length > size - delta:
            continue
        matches.append(image["image"])
    return matches[0] if len(matches) == 1 else None


class DecodedOffsetTargetResolutionSourceTests(unittest.TestCase):
    def test_decrypted_offsets_are_hex_with_or_without_prefix(self):
        self.assertEqual(decoded_offset("0x2DA9DE0"), 0x2DA9DE0)
        self.assertEqual(decoded_offset("1007E5390"), 0x1007E5390)
        self.assertEqual(decoded_offset("100813348"), 0x100813348)
        self.assertNotEqual(decoded_offset("100813348"), 100813348)

    def test_rise_offsets_uniquely_map_to_main_executable(self):
        images = [
            {"image": "Dragons-prod-remote-nocheat", "vmaddr": 0x100000000, "vmsize": 0x2864000},
            {"image": "libRiseofBerk.dylib", "vmaddr": 0, "vmsize": 0x434000},
        ]
        for address, length in (
            (0x1007E5390, 4), (0x100813348, 8), (0x100813994, 8),
            (0x101034B64, 4), (0x10089D49C, 4), (0x1002307F8, 8),
            (0x100819ABC, 4), (0x10088EFE0, 8),
        ):
            self.assertEqual(
                unique_range_target(address, length, images),
                "Dragons-prod-remote-nocheat",
            )

    def test_zero_ambiguous_and_cross_boundary_matches_fail_closed(self):
        self.assertIsNone(unique_range_target(0x3000, 4, [
            {"image": "main", "vmaddr": 0x1000, "vmsize": 0x1000},
        ]))
        self.assertIsNone(unique_range_target(0x1800, 4, [
            {"image": "a", "vmaddr": 0x1000, "vmsize": 0x1000},
            {"image": "b", "vmaddr": 0x1800, "vmsize": 0x1000},
        ]))
        self.assertIsNone(unique_range_target(0x1FFF, 2, [
            {"image": "main", "vmaddr": 0x1000, "vmsize": 0x1000},
        ]))

    def test_source_keeps_generic_parser_separate_and_exports_evidence(self):
        for token in (
            "HFADecodedOffsetValue",
            "strtoull(raw, &end, 16)",
            "HFAExecutableImageResolutionForDecoded",
            '"decoded-offset-executable-range"',
            '"unique-offset-executable-range"',
            '"preferred-mach-o-vmaddr"',
            '"targetResolution"',
            '"decoded-offset-hex-normalized"',
            '"unique-target-image"',
        ):
            self.assertIn(token, RESOLVER)
        self.assertIn("NSNumber *offset = HFADecodedOffsetValue(offsetText)", RESOLVER)
        self.assertIn("if (!targetImage.length)", RESOLVER)


if __name__ == "__main__":
    unittest.main()
