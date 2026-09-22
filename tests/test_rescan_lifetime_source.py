from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
RESOLVER = (ROOT / "hfamap/src/HFAMapResolver.mm").read_text()


class RescanLifetimeSourceTests(unittest.TestCase):
    def test_dispatch_once_descriptor_signals_have_process_lifetime_under_mrc(self):
        self.assertIn("signals = [[NSSet alloc] initWithArray:", RESOLVER)
        self.assertIsNone(re.search(r"signals\s*=\s*\[NSSet\s+setWithArray:", RESOLVER))

    def test_dispatch_once_decrypt_cache_has_process_lifetime_under_mrc(self):
        self.assertIn("cache = [[NSMutableDictionary alloc] init]", RESOLVER)
        self.assertIsNone(re.search(r"cache\s*=\s*\[NSMutableDictionary\s+dictionary\]", RESOLVER))

    def test_no_other_dispatch_once_static_uses_known_autoreleased_constructor(self):
        patterns = (
            r"dispatch_once\([^;]+\b(?:array|dictionary|setWithArray|stringWithFormat|dataWithBytes):?",
            r"dispatch_once\([^;]+\[NSMutable(?:Array|Dictionary|Set)\s+(?:array|dictionary|set)\]",
        )
        for pattern in patterns:
            self.assertIsNone(re.search(pattern, RESOLVER, re.DOTALL))


if __name__ == "__main__":
    unittest.main()
