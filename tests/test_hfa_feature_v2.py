import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "tools" / "validate_hfa_feature_v2.py")
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def load(name):
    return json.loads((ROOT / "schema" / "examples" / name).read_text())


class FeatureV2Tests(unittest.TestCase):
    def test_v1_compatibility_fixture(self):
        validator.validate_package(load("legacy-v1-compat.json"))

    def test_dragons_bytepatch_v2(self):
        validator.validate_package(load("dragons-bytepatch-v2.json"))

    def test_wayofkings_runtime_v2(self):
        validator.validate_package(load("wayofkings-runtime-v2.json"))

    def test_bytepatch_rejects_empty_patch_list(self):
        pkg = load("dragons-bytepatch-v2.json")
        pkg["features"][0]["execution"]["patches"] = []
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(pkg)

    def test_unknown_execution_requires_provider(self):
        pkg = load("dragons-bytepatch-v2.json")
        pkg["features"][0]["execution"] = {"kind": "futureThing"}
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(pkg)
        pkg["features"][0]["execution"]["provider"] = "com.example.future"
        validator.validate_package(pkg)

    def test_runtime_binding_must_exist(self):
        pkg = load("wayofkings-runtime-v2.json")
        pkg["features"][0]["execution"]["binding"] = "missing"
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(pkg)

    def test_one_shot_button_must_not_have_default(self):
        pkg = load("wayofkings-runtime-v2.json")
        debug = pkg["features"][3]
        debug["control"]["default"] = False
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(pkg)


if __name__ == "__main__":
    unittest.main()

class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bridge_spec = importlib.util.spec_from_file_location("bridge", ROOT / "tools" / "hfa_feature_bridge.py")
        cls.bridge = importlib.util.module_from_spec(bridge_spec)
        bridge_spec.loader.exec_module(cls.bridge)

    def test_v1_to_v2_roundtrip_bytepatch(self):
        v1 = load("legacy-v1-compat.json")
        v2 = self.bridge.v1_to_v2(v1)
        validator.validate_package(v2)
        back = self.bridge.v2_bytepatch_to_v1(v2)
        validator.validate_package(back)
        self.assertEqual(back["features"][0]["patches"], v1["features"][0]["patches"])

    def test_dragons_v2_projects_to_existing_v1_consumer_shape(self):
        v2 = load("dragons-bytepatch-v2.json")
        v1 = self.bridge.v2_bytepatch_to_v1(v2)
        validator.validate_package(v1)
        self.assertEqual(v1["features"][0]["patches"][0]["offset"], "0x1007E5390")

    def test_runtime_feature_refuses_v1_projection(self):
        v2 = load("wayofkings-runtime-v2.json")
        with self.assertRaises(self.bridge.BridgeError):
            self.bridge.v2_bytepatch_to_v1(v2, ["god_mode"])
