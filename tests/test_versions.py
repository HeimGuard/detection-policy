"""The order of versions: the vectors are the same file as in Laravel-MDM-Server (tests/fixtures/version-vectors.json)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import feed  # noqa: E402

VECTORS = json.loads((Path(__file__).parent / "version-vectors.json").read_text())["order"]


class VersionOrderTest(unittest.TestCase):
    def test_vectors(self):
        for a, op, b in VECTORS:
            with self.subTest(f"{a!r} {op} {b!r}"):
                ka, kb = feed.version_tuple(a), feed.version_tuple(b)
                if op == "null":
                    self.assertTrue(ka is None or kb is None)
                    continue
                self.assertIsNotNone(ka)
                self.assertIsNotNone(kb)
                want = {"<": -1, "=": 0, ">": 1}[op]
                self.assertEqual(feed.version_compare(ka, kb), want)
                self.assertEqual(feed.version_compare(kb, ka), -want)

    def test_operators_use_it(self):
        item = {"Name": "openssl", "Version": "1.1.1k"}
        self.assertTrue(feed.test({"field": "Version", "op": "version_lt", "value": "1.1.1w"}, item))
        self.assertFalse(feed.test({"field": "Version", "op": "version_lt", "value": "1.1.1k"}, item))
        self.assertTrue(feed.test({"field": "Version", "op": "version_lt", "value": "2.0"}, {"Version": "2.0-rc1"}))


if __name__ == "__main__":
    unittest.main()
