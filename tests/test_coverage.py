import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import coverage  # noqa: E402


class CoverageTest(unittest.TestCase):
    def test_a_rule_recognises_what_it_is_about_and_the_rest_is_listed(self):
        rule = {"key": "org.t", "source": "software", "select": {"field": "Name", "op": "eq", "value": "openssl"},
                "cves": [{"id": "CVE-2000-1", "severity": "high", "ranges": [["1.1.1", "1.1.1w", None]]}]}
        silent = {"key": "org.silent", "source": "software", "when": {"field": "Name", "op": "eq", "value": "nothing"}}
        items = [{"Name": "openssl", "Version": "1.1.1k", "Source": "x"}, {"Name": "openssl", "Version": "1.1.1w", "Source": "x"},
                 {"Name": "Mystery Tool", "Version": "1", "Source": "x"}]
        result = coverage.measure(items, [rule, silent])
        self.assertEqual((3, 2, 1), (result["items"], result["recognised"], result["vulnerable"]))
        self.assertEqual(["org.silent"], result["silent_rules"])
        self.assertEqual({"mystery tool": 1}, dict(result["unmatched"]))


if __name__ == "__main__":
    unittest.main()
