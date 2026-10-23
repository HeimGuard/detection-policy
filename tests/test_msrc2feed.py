"""Unit tests of the MSRC rule generator: python -m unittest discover -s tests -p 'test_*.py'"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import feed  # noqa: E402
import msrc2feed  # noqa: E402

PRODUCTS = [
    {"ProductID": "1", "CPE": "cpe:2.3:o:microsoft:windows_10_22H2:*:*:*:*:*:*:x64:*", "Value": "Windows 10 Version 22H2 for x64-based Systems"},
    {"ProductID": "2", "CPE": "cpe:2.3:o:microsoft:windows_10_22H2:*:*:*:*:*:*:*:*", "Value": "Windows 10 Version 22H2 for 32-bit Systems"},
    {"ProductID": "3", "CPE": "cpe:2.3:a:microsoft:windows_11_version_26h2_for_x64-based_systems:*:*:*:*:*:*:*:*", "Value": "Windows 11 Version 26H2 for x64-based Systems"},
    {"ProductID": "4", "CPE": "cpe:2.3:a:microsoft:microsoft_edge_chromium-based:*:*:*:*:*:*:*:*", "Value": "Microsoft Edge (Chromium-based)"},
    {"ProductID": "5", "CPE": "cpe:2.3:a:microsoft:visual_studio_code:*:*:*:*:*:*:*:*", "Value": "Visual Studio Code"},
    {"ProductID": "6", "CPE": "cpe:2.3:a:microsoft:windows_admin_center:*:*:*:*:*:*:*:*", "Value": "Windows Admin Center"},
    {"ProductID": "7", "CPE": "cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*", "Value": "Microsoft 365 Apps"},
    {"ProductID": "8", "CPE": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*", "Value": "Windows Server 2022 (Server Core installation)"},
]


def vulnerability(cve, severity, fixes, exploited=False):
    return {"CVE": cve,
            "Threats": [{"Type": 3, "Description": {"Value": severity}, "ProductID": [pid for pid, _ in fixes]},
                        {"Type": 1, "Description": {"Value": f"Publicly Disclosed:No;Exploited:{'Yes' if exploited else 'No'}"}, "ProductID": [pid for pid, _ in fixes]},
                        {"Type": 0, "Description": {}}],
            "Remediations": [{"Type": 2, "FixedBuild": build, "ProductID": [pid]} for pid, build in fixes]}


DOC = {"ProductTree": {"FullProductName": PRODUCTS}, "Vulnerability": [
    vulnerability("CVE-2026-1", "Important", [("1", "10.0.19045.7807"), ("2", "10.0.19045.7807"), ("8", "10.0.20348.5761")]),
    vulnerability("CVE-2026-2", "Critical", [("1", "10.0.19045.7548"), ("3", "10.0.26300.9711")], exploited=True),
    vulnerability("CVE-2026-3", "Moderate", [("4", "155.0.4283.45")]),
    vulnerability("CVE-2026-4", "Low", [("4", "156.0.4314.42"), ("5", "1.141.1")]),
    vulnerability("CVE-2026-5", "Important", [("6", "2.4.2.1234"), ("7", "https://aka.ms/OfficeSecurityReleases")]),
]}


def state(*docs):
    return {"docs": {f"doc{i}": {"released": "x", "families": msrc2feed.extract(doc)} for i, doc in enumerate(docs)}}


def findings(rules, item):
    return sorted(r["name"].split(" older")[0] for r in rules.values() if feed.test(r["when"], item))


class Extract(unittest.TestCase):
    def test_only_the_families_that_can_be_told_are_taken(self):
        families = msrc2feed.extract(DOC)
        self.assertEqual({"windows:10.0.19045", "windows:10.0.20348", "windows:10.0.26300", "edge", "vscode"}, set(families))
        win = families["windows:10.0.19045"]
        self.assertEqual(("10.0.19045.7807", 2), (win["fixed"], win["n"]))
        self.assertEqual(["Windows 10 Version 22H2"], win["names"])  # for x64 / 32-bit is not part of the name
        self.assertEqual(["CVE-2026-2", "CVE-2026-1"], [c[0] for c in win["top"]])  # exploited first
        self.assertEqual([["CVE-2026-2", "critical", True, "10.0.19045.7548"]], [c for c in win["top"] if c[0] == "CVE-2026-2"])
        # Admin Center (not an operating system), Office (a link, no build) and the like are not.
        self.assertFalse([f for f in families if "admin" in f or "365" in f])


class Rules(unittest.TestCase):
    def test_windows_by_its_build(self):
        rules, fixtures, skipped = msrc2feed.generate(state(DOC))
        self.assertEqual([], skipped)
        os_item = lambda version, source="windows", name="Microsoft Windows 10 Pro": {"Name": name, "Version": version, "Source": source}
        self.assertEqual(["Windows 10 Version 22H2 (build 10.0.19045)"], findings(rules, os_item("10.0.19045.5555")))
        self.assertEqual([], findings(rules, os_item("10.0.19045.7807")))
        self.assertEqual([], findings(rules, os_item("10.0.19045.9000")))
        # Another build, and a program that is no operating system, are not it.
        self.assertEqual(["Windows Server 2022 (build 10.0.20348)"], findings(rules, os_item("10.0.20348.1", name="Microsoft Windows Server 2022 Standard")))
        self.assertEqual([], findings(rules, os_item("10.0.19045.5555", "registry")))
        self.assertEqual([], findings(rules, os_item("10.0.22000.1")))
        rule = rules["org.msrc-windows-10-0-19045"]
        self.assertIn("CVE-2026-2 (exploited, fixed in 10.0.19045.7548)", rule["message"])
        self.assertEqual("critical", rule["severity"])
        self.assertEqual("windows", rule["platform"])
        for fixture in fixtures.values():
            self.assertTrue(fixture["positive"] and fixture["negative"])

    def test_edge_and_visual_studio_code(self):
        rules, _, _ = msrc2feed.generate(state(DOC))
        item = lambda name, version, source="registry", **more: {"Name": name, "Version": version, "Source": source, **more}
        self.assertEqual(["Microsoft Edge"], findings(rules, item("Microsoft Edge", "154.0.4258.37")))
        self.assertEqual([], findings(rules, item("Microsoft Edge", "156.0.4314.42")))
        self.assertEqual(["Microsoft Edge"], findings(rules, item("microsoft-edge-stable", "154.0.4258.37-1", "dpkg")))
        self.assertEqual([], findings(rules, item("Microsoft Edge WebView2 Runtime", "154.0.4258.37")))
        self.assertEqual(["Visual Studio Code"], findings(rules, item("Microsoft Visual Studio Code (User)", "1.140.0", "registry (user)")))
        self.assertEqual(["Visual Studio Code"], findings(rules, item("code", "1.140.0-1792691907", "dpkg")))
        self.assertEqual([], findings(rules, item("code", "1.140.0", "registry")))
        self.assertEqual([], findings(rules, item("Microsoft Visual Studio Code", "1.141.1")))

    def test_the_updates_of_the_window_are_merged_and_a_build_is_older_than_the_newest_fix(self):
        newer = {"ProductTree": {"FullProductName": PRODUCTS}, "Vulnerability": [vulnerability("CVE-2026-9", "Critical", [("1", "10.0.19045.8000")])]}
        rules, _, _ = msrc2feed.generate(state(DOC, newer))
        rule = rules["org.msrc-windows-10-0-19045"]
        self.assertIn("older than 10.0.19045.8000", rule["name"])
        self.assertIn("3 CVEs", rule["name"])
        self.assertEqual(1, len(findings(rules, {"Name": "Windows", "Version": "10.0.19045.7807", "Source": "windows"})))
        self.assertEqual("critical", rule["severity"])

    def test_the_rules_are_valid_for_the_server(self):
        rules, _, _ = msrc2feed.generate(state(DOC))
        for rule in rules.values():
            self.assertEqual([], feed.rule_errors(rule, False), rule["key"])
            self.assertLessEqual(len(rule["name"]), 120)


if __name__ == "__main__":
    unittest.main()
