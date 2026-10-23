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
    {"ProductID": "9", "CPE": "cpe:2.3:o:microsoft:windows_server_2012_R2:*:*:*:*:*:*:*:*", "Value": "Windows Server 2012 R2"},
]


def vulnerability(cve, severity, fixes, exploited=False):
    return {"CVE": cve,
            "Threats": [{"Type": 3, "Description": {"Value": severity}, "ProductID": [pid for pid, _ in fixes]},
                        {"Type": 1, "Description": {"Value": f"Publicly Disclosed:No;Exploited:{'Yes' if exploited else 'No'}"}, "ProductID": [pid for pid, _ in fixes]},
                        {"Type": 0, "Description": {}}],
            "Remediations": [{"Type": 2, "FixedBuild": build, "ProductID": [pid]} for pid, build in fixes]}


def document(*vulnerabilities):
    return {"ProductTree": {"FullProductName": PRODUCTS}, "Vulnerability": list(vulnerabilities)}


DOC = document(
    vulnerability("CVE-2026-1", "Important", [("1", "10.0.19045.7807"), ("2", "10.0.19045.7807"), ("8", "10.0.20348.5761")]),
    vulnerability("CVE-2026-2", "Critical", [("1", "10.0.19045.7548"), ("3", "10.0.26300.9711")], exploited=True),
    vulnerability("CVE-2026-3", "Moderate", [("4", "155.0.4283.45")]),
    vulnerability("CVE-2026-4", "Low", [("4", "156.0.4314.42"), ("5", "1.141.1")]),
    vulnerability("CVE-2026-5", "Important", [("6", "2.4.2.1234"), ("7", "https://aka.ms/OfficeSecurityReleases")]),
    vulnerability("CVE-2026-6", "Important", [("4", "7.1.0"), ("9", "6.3.9600.23470")]),
)


def state(*docs):
    return {"docs": {f"doc{i}": {"released": "x", "initial": f"2026-0{i + 1}", **msrc2feed.extract(doc)} for i, doc in enumerate(docs)}}


def rules_of(*docs):
    rules, _, skipped = msrc2feed.generate(state(*docs))
    assert skipped == [], skipped
    return rules


def findings(rules, item, source):
    return sorted(r["key"] for r in rules.values() if r["source"] == source and feed.test(r["when"], item))


def os_item(version, id="windows"):
    return {"Id": id, "Name": "Microsoft Windows", "Version": version}


class Extract(unittest.TestCase):
    def test_only_what_can_be_told_is_taken(self):
        doc = msrc2feed.extract(DOC)
        self.assertEqual({"windows:10.0.19045", "windows:10.0.20348", "windows:10.0.26300", "edge", "vscode"}, set(doc["families"]))
        self.assertEqual({"10.0.19045.7548": "2026-2:cx", "10.0.19045.7807": "2026-1:h"}, doc["families"]["windows:10.0.19045"])
        self.assertEqual(["Windows 10 Version 22H2"], doc["names"]["windows:10.0.19045"])  # for x64 / 32-bit is not part of the name
        # Admin Center (not an operating system), Office (a link, no build), Edge for iOS (7.1.0), Server 2012 R2 (6.3) are not.
        self.assertFalse([f for f in doc["families"] if "admin" in f or "365" in f or "6.3" in f])
        self.assertEqual({"155.0.4283.45": "2026-3:m", "156.0.4314.42": "2026-4:l"}, doc["families"]["edge"])


class Rules(unittest.TestCase):
    def test_a_rule_is_a_missing_update_and_a_host_sees_the_updates_it_lacks(self):
        rules = rules_of(DOC)
        both = {"org.msrc-windows-10-0-19045-7548", "org.msrc-windows-10-0-19045-7807"}
        # Two updates are missing: two findings, each with the CVEs it fixes.
        self.assertEqual(sorted(both), findings(rules, os_item("10.0.19045.5555"), "os"))
        # Only the newest is missing: one finding, and the CVE the older update fixed is not in it.
        self.assertEqual(["org.msrc-windows-10-0-19045-7807"], findings(rules, os_item("10.0.19045.7548"), "os"))
        self.assertEqual([], findings(rules, os_item("10.0.19045.7807"), "os"))
        self.assertEqual([], findings(rules, os_item("10.0.19045.9000"), "os"))
        old, new = rules["org.msrc-windows-10-0-19045-7548"], rules["org.msrc-windows-10-0-19045-7807"]
        self.assertEqual(("critical", "high"), (old["severity"], new["severity"]))  # by what the update fixes
        self.assertIn("CVE-2026-2 (exploited)", old["message"])
        self.assertNotIn("CVE-2026-2", new["message"])
        self.assertEqual("os", old["source"])
        self.assertEqual("windows", old["platform"])
        # Another build and a system of another family are not it.
        self.assertEqual(["org.msrc-windows-10-0-20348-5761"], findings(rules, os_item("10.0.20348.1"), "os"))
        self.assertEqual([], findings(rules, os_item("10.0.22000.1"), "os"))
        self.assertEqual([], findings(rules, os_item("10.0.19045.5555", "ubuntu"), "os"))
        self.assertEqual([], findings(rules, {"Name": "Microsoft Windows", "Version": "10.0.19045.5555", "Source": "windows"}, "software"))

    def test_edge_and_visual_studio_code(self):
        rules = rules_of(DOC)
        item = lambda name, version, source="registry": {"Name": name, "Version": version, "Source": source}
        self.assertEqual(["org.msrc-edge-155-0-4283-45", "org.msrc-edge-156-0-4314-42"], findings(rules, item("Microsoft Edge", "154.0.4258.37"), "software"))
        self.assertEqual(["org.msrc-edge-156-0-4314-42"], findings(rules, item("Microsoft Edge", "155.0.4283.45"), "software"))
        self.assertEqual([], findings(rules, item("Microsoft Edge", "156.0.4314.42"), "software"))
        self.assertEqual(["org.msrc-edge-156-0-4314-42"], findings(rules, item("microsoft-edge-stable", "155.0.4283.60-1", "dpkg"), "software"))
        self.assertEqual([], findings(rules, item("Microsoft Edge WebView2 Runtime", "154.0.4258.37"), "software"))
        self.assertEqual(["org.msrc-vscode-1-141-1"], findings(rules, item("Microsoft Visual Studio Code (User)", "1.140.0", "registry (user)"), "software"))
        self.assertEqual(["org.msrc-vscode-1-141-1"], findings(rules, item("code", "1.140.0-1792691907", "dpkg"), "software"))
        self.assertEqual([], findings(rules, item("code", "1.140.0", "registry"), "software"))
        self.assertEqual([], findings(rules, item("Microsoft Visual Studio Code", "1.141.1"), "software"))

    def test_a_cve_two_updates_list_is_counted_once_by_the_newer_update(self):
        again = document(vulnerability("CVE-2026-1", "Critical", [("1", "10.0.19045.8000")]), vulnerability("CVE-2026-9", "Low", [("1", "10.0.19045.8000")]))
        rules = rules_of(DOC, again)  # the second document is the newer one
        self.assertIn("(1 CVEs)", rules["org.msrc-windows-10-0-19045-7548"]["name"])
        self.assertIn("(2 CVEs)", rules["org.msrc-windows-10-0-19045-8000"]["name"])
        self.assertNotIn("org.msrc-windows-10-0-19045-7807", rules)  # its only CVE moved to the newer update
        self.assertEqual(["org.msrc-windows-10-0-19045-7548", "org.msrc-windows-10-0-19045-8000"], findings(rules, os_item("10.0.19045.5555"), "os"))

    def test_the_rules_are_valid_for_the_server(self):
        for rule in rules_of(DOC).values():
            self.assertEqual([], feed.rule_errors(rule, False), rule["key"])
            self.assertLessEqual(len(rule["name"]), 120)


if __name__ == "__main__":
    unittest.main()
