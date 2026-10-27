"""Unit tests of the generator of the rules of the Ubuntu and Debian trackers: python -m unittest discover -s tests"""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import cves  # noqa: E402
import distro2feed as d2f  # noqa: E402
import feed  # noqa: E402


def package(name, **statuses):
    return {"name": name, "statuses": [{"release_codename": r, "status": s if isinstance(s, str) else s[0], "description": "" if isinstance(s, str) else s[1]}
                                      for r, s in statuses.items()]}


class Ubuntu(unittest.TestCase):
    def test_a_record_keeps_what_a_supported_release_has_open_or_fixed(self):
        rec = {"id": "CVE-2026-1", "priority": "high", "published": "2026-10-01T00:00:00", "packages": [
            package("openssl", noble="needed", jammy="DNE", bionic="needed", resolute=("released", "3.5.1-1ubuntu1"), focal="not-affected"),
            package("gone", jammy="DNE", noble="not-affected"),
            package("linux-aws-5.4", focal="needed"), package("linux-oem-random-flavour-123", focal="needed"), package("linux", jammy="needed")]}
        entry = d2f.ubuntu_record(rec)
        self.assertEqual("high", entry["severity"])
        self.assertEqual({"noble": ["needed", ""], "resolute": ["released", "3.5.1-1ubuntu1"]}, entry["packages"]["openssl"])
        self.assertNotIn("gone", entry["packages"])
        self.assertIn("linux-aws-5.4", entry["packages"])
        self.assertIn("linux", entry["packages"])
        self.assertNotIn("linux-oem-random-flavour-123", entry["packages"], "a kernel flavour nobody runs would be hundreds of lines")
        self.assertIsNone(d2f.ubuntu_record({"id": "CVE-2", "priority": "high", "packages": [package("x", noble="not-affected")]}))

    def test_two_releases_of_one_cve_are_put_together(self):
        state = {}
        d2f.merge(state, "CVE-1", {"severity": "high", "published": "2026-10-01", "packages": {"foo": {"noble": ["needed", ""]}}})
        d2f.merge(state, "CVE-1", {"severity": "high", "published": "2026-10-01", "packages": {"foo": {"jammy": ["needed", ""]}, "bar": {"jammy": ["released", "1-1"]}}})
        self.assertEqual({"foo": {"jammy": ["needed", ""], "noble": ["needed", ""]}, "bar": {"jammy": ["released", "1-1"]}}, state["CVE-1"]["packages"])


class Debian(unittest.TestCase):
    DATA = {
        "foo": {"CVE-2026-5": {"releases": {"bookworm": {"status": "open", "urgency": "medium"}, "trixie": {"status": "resolved", "fixed_version": "1.0-2", "urgency": "high"},
                                            "sid": {"status": "open", "urgency": "high"}, "bullseye": {"status": "open", "urgency": "unimportant"}}}},
        "bar": {"CVE-2020-1": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "2-1", "urgency": "high"}}},
                "CVE-2025-2": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "2-2", "urgency": "high"}}},
                "CVE-2019-3": {"releases": {"bookworm": {"status": "open", "urgency": "low"}}}},
        "linux": {"CVE-2026-9": {"releases": {"bookworm": {"status": "open", "urgency": "high"}}}},
        "linux-weird-flavour": {"CVE-2026-9": {"releases": {"bookworm": {"status": "open", "urgency": "high"}}}},
    }

    def test_open_medium_and_up_and_the_fixes_of_two_years(self):
        cves_ = d2f.ingest_debian(self.DATA, today=datetime(2026, 10, 26, tzinfo=timezone.utc))
        self.assertEqual({"bookworm": ["needed", ""], "trixie": ["released", "1.0-2"]}, cves_["CVE-2026-5"]["packages"]["foo"])
        self.assertEqual("high", cves_["CVE-2026-5"]["severity"])
        self.assertIn("CVE-2025-2", cves_)
        self.assertNotIn("CVE-2020-1", cves_, "an old fix is not reported")
        self.assertNotIn("CVE-2019-3", cves_, "low urgency is not")
        self.assertEqual(["linux"], list(cves_["CVE-2026-9"]["packages"]))


class Rules(unittest.TestCase):
    STATE = {
        "CVE-2026-1": {"severity": "high", "published": "2026-10-01", "packages": {"openssl": {"noble": ["needed", ""]}, "linux": {"noble": ["released", "6.8.0-100.100"]}}},
        "CVE-2026-2": {"severity": "critical", "published": "2026-10-02", "packages": {"openssl": {"jammy": ["released", "3.0.2-0ubuntu1.20"]}}},
    }

    def test_the_rules_have_no_when_a_select_and_the_cves_of_their_packages(self):
        rules, fixtures = d2f.build("ubuntu", self.STATE)
        self.assertEqual(set(rules), set(fixtures))
        for key, rule in rules.items():
            self.assertTrue(key.startswith("org.distro-ubuntu-"))
            self.assertNotIn("when", rule)
            self.assertEqual([], feed.rule_errors(rule, False))
            self.assertTrue(all(c["ranges"] == [] and "ubuntu" in c for c in rule["cves"]))
        kernel = next(r for r in rules.values() if any(c["id"] == "CVE-2026-1" and "linux" in c["ubuntu"] for c in r["cves"]))
        names = next(c for c in kernel["select"]["all"] if "any" in c)["any"][0]["value"]
        self.assertIn("linux-signed", names, "the signed kernel is built from linux")

    def test_the_bucket_of_a_package_does_not_change_when_others_come(self):
        self.assertEqual(d2f.bucket("openssl"), d2f.bucket("openssl"))
        a, _ = d2f.build("ubuntu", self.STATE)
        more = {**self.STATE, "CVE-2026-3": {"severity": "high", "published": "2026-10-03", "packages": {"zlib": {"noble": ["needed", ""]}}}}
        b, _ = d2f.build("ubuntu", more)
        key = f"org.distro-ubuntu-{d2f.bucket('openssl')}"
        self.assertEqual({c["id"] for c in a[key]["cves"]}, {c["id"] for c in b[key]["cves"]} - {"CVE-2026-3"})

    def test_a_cve_the_nvd_rules_judge_for_a_package_is_left_out(self):
        taken = {("ubuntu", "CVE-2026-1", "openssl")}
        rules, _ = d2f.build("ubuntu", self.STATE, taken)
        pairs = {(c["id"], s) for r in rules.values() for c in r["cves"] for s in c["ubuntu"]}
        self.assertNotIn(("CVE-2026-1", "openssl"), pairs)
        self.assertIn(("CVE-2026-1", "linux"), pairs, "another package of the same CVE stays")
        self.assertIn(("CVE-2026-2", "openssl"), pairs)
        self.assertEqual([], feed.cve_duplicates(rules.values()))

    def test_the_fixture_is_proven_by_the_python_evaluator(self):
        rules, fixtures = d2f.build("ubuntu", self.STATE)
        for key, rule in rules.items():
            fx = fixtures[key]
            ctx = fx["context"]
            for item in fx["positive"]:
                self.assertTrue(feed.test(rule["select"], item) and cves.affecting(rule["cves"], item, ctx["release"], ctx["os"]))
            for item in fx["negative"]:
                self.assertFalse(feed.test(rule["select"], item) and cves.affecting(rule["cves"], item, ctx["release"], ctx["os"]))

    def test_the_rules_fit_a_budget_open_cves_first(self):
        state = {f"CVE-2026-{i}": {"severity": "high", "published": "2026-10-01", "packages": {f"pkg{i}": {"noble": ["released", "1-1"]}}} for i in range(50)}
        state["CVE-2026-99"] = {"severity": "low", "published": "2020-01-01", "packages": {"openpkg": {"noble": ["needed", ""]}}}
        self.assertEqual("CVE-2026-99", d2f.prioritise(state)[0], "what is open comes before what is fixed")
        original = dict(d2f.BYTES)
        d2f.BYTES["ubuntu"] = 6000
        try:
            rules, _ = d2f.build("ubuntu", state)
        finally:
            d2f.BYTES.update(original)
        kept = {c["id"] for r in rules.values() for c in r["cves"]}
        self.assertIn("CVE-2026-99", kept)
        self.assertLess(len(kept), len(state))

    def test_an_open_kernel_cve_counts_when_it_is_critical_a_fixed_one_when_it_is_high(self):
        open_high = {"noble": ["needed", ""]}
        fixed = {"noble": ["released", "6.8.0-1.1"]}
        self.assertEqual({}, d2f.actionable("linux", "high", open_high), "hundreds of these would be a finding nobody can act on")
        self.assertEqual(open_high, d2f.actionable("linux", "critical", open_high))
        self.assertEqual(fixed, d2f.actionable("linux-aws", "high", fixed))
        self.assertEqual(open_high, d2f.actionable("openssl", "high", open_high), "only the kernel is held back")
        state = {"CVE-2026-1": {"severity": "high", "published": "2026-10-01", "packages": {"linux": open_high}},
                 "CVE-2026-2": {"severity": "high", "published": "2026-10-01", "packages": {"linux": fixed, "openssl": open_high}}}
        rules, _ = d2f.build("ubuntu", state)
        pairs = {(c["id"], names) for r in rules.values() for c in r["cves"] for names in c["ubuntu"]}
        self.assertNotIn(("CVE-2026-1", "linux"), pairs)
        self.assertIn(("CVE-2026-2", "linux"), pairs)
        self.assertIn(("CVE-2026-2", "openssl"), pairs)

    def test_a_cve_of_arm_cores_is_found_only_on_an_arm_device(self):
        arm = ("Arm C1-Ultra, C1-Premium, Neoverse V3 & V3AE, Cortex-X925, Cortex-A76 & A76A may allow writes to resources "
               "owned by a higher exception level.")
        self.assertEqual(["arm64"], d2f.arch_of(arm))
        self.assertIsNone(d2f.arch_of("A heap overflow in the Linux kernel's netfilter, no Arm here"))
        self.assertIsNone(d2f.arch_of(None))
        packages = {"linux": {"resolute": ["released", "7.0.0-31.31"]}}
        rec = {"priority": "high", "published": "2026-06-09", "description": arm,
               "packages": [{"name": "linux", "statuses": [{"release_codename": "resolute", "status": "released", "description": "7.0.0-31.31"}]}]}
        entry = d2f.ubuntu_record(rec)
        self.assertEqual(["arm64"], entry["arch"])
        rules, _ = d2f.build("ubuntu", {"CVE-2025-10263": entry})
        rule = rules["org.distro-ubuntu-kernel-resolute"]
        self.assertEqual(["arm64"], rule["cves"][0]["arch"])
        old = {"Name": "linux-image-7.0.0-22-generic", "Version": "7.0.0-22.22", "SourcePackage": "linux-signed", "Source": "dpkg", "Origin": "Ubuntu"}
        self.assertEqual(["CVE-2025-10263"], list(cves.affecting(rule["cves"], old, "resolute", "ubuntu")), "no architecture known: as before")
        self.assertEqual(["CVE-2025-10263"], list(cves.affecting(rule["cves"], old, "resolute", "ubuntu", "aarch64")))
        self.assertEqual({}, cves.affecting(rule["cves"], old, "resolute", "ubuntu", "x86_64"))
        self.assertEqual({}, cves.affecting(rule["cves"], old, "resolute", "ubuntu", "amd64"))
        other = d2f.ubuntu_record({**rec, "description": "Use after free in netfilter"})
        self.assertNotIn("arch", other)

    def test_the_kernels_are_a_rule_per_release_and_a_cve_names_the_sources_that_have_the_same_lines(self):
        same = {"noble": ["needed", ""], "jammy": ["needed", ""]}
        state = {"CVE-2026-1": {"severity": "critical", "published": "2026-10-01", "packages": {"linux": same, "linux-aws": same, "linux-gcp": {"noble": ["released", "6.8.0-1.1"]}, "openssl": same}}}
        rules, fixtures = d2f.build("ubuntu", state)
        noble = rules["org.distro-ubuntu-kernel-noble"]
        self.assertEqual({"linux,linux-aws": {"noble": ["needed", ""]}, "linux-gcp": {"noble": ["released", "6.8.0-1.1"]}}, noble["cves"][0]["ubuntu"])
        self.assertEqual({"linux,linux-aws": {"jammy": ["needed", ""]}}, rules["org.distro-ubuntu-kernel-jammy"]["cves"][0]["ubuntu"])
        self.assertNotIn("openssl", noble["cves"][0]["ubuntu"])
        item = {"Name": "linux-image-6.8.0-1-generic", "Version": "6.8.0-1.1", "SourcePackage": "linux-signed-aws", "Source": "dpkg", "Origin": "Ubuntu"}
        self.assertTrue(feed.test(noble["select"], item))
        self.assertEqual(["CVE-2026-1"], list(cves.affecting(noble["cves"], item, "noble", "ubuntu")))
        self.assertEqual({}, cves.affecting(rules["org.distro-ubuntu-kernel-jammy"]["cves"], item, "noble", "ubuntu"), "a device finds only in the rule of its release")
        self.assertEqual([], feed.rule_errors(noble, False))
        self.assertEqual({"org.distro-ubuntu-kernel-noble", "org.distro-ubuntu-kernel-jammy", f"org.distro-ubuntu-{d2f.bucket('openssl')}"}, set(fixtures))


class Evaluator(unittest.TestCase):
    """scripts/cves.py is the twin of SecurityCves.php (checked against it on 600 random cases when it was written)."""

    def test_it_judges_by_the_tracker_of_the_distribution(self):
        cve = {"id": "CVE-1", "severity": "high", "ranges": [], "ubuntu": {"foo": {"noble": ["needed", ""]}},
               "debian": {"foo": {"bookworm": ["released", "1.0-2+deb12u1"]}}}
        item = {"Name": "foo", "Version": "1.0-1+deb12u1", "Source": "dpkg", "Origin": "Debian"}
        self.assertEqual("no_fix", cves.affecting([cve], {**item, "Origin": "Ubuntu"}, "noble", "ubuntu")["CVE-1"]["status"])
        self.assertEqual("update_available", cves.affecting([cve], item, "bookworm", "debian")["CVE-1"]["status"])
        self.assertEqual({}, cves.affecting([cve], {**item, "Version": "1.0-2+deb12u1"}, "bookworm", "debian"))
        self.assertEqual({}, cves.affecting([cve], item, "wilma", "linuxmint"), "a derivative has no tracker and the CVE has no ranges")
        self.assertEqual("linux", cves.tracker_source("linux-signed-amd64"))

    def test_installed_must_be_below_the_fix(self):
        cve = {"id": "CVE-1", "ranges": [[None, "156.0.8078.47", None]]}
        chrome = lambda v: {"Name": "google-chrome-stable", "Version": v, "Source": "dpkg", "Origin": "Google LLC"}
        self.assertEqual({}, cves.affecting([cve], chrome("156.0.8078.47-1"), "noble", "ubuntu"))
        self.assertEqual(["CVE-1"], list(cves.affecting([cve], chrome("156.0.8078.46-1"), "noble", "ubuntu")))
        snap = {"Name": "lxd", "Version": "5.0.10-24fe763", "Source": "snap", "Channel": "5.0/stable"}
        lxd = {"id": "CVE-2", "ranges": [["4.0.0", "5.21.4", None]]}
        self.assertEqual("no_fix", cves.affecting([lxd], snap)["CVE-2"]["status"])
        self.assertEqual("update_available", cves.affecting([lxd], {**snap, "Candidate": "5.21.4"})["CVE-2"]["status"])


if __name__ == "__main__":
    unittest.main()
