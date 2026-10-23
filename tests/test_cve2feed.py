"""Unit tests of the CVE rule generator: python -m unittest discover -s tests -p 'test_*.py'"""
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import cve2feed  # noqa: E402
import feed  # noqa: E402


def cve(severity="high", products=None, ubuntu=None, kev=False):
    entry = {"severity": severity, "kev": kev, "desc": "A flaw.", "refs": ["https://example.org/advisory"],
             "products": products or {}, "modified": "2026-10-01T00:00:00.000"}
    if ubuntu is not None:
        entry["ubuntu"] = {"checked": "2026-10-01", "sources": ubuntu}
    return entry


def findings(rules, item):
    return sorted(r["name"] for r in rules.values() if feed.test(r["when"], item))


class Versions(unittest.TestCase):
    def test_a_bound_is_written_the_way_the_server_reads_it(self):
        self.assertEqual("7.1.2.31", cve2feed.norm_bound("7.1.2-31"))
        self.assertEqual("156.0.8078.47", cve2feed.norm_bound("156.0.8078.47"))
        self.assertIsNone(cve2feed.norm_bound(None))
        for unreadable in ("b7653", "2.0.0-rc1", "1.1.1w", "9.9p1"):
            self.assertIs(False, cve2feed.norm_bound(unreadable), unreadable)

    def test_the_ranges_keep_only_what_can_be_written(self):
        self.assertEqual([("7.0.0.0", "7.1.2.31", None)], cve2feed.norm_ranges([["7.0.0-0", "7.1.2-31", None], [None, "b7653", None]]))

    def test_dpkg_order(self):
        for older, newer in (("8.2512.0-1ubuntu4.1", "8.2512.0-1ubuntu4.2"), ("2.7.4-1ubuntu0.2", "2.7.4-1ubuntu0.10"),
                             ("1.0~rc1-1", "1.0-1"), ("2.0-1", "1:0.9-1"), ("1.0", "1.0-1"), ("1.2-4+deb12u2", "1.2-4+deb12u10")):
            self.assertEqual(-1, feed.dpkg_compare(older, newer), f"{older} < {newer}")
            self.assertEqual(1, feed.dpkg_compare(newer, older))
        self.assertEqual(0, feed.dpkg_compare("1.0-1", "1.0-1"))

    def test_a_missing_part_is_zero(self):
        self.assertTrue(feed.test({"field": "Version", "op": "version_gte", "value": "8.5.0"}, {"Version": "8.5"}))


class Names(unittest.TestCase):
    def matches(self, source, name):
        return bool(re.search(cve2feed.source_regex(source), name, re.I))

    def test_a_source_package_is_its_binary_packages_and_nothing_else(self):
        for source, yes, no in (
            ("glib2.0", ["libglib2.0-0t64", "libglib2.0-bin", "libglib2.0-data"],
             ["gir1.2-glib-2.0", "libaccounts-glib0", "glib-networking", "libjson-glib-1.0-0", "libdbus-glib-1-2"]),
            ("php8.5", ["php8.5-cli", "php8.5-common", "libphp8.5-embed"], ["php-cli", "php-enum", "php8.3-cli", "php-symfony-console"]),
            ("expat", ["libexpat1", "libexpat1-dev", "expat"], ["libexpatx", "python3-expat-foo2"]),
            ("libsoup3", ["libsoup-3.0-0", "libsoup-3.0-common", "libsoup3"], ["libsoup2.4-1"]),
        ):
            for name in yes:
                self.assertTrue(self.matches(source, name), f"{source}: {name}")
            for name in no:
                self.assertFalse(self.matches(source, name), f"{source}: {name}")

    def test_which_source_packages_are_the_product(self):
        for product, source in (("php", "php8.5"), ("glib", "glib2.0"), ("libexpat", "expat"), ("libsoup", "libsoup3"), ("rsyslog", "rsyslog"), ("grub2", "grub2")):
            self.assertTrue(cve2feed.related(product, source), f"{product} / {source}")
        for product, source in (("chrome", "chromium-browser"), ("php", "phpmyadmin"), ("glib", "glibc"), ("tools", "open-vm-tools")):
            self.assertFalse(cve2feed.related(product, source), f"{product} / {source}")


class Rules(unittest.TestCase):
    def test_what_ubuntu_fixed_is_not_reported_and_what_it_did_not_is(self):
        state = {"cves": {"CVE-2026-19654": cve("high", {"rsyslog:rsyslog": [["8.36.0", "8.2608.0", None]]}, {"rsyslog": {
            "resolute": ["released", "8.2512.0-1ubuntu4.1"], "noble": ["released", "8.2312.0-3ubuntu9.3"], "jammy": ["needs-triage", ""]}})}}
        rules, fixtures, skipped = cve2feed.generate(state)
        self.assertEqual([], skipped)
        self.assertEqual(1, len(rules))
        item = lambda version, source="dpkg": {"Name": "rsyslog", "Version": version, "Source": source}
        self.assertEqual([], findings(rules, item("8.2512.0-1ubuntu4.2")))
        self.assertEqual([], findings(rules, item("8.2512.0-1ubuntu4.1")))
        self.assertEqual(1, len(findings(rules, item("8.2512.0-1ubuntu4.0"))))
        # A noble package below its own fix is reported, one above it is not (the resolute fix is not its fix).
        self.assertEqual(1, len(findings(rules, item("8.2312.0-3ubuntu9.2"))))
        self.assertEqual([], findings(rules, item("8.2312.0-3ubuntu9.4")))
        # A Debian revision is not comparable with an Ubuntu one.
        self.assertEqual(1, len(findings(rules, item("8.2312.0-3+deb13u1"))))
        # Software that is not a dpkg package is judged by the version range alone.
        self.assertEqual(1, len(findings(rules, item("8.2512.0", "snap"))))
        for fixture in fixtures.values():
            self.assertTrue(fixture["positive"] and fixture["negative"])

    def test_cves_of_a_product_with_the_same_ubuntu_data_are_one_rule_and_binary_packages_are_told_apart(self):
        php = {"php:php": [[None, "8.5.12", None]]}
        fixed = {"php8.5": {"resolute": ["released", "8.5.4-0ubuntu1.5"]}}
        state = {"cves": {"CVE-2026-109618": cve("critical", php, fixed), "CVE-2026-109619": cve("critical", php, fixed, kev=True),
                          "CVE-2026-1": cve("low", {"php:php": [[None, "8.5.13", None]]}, fixed)}}
        rules, _, skipped = cve2feed.generate(state)
        self.assertEqual([], skipped)
        self.assertEqual(1, len(rules))
        rule = next(iter(rules.values()))
        self.assertEqual("php affected by 3 CVEs", rule["name"])
        self.assertEqual("critical", rule["severity"])
        self.assertIn("CVE-2026-109618 (fixed in 8.5.12)", rule["message"])
        self.assertIn("CVE-2026-1 (fixed in 8.5.13)", rule["message"])
        item = lambda name, version: {"Name": name, "Version": version, "Source": "dpkg", "Publisher": "Ubuntu Developers"}
        self.assertEqual(1, len(findings(rules, item("php8.5-cli", "8.5.4-0ubuntu1.4"))))
        self.assertEqual([], findings(rules, item("php8.5-cli", "8.5.4-0ubuntu1.5")))
        # The metapackage and the PHP libraries are not PHP.
        self.assertEqual([], findings(rules, item("php-cli", "2:8.5+99ubuntu1")))
        self.assertEqual([], findings(rules, item("php-symfony-console", "7.4.7+dfsg-1ubuntu1")))
        self.assertEqual([], findings(rules, item("php-enum", "4.7.2-1")))

    def test_cves_fixed_in_different_versions_are_one_finding_that_tells_which_applies(self):
        ranges = {30: [[None, "6.9.13-55", None], ["7.0.0-0", "7.1.2-30", None]], 31: [[None, "6.9.13-56", None], ["7.0.0-0", "7.1.2-31", None]],
                  32: [[None, "6.9.13-57", None], ["7.0.0-0", "7.1.2-32", None]]}
        state = {"cves": {f"CVE-2026-1{n}": cve("medium", {"imagemagick:imagemagick": r}) for n, r in ranges.items()}}
        rules, skipped, = cve2feed.generate(state)[::2]
        self.assertEqual([], skipped)
        self.assertEqual(1, len(rules))
        rule = next(iter(rules.values()))
        self.assertIn("CVE-2026-130 (fixed in 6.9.13.55 / 7.1.2.30)", rule["message"])
        self.assertIn("CVE-2026-132 (fixed in 6.9.13.57 / 7.1.2.32)", rule["message"])
        item = lambda version: {"Name": "imagemagick", "Version": version, "Source": "dpkg"}
        self.assertEqual(1, len(findings(rules, item("8:7.1.2.18+dfsg1-1"))))
        self.assertEqual(1, len(findings(rules, item("8:7.1.2.31+dfsg1-1"))), "below the newest fix: at least one CVE applies")
        self.assertEqual([], findings(rules, item("8:7.1.2.32+dfsg1-1")))
        self.assertEqual(1, len(findings(rules, item("6.9.13.40"))))

    def test_a_package_that_only_shares_a_word_is_not_the_product(self):
        state = {"cves": {"CVE-2026-58014": cve("high", {"gnome:glib": [[None, "2.88.1", None]]},
                                                {"glib2.0": {"resolute": ["released", "2.88.0-1ubuntu0.1"], "jammy": ["released", "2.72.4-0ubuntu2.10"]}})}}
        rules, _, _ = cve2feed.generate(state)
        item = lambda name, version, **more: {"Name": name, "Version": version, "Source": "dpkg", **more}
        self.assertEqual([], findings(rules, item("libaccounts-glib0", "1.27-3")))
        self.assertEqual([], findings(rules, item("glib-networking", "2.80.1-1build2")))
        self.assertEqual([], findings(rules, item("gir1.2-glib-2.0", "2.88.0-1ubuntu0.1")))
        # gir1.2-glib-2.0 is built from glib2.0 on one release and from gobject-introspection (1.72.0) on another:
        # an agent that sends the source package decides by it, one that does not is not guessed at.
        self.assertEqual([], findings(rules, item("gir1.2-glib-2.0", "1.72.0-1", SourcePackage="gobject-introspection")))
        self.assertEqual([], findings(rules, item("gir1.2-glib-2.0", "1.72.0-1")))
        self.assertEqual(1, len(findings(rules, item("libglib2.0-0", "2.72.4-0ubuntu2.9", SourcePackage="glib2.0"))))
        self.assertEqual([], findings(rules, item("libglib2.0-0", "2.72.4-0ubuntu2.10", SourcePackage="glib2.0")))
        self.assertEqual(1, len(findings(rules, item("libglib2.0-0t64", "2.88.0-1ubuntu0"))))

    def test_the_source_package_of_a_binary_package_says_what_its_name_cannot(self):
        state = {"cves": {"CVE-2026-3": cve("high", {"gnu:gnutls": [[None, "3.8.13", None]]},
                                            {"gnutls28": {"resolute": ["released", "3.8.12-2ubuntu1.1"], "noble": ["needed", ""]}})}}
        rules, skipped, = cve2feed.generate(state)[::2]
        self.assertEqual([], skipped)
        item = lambda version, **more: {"Name": "libgnutls30t64", "Version": version, "Source": "dpkg", **more}
        # Agents 1.24.0+ send the source package: libgnutls30t64 is gnutls28, below the fix it is a finding.
        self.assertEqual(1, len(findings(rules, item("3.8.12-2ubuntu1.0", SourcePackage="gnutls28"))))
        self.assertEqual([], findings(rules, item("3.8.12-2ubuntu1.1", SourcePackage="gnutls28")))
        self.assertEqual([], findings(rules, item("3.8.12-2ubuntu1.2", SourcePackage="gnutls28")))
        # A package of another source package is not gnutls, whatever its name.
        self.assertEqual([], findings(rules, item("3.8.12-2ubuntu1.0", SourcePackage="something-else")))

    def test_a_source_the_cve_does_not_touch_is_not_reported(self):
        state = {"cves": {"CVE-2026-2": cve("high", {"mozilla:firefox": [[None, "150.0", None]]},
                                            {"firefox": {"noble": ["not-affected", ""], "resolute": ["not-affected", ""]}})}}
        rules, _, _ = cve2feed.generate(state)
        self.assertEqual([], findings(rules, {"Name": "firefox", "Version": "149.0", "Source": "dpkg"}))
        self.assertEqual(1, len(findings(rules, {"Name": "Mozilla Firefox", "Version": "149.0", "Source": "x"})))

    def test_the_upstream_project_and_ended_releases_do_not_decide_whether_ubuntu_is_affected(self):
        state = {"cves": {"CVE-2025-1125": cve("high", {"gnu:grub2": [[None, "2.12", None]]},
                                               {"grub2": {"jammy": ["not-affected", ""], "noble": ["not-affected", ""], "trusty": ["ignored", ""],
                                                          "upstream": ["needs-triage", ""]}})}}
        rules, _, skipped = cve2feed.generate(state)
        self.assertEqual([], skipped)
        item = lambda **more: {"Name": "grub2-common", "Version": "2.06-2ubuntu7.2", "Source": "dpkg", **more}
        self.assertEqual([], findings(rules, item(SourcePackage="grub2")))
        self.assertEqual([], findings(rules, item()))

    def test_a_bound_such_as_7_1_2_31_finds_debian_numbering(self):
        state = {"cves": {"CVE-2026-106580": cve("medium", {"imagemagick:imagemagick": [[None, "6.9.13-56", None], ["7.0.0-0", "7.1.2-31", None]]})}}
        rules, _, _ = cve2feed.generate(state)
        self.assertEqual(1, len(findings(rules, {"Name": "imagemagick", "Version": "8:7.1.2.18+dfsg1-1", "Source": "dpkg"})))
        self.assertEqual([], findings(rules, {"Name": "imagemagick", "Version": "8:7.1.2.31+dfsg1-1", "Source": "dpkg"}))

    def test_many_cves_fixed_in_one_release_are_one_finding(self):
        chrome = {"google:chrome": [[None, "156.0.8078.47", None]]}
        state = {"cves": {f"CVE-2026-{113000 + i}": cve("high", chrome) for i in range(300)}}
        rules, _, skipped = cve2feed.generate(state)
        self.assertEqual([], skipped)
        self.assertEqual(1, len(rules))
        rule = next(iter(rules.values()))
        self.assertEqual([], feed.rule_errors(rule, False))
        self.assertEqual(1, len(findings(rules, {"Name": "google-chrome-stable", "Version": "156.0.8078.46-1", "Source": "dpkg"})))
        self.assertEqual([], findings(rules, {"Name": "google-chrome-stable", "Version": "156.0.8078.47-1", "Source": "dpkg"}))
        self.assertEqual([], findings(rules, {"Name": "node-chrome-trace-event", "Version": "1.0.3-2", "Source": "dpkg"}))

    def test_generic_products_and_bounds_that_cannot_be_written_are_left_out(self):
        state = {"cves": {"CVE-2025-41244": cve("high", {"vmware:tools": [[None, "12.5.4", None]]}),
                          "CVE-2026-43630": cve("high", {"ggml:llama.cpp": [[None, "b7653", None]]})}}
        rules, _, skipped = cve2feed.generate(state)
        self.assertEqual({}, rules)
        self.assertEqual(2, len(skipped))


if __name__ == "__main__":
    unittest.main()
