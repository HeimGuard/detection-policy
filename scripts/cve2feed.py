#!/usr/bin/env python3
"""Turn newly published / changed CVEs from the NVD into `software` rules of the feed.

  python scripts/cve2feed.py [--days 2] [--limit 500]

Every CVE the NVD changed in the window is taken, whatever its severity: the rule gets the CVSS severity of
the CVE, and CVEs on the CISA Known Exploited Vulnerabilities list say so in the description. Only CVEs with
a product and a version range in their CPE configuration (versionEndExcluding / versionEndIncluding)
produce a rule.
Each CVE + product becomes rules/any/org.cve-<year>-<id>-<product>.json with a fixture; an existing
key is never overwritten, so a rule edited by hand stays. Set NVD_API_KEY for a higher rate limit.
"""
import argparse
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import feed  # noqa: E402  (the same rule checks and matching as CI)

ROOT = Path(__file__).resolve().parent.parent
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGET_SW = {"*", "-", "windows", "linux", "debian", "ubuntu"}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class NvdError(Exception):
    """The NVD did not answer after all retries."""


RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVD answers 403 / 429 when the rate limit is hit
ATTEMPTS = 8
WINDOW_DAYS = 30  # the NVD refuses a date range over 120 days; short windows keep every page small


def request(url, headers):
    """GET a JSON document; waits and retries (exponential backoff with jitter, Retry-After honoured)."""
    for attempt in range(ATTEMPTS):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in RETRY_STATUS:
                raise NvdError(f"NVD answered {e.code}") from e
            reason, retry_after = f"HTTP {e.code}", e.headers.get("Retry-After", "")
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            reason, retry_after = str(e), ""
        if attempt == ATTEMPTS - 1:
            raise NvdError(f"NVD unavailable after {ATTEMPTS} attempts ({reason})")
        wait = float(retry_after) if retry_after.isdigit() else min(120, 6 * 2 ** attempt)
        wait = min(wait, 300) * random.uniform(0.75, 1.25)
        print(f"NVD: {reason}; attempt {attempt + 1}/{ATTEMPTS}, waiting {wait:.0f}s", file=sys.stderr)
        time.sleep(wait)


def fetch(days, extra):
    """Yield CVEs matching the NVD query `extra` changed in the last `days` days, newest window first, page by page.

    Raises NvdError when the NVD stops answering; what was yielded before is still good.
    """
    headers = {"User-Agent": "detection-policy-cve2feed"}
    pause = 0.7 if os.environ.get("NVD_API_KEY") else 6.5  # the limit is 5 requests per 30 s (50 with a key)
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    end = datetime.now(timezone.utc)
    oldest = end - timedelta(days=min(days, 120))
    while end > oldest:
        begin = max(oldest, end - timedelta(days=WINDOW_DAYS))
        start = 0
        while True:
            query = urllib.parse.urlencode({"lastModStartDate": begin.strftime(fmt), "lastModEndDate": end.strftime(fmt),
                                            "resultsPerPage": 200, "startIndex": start}) + extra
            page = request(f"{API}?{query}", headers)
            yield from page.get("vulnerabilities", [])
            start += page.get("resultsPerPage", 0)
            time.sleep(pause)
            if not page.get("resultsPerPage") or start >= page.get("totalResults", 0):
                break
        end = begin


def products(cve):
    """{(vendor, product): [(start_incl, end_excl, end_incl), ...]} of the vulnerable application ranges."""
    found = {}
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m["criteria"].split(":")
                if not m.get("vulnerable") or len(parts) < 12 or parts[2] != "a" or parts[10] not in TARGET_SW:
                    continue
                rng = (m.get("versionStartIncluding"), m.get("versionEndExcluding"), m.get("versionEndIncluding"))
                if rng[1] or rng[2]:
                    found.setdefault((parts[3], parts[4]), []).append(rng)
    return found


def severity(cve):
    for kind in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for m in cve.get("metrics", {}).get(kind, []):
            s = str(m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity", "")).upper()
            if s in SEVERITY:
                return SEVERITY[s]
    return "high"  # on the KEV list: exploited in the wild


def bump(version):
    now = datetime.now(timezone.utc)
    prefix = f"{now.year}.{now.month}."
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if m and f"{m[1]}.{m[2]}." == prefix:
        return prefix + str(int(m[3]) + 1)
    return prefix + "1"


def before(version):
    """A version just under `version` (for the fixture)."""
    nums = [int(x) for x in re.findall(r"\d+", version)] or [1]
    for i in range(len(nums) - 1, -1, -1):
        if nums[i] > 0:
            nums[i] -= 1
            return ".".join(map(str, nums))
    return "0"


def name_pattern(product):
    """The package / program name as a whole word: 'ray' matches 'ray' and 'python3-ray', not 'libbluray'."""
    parts = [re.escape(x) for x in re.split(r"[\s_-]+", product) if x]
    return r"(^|[^a-z0-9])" + "[ _-]".join(parts) + r"($|[^a-z])"


# What a Debian / Ubuntu binary package of a product is called (php8.5-cli, google-chrome-stable,
# python3-ray), as opposed to a library that only mentions it (php-enum, node-chrome-trace-event).
DPKG_SUFFIXES = "cli|common|bin|core|server|client|fpm|cgi|dev|stable|beta|unstable|esr|browser|utils|tools|data|doc"


def dpkg_name_pattern(product):
    """The name pattern of the product as a dpkg package: one optional word before it (google-, python3-),
    an optional version (php8.5) and only the known suffixes after it."""
    parts = [re.escape(x) for x in re.split(r"[\s_-]+", product) if x]
    return r"^([a-z0-9]+-)?" + "[ _-]".join(parts) + r"[0-9.]*(-(" + DPKG_SUFFIXES + r"))*$"


def distro_conds(cid, product):
    """Conditions that keep a distribution package out of a rule it is not a finding of."""
    return [
        # rpm packages are not read for backported fixes yet, so they stay out of the CVE rules.
        {"field": "Source", "op": "not_in", "value": ["rpm"]},
        # A dpkg package is the product itself, not a library named after it.
        {"any": [
            {"field": "Source", "op": "ne", "value": "dpkg"},
            {"field": "Name", "op": "matches", "value": dpkg_name_pattern(product)},
        ]},
        # Debian / Ubuntu backport fixes without changing the upstream version: a changelog that names
        # the CVE (the agent sends the ids as ",CVE-1,CVE-2,") says the package is fixed.
        {"not": {"field": "FixedCves", "op": "contains", "value": f",{cid},"}},
    ]


def range_cond(rng):
    start, end_excl, end_incl = rng
    conds = []
    if start:
        conds.append({"field": "Version", "op": "version_gte", "value": start})
    conds.append({"field": "Version", "op": "version_lt" if end_excl else "version_lte", "value": end_excl or end_incl})
    return conds, start, end_excl, end_incl


def build_rule(cve, vendor, product, ranges, kev=True):
    cid = cve["id"]
    name = re.sub(r"[_\s]+", " ", product).strip()
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), cid)
    items = [range_cond(r) for r in sorted(set(ranges), key=lambda r: tuple(x or "" for x in r))[:8]]
    ranged = [{"all": c} if len(c) > 1 else c[0] for c, *_ in items]
    when = {"all": [
        {"field": "Name", "op": "matches", "value": name_pattern(name)},
        ranged[0] if len(ranged) == 1 else {"any": ranged},
        *distro_conds(cid, name),
    ]}
    key = re.sub(r"[^a-z0-9.-]+", "-", f"org.cve-{cid[4:]}-{product}".lower()).strip("-")[:64].rstrip("-.")
    rule = {
        "key": key,
        "name": f"{name} affected by {cid}",
        "description": f"{cid}{' (CISA Known Exploited Vulnerabilities)' if kev else ''}: {desc}"[:1000],
        "severity": severity(cve),
        "platform": "any",
        "source": "software",
        "when": when,
        "message": f"{{Name}} {{Version}} is affected by {cid}",
        "remediation": "Update the software to a fixed version, see the vendor advisory."[:1000],
        "urls": [f"https://nvd.nist.gov/vuln/detail/{cid}"] + [
            r["url"] for r in cve.get("references", [])
            if re.match(r"^https?://[^/\s]+\S*$", r.get("url", "")) and len(r["url"]) <= 500][:4],
    }
    fixture = make_fixture(rule, name, sorted(set(ranges), key=lambda r: tuple(x or "" for x in r))[:8])
    return rule, fixture


def make_fixture(rule, name, ranges):
    """A fixture proven against the rule itself, or None when no version inside / outside the ranges is found."""
    inside, outside = [], ["99999.0"]
    for start, end_excl, end_incl in ranges:
        inside += [v for v in (start, before(end_excl) if end_excl else None, end_incl) if v]
        outside += [end_excl or f"{end_incl}.1", f"{end_excl or end_incl}.1"]

    def hit(version, item_name=name):
        return feed.test(rule["when"], {"Name": item_name, "Version": version, "Source": "x"})

    positive = next((v for v in inside if hit(v)), None)
    negative = next((v for v in outside if not hit(v)), None)
    if positive is None or negative is None or hit(positive, "Unrelated tool") or hit(positive, f"lib{name.replace(' ', '')}x"):
        return None
    return {
        "key": rule["key"],
        "positive": [
            {"Name": name, "Version": positive, "Source": "x"},
            {"Name": name, "Version": positive, "Source": "dpkg", "FixedCves": ",CVE-2000-0001,"},
        ],
        "negative": [
            {"Name": name, "Version": negative, "Source": "x"},
            {"Name": "Unrelated tool", "Version": positive, "Source": "x"},
            {"Name": f"lib{name.replace(' ', '')}x", "Version": positive, "Source": "x"},
            {"Name": name, "Version": positive, "Source": "dpkg", "FixedCves": f",{rule['name'].split()[-1]},"},
            {"Name": f"{name.replace(' ', '-')}-enum", "Version": positive, "Source": "dpkg"},
            {"Name": name, "Version": positive, "Source": "rpm"},
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=2)
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    existing = {p.name for p in (ROOT / "rules").rglob("*.json")}
    added = 0
    failure = None
    feed_iter = fetch(args.days, "")
    while True:
        try:
            v = next(feed_iter, None)
        except NvdError as e:
            failure = e
            break
        if v is None:
            break
        if added >= args.limit:
            print(f"limit of {args.limit} reached")
            break
        cve = v["cve"]
        for (vendor, product), ranges in sorted(products(cve).items()):
            rule, fixture = build_rule(cve, vendor, product, ranges, bool(cve.get("cisaExploitAdd")))
            if f"{rule['key']}.json" in existing:
                continue
            if added >= args.limit:
                break
            if fixture is None or feed.rule_errors(rule, False):
                print(f"skipped {rule['key']}: no valid rule / fixture could be built", file=sys.stderr)
                continue
            (ROOT / "rules" / "any" / f"{rule['key']}.json").write_text(json.dumps(rule, indent=2) + "\n")
            (ROOT / "tests" / "fixtures" / f"{rule['key'].removeprefix('org.')}.json").write_text(
                json.dumps(fixture, indent=2) + "\n")
            existing.add(f"{rule['key']}.json")
            print("added", rule["key"])
            added += 1
    if added:
        mf = ROOT / "manifest.json"
        m = json.loads(mf.read_text())
        mf.write_text(json.dumps({"version": bump(m["version"]), "files": m["files"]}, indent=2) + "\n")
    print(f"{added} new rule(s)")
    if failure:
        # Keep what was fetched (the next night continues); fail only when nothing came out of the run.
        print(f"::warning::{failure}; the CVEs fetched before it were processed", file=sys.stderr)
        if not added:
            sys.exit(f"{failure}")


if __name__ == "__main__":
    main()
