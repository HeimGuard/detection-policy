#!/usr/bin/env python3
"""Turn CVEs from the NVD into `software` rules of the feed.

  python scripts/cve2feed.py [--days 4] [--limit 500]    # nightly: fetch what the NVD changed, update, regenerate
  python scripts/cve2feed.py --cve CVE-2026-1 CVE-2026-2   # take these CVEs too
  python scripts/cve2feed.py --offline                     # regenerate rules / fixtures from data/cves.json only

data/cves.json is the state: for every CVE what the NVD said (products with version ranges, severity, ...)
and what the Ubuntu security tracker says about its packages (fixed versions per release). The rules and
fixtures under rules/any/org.cve-*.json and tests/fixtures/cve-*.json are a pure function of it, so a CVE the
NVD corrects is corrected in its rule, and CI checks that nobody edited a generated file (`--offline`).
Write a rule by hand under another key (`org.<source>-<what>`), not `org.cve-`.

CVEs of one product with the same version ranges and the same Ubuntu fixes become one rule (320 Chrome CVEs
fixed in one release are one finding, not 320). Only CVEs with a product and a version range in their CPE
configuration (versionEndExcluding / versionEndIncluding) produce a rule. Set NVD_API_KEY for a higher rate limit.
"""
import argparse
import hashlib
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
UBUNTU_API = "https://ubuntu.com/security/cves/{}.json"
STATE = ROOT / "data" / "cves.json"
TARGET_SW = {"*", "-", "windows", "linux", "debian", "ubuntu"}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# Products whose name alone says nothing ("tools" is VMware Tools, and also initramfs-tools): no rule can find them.
GENERIC = {"tools", "tool", "core", "server", "client", "agent", "manager", "service", "services", "contracts",
           "platform", "engine", "framework", "library", "libs", "utils", "utilities", "common", "base", "data",
           "system", "console", "portal", "gateway", "network", "desktop", "web", "app", "application", "plugin",
           "plugins", "extension", "sdk", "api", "cli", "gui", "linux", "windows", "kernel", "mobile", "cloud"}
# Ubuntu releases, oldest first: when a rule is too big the fixes of the oldest are dropped first.
RELEASES = ["trusty", "xenial", "bionic", "focal", "jammy", "noble", "oracular", "plucky", "questing", "resolute"]
MAX_FIXED_CVES = 30  # a group of more CVEs is not hidden by a changelog (the conditions would not fit)


class NvdError(Exception):
    """The NVD did not answer after all retries."""


RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVD answers 403 / 429 when the rate limit is hit
ATTEMPTS = 8
WINDOW_DAYS = 30  # the NVD refuses a date range over 120 days; short windows keep every page small


def request(url, headers, missing=None, attempts=ATTEMPTS, timeout=60):
    """GET a JSON document; waits and retries (exponential backoff with jitter, Retry-After honoured).

    A 404 gives `missing` when that is not None."""
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404 and missing is not None:
                return missing
            if e.code not in RETRY_STATUS:
                raise NvdError(f"{url.split('?')[0]} answered {e.code}") from e
            reason, retry_after = f"HTTP {e.code}", e.headers.get("Retry-After", "")
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            reason, retry_after = str(e), ""
        if attempt == attempts - 1:
            raise NvdError(f"{url.split('?')[0]} unavailable after {attempts} attempts ({reason})")
        wait = float(retry_after) if retry_after.isdigit() else min(120, 6 * 2 ** attempt)
        wait = min(wait, 300) * random.uniform(0.75, 1.25)
        print(f"{url.split('?')[0]}: {reason}; attempt {attempt + 1}/{attempts}, waiting {wait:.0f}s", file=sys.stderr)
        time.sleep(wait)


def nvd_headers():
    headers = {"User-Agent": "detection-policy-cve2feed"}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    return headers


def nvd_pause():
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.5  # the limit is 5 requests per 30 s (50 with a key)


def fetch(days, extra):
    """Yield CVEs matching the NVD query `extra` changed in the last `days` days, newest window first, page by page.

    Raises NvdError when the NVD stops answering; what was yielded before is still good.
    """
    headers, pause = nvd_headers(), nvd_pause()
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


def fetch_ids(ids):
    """Yield the NVD records of these CVE ids."""
    headers, pause = nvd_headers(), nvd_pause()
    for cid in ids:
        page = request(f"{API}?cveId={urllib.parse.quote(cid)}", headers)
        yield from page.get("vulnerabilities", [])
        time.sleep(pause)


# ---------------------------------------------------------------------------------------------------------------
# What the NVD says


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


def state_entry(cve):
    """What the state keeps of an NVD record, None when it gives no product with a version range."""
    found = products(cve)
    if not found:
        return None
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), cve["id"])
    return {
        "severity": severity(cve),
        "kev": bool(cve.get("cisaExploitAdd")),
        "desc": desc[:400],
        "refs": [r["url"] for r in cve.get("references", [])
                 if re.match(r"^https?://[^/\s]+\S*$", r.get("url", "")) and len(r["url"]) <= 500][:4],
        "products": {f"{v}:{p}": [list(r) for r in sorted(set(rs), key=lambda r: tuple(x or "" for x in r))]
                     for (v, p), rs in sorted(found.items())},
        "modified": cve.get("lastModified", ""),
    }


def norm_bound(version):
    """A bound the server reads right: only numbers and dots ("7.1.2-31" is written 7.1.2.31, the way Debian
    numbers it). None when there is no bound, False when it cannot be written that way (b7653, 2.0-rc1, 1.1.1w)."""
    if version is None:
        return None
    version = re.sub(r"(?<=\d)-(?=\d)", ".", str(version).strip().lstrip("vV"))
    return version if re.fullmatch(r"\d+(\.\d+)*", version) else False


def norm_ranges(ranges):
    """The ranges of the state as (start, end_excl, end_incl) with representable bounds, sorted, at most 8."""
    out = set()
    for start, end_excl, end_incl in ranges:
        rng = (norm_bound(start), norm_bound(end_excl), norm_bound(end_incl))
        if False in rng or not (rng[1] or rng[2]):
            continue
        out.add(rng)
    return sorted(out, key=lambda r: tuple(x or "" for x in r))[:8]


def generic(product):
    words = [w for w in re.split(r"[\s_-]+", product.lower()) if w]
    return not words or all(w in GENERIC or len(w) < 3 for w in words)


# ---------------------------------------------------------------------------------------------------------------
# What Ubuntu says


def related(product, source):
    """Whether an Ubuntu source package is the product (php8.5 / php, glib2.0 / glib, expat / libexpat)."""
    flat = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    stem = flat(re.sub(r"[0-9.]+$", "", source.lower()))
    prod = flat(product)
    return len(stem) >= 3 and stem in (prod, "lib" + prod) or (len(prod) >= 3 and prod == "lib" + stem)


def source_regex(source):
    """The binary packages of a source package: php8.5 -> php8.5, php8.5-cli, libphp8.5-embed; glib2.0 ->
    libglib2.0-0t64, gir1.2-glib-2.0; libsoup3 -> libsoup-3.0-0; expat -> libexpat1, libexpat1-dev."""
    core = ""
    for token in re.findall(r"[a-z]+|\d+(?:\.\d+)*|[^a-z\d]+", source.lower()):
        if token[0].isdigit():
            core += ("[-_.]?" if core and core[-1] != "?" and core[-1:].isalpha() else "") + re.escape(token)
        elif token[0].isalpha():
            core += token
        else:
            core += "[-_.]?"
    return r"^(?:lib|gir1\.2-)?" + core + r"[0-9.]*(?:[-_.+][a-z0-9.+_~-]*)?$"


def ubuntu_lookup(cid, found):
    """{source package: {release: [status, fixed version]}} of the sources that are one of the products of the
    CVE, {} when Ubuntu does not know it, None when it did not answer."""
    try:
        # The tracker is slow for some CVEs: a few quick attempts, the next night asks again.
        page = request(UBUNTU_API.format(cid), {"User-Agent": "detection-policy-cve2feed"}, missing={}, attempts=2, timeout=25)
    except NvdError as e:
        print(f"Ubuntu tracker: {e}", file=sys.stderr)
        return None
    out = {}
    for package in page.get("packages", []):
        if not any(related(p.split(":", 1)[1], package["name"]) for p in found):
            continue
        rel = {s["release_codename"]: [s["status"], s.get("description", "") if s["status"] == "released" else ""]
               for s in package.get("statuses", []) if s["status"] != "DNE"}
        if rel:
            out[package["name"]] = rel
    return out


def dpkg_info(product, ubuntu):
    """What Ubuntu changes in a rule for a dpkg package of the product: the source packages (as name patterns), the
    fixed versions per release and the sources the CVE does not touch."""
    info = {"names": [], "fixes": [], "unaffected": []}
    for source, rel in sorted((ubuntu or {}).get("sources", {}).items()):
        if not related(product, source):
            continue
        pattern = source_regex(source)
        if all(status == "not-affected" for status, _ in rel.values()):
            info["unaffected"].append([source, pattern])
            continue
        info["names"].append([source, pattern])
        for release, (status, version) in sorted(rel.items()):
            if status == "released" and version:
                info["fixes"].append([source, pattern, version, release])
    return info


# ---------------------------------------------------------------------------------------------------------------
# The rules


def name_pattern(product):
    """The package / program name as a whole word: 'ray' matches 'ray' and 'python3-ray', not 'libbluray'."""
    parts = [re.escape(x) for x in re.split(r"[\s_-]+", product) if x]
    return r"(^|[^a-z0-9])" + "[ _-]".join(parts) + r"($|[^a-z])"


# What a Debian / Ubuntu binary package of a product is called (google-chrome-stable, python3-ray), as opposed to a
# library that only mentions it (php-enum, node-chrome-trace-event, libaccounts-glib0).
DPKG_SUFFIXES = "cli|common|bin|core|server|client|fpm|cgi|dev|stable|beta|unstable|esr|browser|utils|tools|data|doc"


def dpkg_name_pattern(product):
    """The name pattern of the product as a dpkg package when Ubuntu does not tell: google- or python3- before it,
    an optional version (php8.5) and only the known suffixes after it."""
    parts = [re.escape(x) for x in re.split(r"[\s_-]+", product) if x]
    return r"^(google-|python3?-)?" + "[ _-]".join(parts) + r"[0-9.]*(-(" + DPKG_SUFFIXES + r"))*$"


def alternatives(patterns):
    return patterns[0] if len(patterns) == 1 else "|".join(f"(?:{p})" for p in patterns)


def range_cond(rng):
    start, end_excl, end_incl = rng
    conds = []
    if start:
        conds.append({"field": "Version", "op": "version_gte", "value": start})
    conds.append({"field": "Version", "op": "version_lt" if end_excl else "version_lte", "value": end_excl or end_incl})
    return {"all": conds} if len(conds) > 1 else conds[0]


def fix_prefix(version):
    """'2:2.80.0-6ubuntu3.9' -> '2:2.80.0-': what a version of the same upstream release starts with."""
    head, dash, _ = version.rpartition("-")
    return head + "-" if dash else version


def build_when(product, ranges, info, cids, fixes):
    ranged = [range_cond(r) for r in ranges]
    patterns = [name_pattern(product)] + [p for _, p in info["names"]]
    dpkg_names = alternatives([p for _, p in info["names"]]) if info["names"] else dpkg_name_pattern(product)
    conds = [
        {"field": "Name", "op": "matches", "value": alternatives(patterns)},
        ranged[0] if len(ranged) == 1 else {"any": ranged},
        # rpm packages are not read for backported fixes yet, so they stay out of the CVE rules.
        {"field": "Source", "op": "not_in", "value": ["rpm"]},
        # A dpkg package is the product itself, not a library named after it.
        {"any": [{"field": "Source", "op": "ne", "value": "dpkg"}, {"field": "Name", "op": "matches", "value": dpkg_names}]},
    ]
    # Debian / Ubuntu backport fixes without changing the upstream version: a changelog that names the CVE (the agent
    # sends the ids as ",CVE-1,CVE-2,") says the package is fixed.
    if len(cids) <= MAX_FIXED_CVES:
        named = [{"field": "FixedCves", "op": "contains", "value": f",{c},"} for c in cids]
        conds.append({"not": named[0] if len(named) == 1 else {"all": named}})
    # What the Ubuntu tracker says: a package at or after the version that fixed it is fine, and so is one of a
    # source package the CVE does not touch. A Debian revision (+deb12u1) is not comparable with an Ubuntu one.
    skip = [{"all": [
        {"field": "Source", "op": "eq", "value": "dpkg"},
        {"field": "Name", "op": "matches", "value": pattern},
        {"field": "Version", "op": "starts_with", "value": fix_prefix(version)},
        {"field": "Version", "op": "dpkg_gte", "value": version},
        {"field": "Version", "op": "not_matches", "value": r"[+~]deb\d"},
    ]} for _, pattern, version, _ in fixes]
    if info["unaffected"]:
        skip.append({"all": [{"field": "Source", "op": "eq", "value": "dpkg"},
                             {"field": "Name", "op": "matches", "value": alternatives([p for _, p in info["unaffected"]])}]})
    if skip:
        conds.append({"not": skip[0] if len(skip) == 1 else {"any": skip}})
    return {"all": conds}


def range_text(ranges):
    texts = []
    for start, end_excl, end_incl in ranges:
        end = f"before {end_excl}" if end_excl else f"up to {end_incl}"
        texts.append(f"from {start} {end}" if start else end)
    return "; ".join(texts)


def fit(head, items, tail, limit=1000):
    """head + as many items as fit (+ 'and n more') + tail within `limit` characters."""
    shown = []
    for item in items:
        more = len(items) - len(shown) - 1
        text = head + ", ".join(shown + [item]) + (f" and {more} more" if more else "") + tail
        if len(text) > limit:
            break
        shown.append(item)
    more = len(items) - len(shown)
    return head + ", ".join(shown) + (f" and {more} more" if more else "") + tail


def build_rule(product, ranges, info, cves, fixes):
    """cves: [(cid, entry)] of one group. Returns the rule."""
    cves = sorted(cves, key=lambda c: (-RANK[c[1]["severity"]], not c[1]["kev"], c[0]), reverse=False)
    cids = [c for c, _ in cves]
    top_cid, top = cves[0]
    name = re.sub(r"[_\s]+", " ", product).strip()
    sig = json.dumps([product, ranges, info], sort_keys=True)
    key = re.sub(r"[^a-z0-9.-]+", "-", f"org.cve-{product}".lower()).strip("-")[:48].rstrip("-.")
    key += "-" + hashlib.sha1(sig.encode()).hexdigest()[:8]
    kev = [c for c, e in cves if e["kev"]]
    if len(cves) == 1:
        title = f"{name} affected by {top_cid}"
        description = f"{top_cid}{' (CISA Known Exploited Vulnerabilities)' if top['kev'] else ''}: {top['desc']}"[:1000]
        message = f"{{Name}} {{Version}} is affected by {top_cid}"
    else:
        title = f"{name} affected by {len(cves)} CVEs"
        exploited = f" Known exploited: {', '.join(kev[:10])}{' ...' if len(kev) > 10 else ''}." if kev else ""
        description = fit(f"{len(cves)} known vulnerabilities of {name} ({range_text(ranges)}), the most severe is "
                          f"{top_cid} ({top['severity']}).{exploited} CVEs: ", cids, "")
        message = fit("{Name} {Version} is affected by " + f"{len(cves)} CVEs: ", cids, "")
    links = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cids[:3]]
    for _, e in cves[:3]:
        links += e["refs"]
    urls = list(dict.fromkeys(links))[:10]
    return {
        "key": key,
        "name": title[:120],
        "description": description,
        "severity": max((e["severity"] for _, e in cves), key=RANK.get),
        "platform": "any",
        "source": "software",
        "when": build_when(product, ranges, info, cids, fixes),
        "message": message[:1000],
        "remediation": "Update the software to a fixed version, see the vendor advisory.",
        "urls": urls,
    }


def before(version):
    """A version just under `version` (for the fixture)."""
    nums = [int(x) for x in re.findall(r"\d+", version)] or [1]
    for i in range(len(nums) - 1, -1, -1):
        if nums[i] > 0:
            nums[i] -= 1
            return ".".join(map(str, nums))
    return "0"


def make_fixture(rule, product, ranges, info, cids, fixes):
    """A fixture proven against the rule itself, or None when no version inside / outside the ranges is found."""
    name = re.sub(r"[_\s]+", " ", product).strip()
    inside, outside = [], ["99999.0"]
    for start, end_excl, end_incl in ranges:
        inside += [v for v in (start, before(end_excl) if end_excl else None, end_incl) if v]
        outside += [end_excl or f"{end_incl}.1", f"{end_excl or end_incl}.1"]

    def hit(item):
        return feed.test(rule["when"], item)

    positive_version = next((v for v in inside if hit({"Name": name, "Version": v, "Source": "x"})), None)
    negative_version = next((v for v in outside if not hit({"Name": name, "Version": v, "Source": "x"})), None)
    if positive_version is None or negative_version is None:
        return None
    v = positive_version
    packages = [source for source, _ in info["names"]]
    dpkg_name = packages[0] if packages else name.replace(" ", "-")
    positive = [
        {"Name": name, "Version": v, "Source": "x"},
        {"Name": dpkg_name, "Version": v, "Source": "dpkg", "FixedCves": ",CVE-2000-0001,"},
    ]
    negative = [
        {"Name": name, "Version": negative_version, "Source": "x"},
        {"Name": "Unrelated tool", "Version": v, "Source": "x"},
        {"Name": f"lib{name.replace(' ', '')}x", "Version": v, "Source": "x"},
        {"Name": name, "Version": v, "Source": "rpm"},
    ]
    if not packages:  # (what Ubuntu names as binary packages of the product is told apart by its own patterns)
        negative.append({"Name": f"{name.replace(' ', '-')}-enum", "Version": v, "Source": "dpkg"})
    if len(cids) <= MAX_FIXED_CVES:
        negative.append({"Name": dpkg_name, "Version": v, "Source": "dpkg", "FixedCves": "," + ",".join(cids) + ","})
    for source, _, version, _ in fixes[:1]:
        # Just before the fix is a finding, the fix itself and the later revisions are not.
        revision = fix_prefix(version) + "0"
        positive.append({"Name": source, "Version": revision, "Source": "dpkg"})
        negative.append({"Name": source, "Version": version, "Source": "dpkg"})
        negative.append({"Name": source, "Version": version + ".1", "Source": "dpkg"})
    if info["unaffected"]:
        negative.append({"Name": info["unaffected"][0][0], "Version": v, "Source": "dpkg"})
    positive = [i for i in positive if hit(i)]
    for item in negative:
        if hit(item):
            return None  # the rule would report something it must not: leave it out rather than ship it
    return {"key": rule["key"], "positive": positive, "negative": negative}


def generate(state):
    """(rules, fixtures, skipped): everything the state says as {key: rule}, {key: fixture} and the reasons."""
    groups, skipped = {}, []
    for cid, entry in sorted(state["cves"].items()):
        for pkey, raw in entry["products"].items():
            product = pkey.split(":", 1)[1]
            if generic(product):
                skipped.append(f"{cid} {product}: the name is too generic to find")
                continue
            ranges = norm_ranges(raw)
            if not ranges:
                skipped.append(f"{cid} {product}: no version range that can be written")
                continue
            info = dpkg_info(product, entry.get("ubuntu"))
            groups.setdefault((product, json.dumps([ranges, info], sort_keys=True)), (product, ranges, info, {}))[3][cid] = entry
    rules, fixtures = {}, {}
    for product, ranges, info, members in groups.values():
        cves = list(members.items())
        fixes = sorted(info["fixes"], key=lambda f: (RELEASES.index(f[3]) if f[3] in RELEASES else len(RELEASES), f[2]), reverse=True)
        shown = list(dict.fromkeys((f[1], f[2]) for f in fixes))
        fixes = [next(f for f in fixes if (f[1], f[2]) == s) for s in shown]
        while True:  # too many conditions: drop the fixes of the oldest releases
            rule = build_rule(product, ranges, info, cves, fixes)
            if not feed.rule_errors(rule, False) or not fixes:
                break
            fixes = fixes[:-1]
        if feed.rule_errors(rule, False):
            skipped.append(f"{rule['key']}: {'; '.join(feed.rule_errors(rule, False))}")
            continue
        fixture = make_fixture(rule, product, ranges, info, [c for c, _ in cves], fixes)
        if fixture is None:
            skipped.append(f"{rule['key']}: no valid fixture could be built")
            continue
        rules[rule["key"]] = rule
        fixtures[rule["key"]] = fixture
    return rules, fixtures, skipped


def write(rules, fixtures):
    """Replace the generated files by these; True when something changed."""
    changed = False
    rule_dir, fixture_dir = ROOT / "rules" / "any", ROOT / "tests" / "fixtures"
    wanted = {rule_dir / f"{k}.json": json.dumps(r, indent=2) + "\n" for k, r in rules.items()}
    wanted |= {fixture_dir / f"{k.removeprefix('org.')}.json": json.dumps(f, indent=2) + "\n" for k, f in fixtures.items()}
    for old in list(rule_dir.glob("org.cve-*.json")) + list(fixture_dir.glob("cve-*.json")):
        if old not in wanted:
            old.unlink()
            changed = True
    for path, text in wanted.items():
        if not path.exists() or path.read_text() != text:
            path.write_text(text)
            changed = True
    return changed


def bump(version):
    now = datetime.now(timezone.utc)
    prefix = f"{now.year}.{now.month}."
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if m and f"{m[1]}.{m[2]}." == prefix:
        return prefix + str(int(m[3]) + 1)
    return prefix + "1"


def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"cves": {}}


def save_state(state):
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def ingest(state, records, limit=None):
    """Take NVD records into the state; returns the number of CVEs that are new or changed."""
    changed = 0
    for record in records:
        cve = record["cve"] if "cve" in record else record
        entry = state_entry(cve)
        old = state["cves"].get(cve["id"])
        if entry is None:
            if old is not None:
                del state["cves"][cve["id"]]  # the NVD took its product away
                changed += 1
            continue
        if old and old.get("modified") == entry["modified"]:
            continue
        if old is None and limit is not None and changed >= limit:
            break
        if old and "ubuntu" in old and old["products"] == entry["products"]:
            entry["ubuntu"] = old["ubuntu"]
        state["cves"][cve["id"]] = entry
        changed += 1
    return changed


def refresh_ubuntu(state, limit, offline_ok=False):
    """Ask the Ubuntu tracker about the CVEs it was not asked about for 2 days (14 when everything is settled)."""
    today = datetime.now(timezone.utc).date()
    asked = 0
    for cid, entry in sorted(state["cves"].items(), key=lambda c: (c[1].get("ubuntu", {}).get("checked", ""), c[0])):
        ubuntu = entry.get("ubuntu")
        if ubuntu:
            age = (today - datetime.strptime(ubuntu["checked"], "%Y-%m-%d").date()).days
            settled = all(status in ("released", "not-affected", "ignored") for rel in ubuntu["sources"].values()
                          for status, _ in rel.values())
            if age < (14 if settled else 2):
                continue
        if asked >= limit:
            break
        found = ubuntu_lookup(cid, entry["products"])
        asked += 1
        time.sleep(0.2)
        if found is not None:
            entry["ubuntu"] = {"checked": today.isoformat(), "sources": found}
        if asked % 50 == 0:
            save_state(state)  # a long run keeps what it has
    return asked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=4, help="take the CVEs the NVD changed in the last N days")
    ap.add_argument("--limit", type=int, default=500, help="at most N new CVEs per run")
    ap.add_argument("--cve", nargs="*", default=[], help="take these CVEs too")
    ap.add_argument("--import-nvd", help="take the NVD records of this JSON file ({id: record} or a list)")
    ap.add_argument("--offline", action="store_true", help="only regenerate from data/cves.json")
    ap.add_argument("--no-ubuntu", action="store_true", help="do not ask the Ubuntu security tracker")
    ap.add_argument("--ubuntu-limit", type=int, default=1500)
    args = ap.parse_args()

    state = load_state()
    failure = None
    if not args.offline:
        try:
            if args.import_nvd:
                data = json.loads(Path(args.import_nvd).read_text())
                print(f"{ingest(state, data.values() if isinstance(data, dict) else data)} CVE(s) imported")
            if args.cve:
                print(f"{ingest(state, fetch_ids(args.cve))} of the named CVE(s) taken")
            if args.days:
                print(f"{ingest(state, fetch(args.days, ''), args.limit)} new or changed CVE(s)")
        except NvdError as e:
            failure = e
        if not args.no_ubuntu:
            print(f"{refresh_ubuntu(state, args.ubuntu_limit)} CVE(s) asked at the Ubuntu security tracker")
        save_state(state)

    rules, fixtures, skipped = generate(state)
    for reason in skipped:
        print(f"skipped {reason}", file=sys.stderr)
    changed = write(rules, fixtures)
    if changed and not args.offline:
        manifest = ROOT / "manifest.json"
        m = json.loads(manifest.read_text())
        manifest.write_text(json.dumps({"version": bump(m["version"]), "files": m["files"]}, indent=2) + "\n")
    print(f"{len(state['cves'])} CVE(s) -> {len(rules)} rule(s), {len(skipped)} skipped")
    if failure:
        # Keep what was fetched (the next night continues); fail only when nothing came out of the run.
        print(f"::warning::{failure}; the CVEs fetched before it were processed", file=sys.stderr)
        if not changed:
            sys.exit(f"{failure}")


if __name__ == "__main__":
    main()
