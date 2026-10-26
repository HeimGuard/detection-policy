#!/usr/bin/env python3
"""Turn what the security trackers of Ubuntu and Debian say into `software` rules of the feed.

  python scripts/distro2feed.py                 # fetch both trackers, update data/distro.json, regenerate
  python scripts/distro2feed.py --no-debian     # only Ubuntu
  python scripts/distro2feed.py --import-debian FILE   # the Debian tracker data (JSON) from a file
  python scripts/distro2feed.py --offline       # regenerate rules / fixtures from data/distro.json only

cve2feed.py starts from the NVD, which has no product for a third of the new CVEs yet and none at all for the kernel, while the
trackers know every CVE of every source package of their distribution. These rules start from them: for the critical and high
CVEs that a supported release has not fixed (and the ones it fixed lately) every source package gets the CVEs with their status
per release. Same format as the rules of cve2feed.py (`select` and `cves`, no ranges, no `when`), judged by the server one CVE
at a time: installed < fixed, a changelog that names the CVE is a fix, the tracker of the device's distribution decides.

The source packages are spread over 32 rules by a hash of their name (org.distro-ubuntu-07), so a rule keeps its key when a
package comes or goes and its findings keep their acknowledgements; the kernels have a rule per release (org.distro-ubuntu-kernel-noble). The rules are a pure function of data/distro.json.
"""
import argparse
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import feed  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "data" / "distro.json"
UBUNTU_LIST = "https://ubuntu.com/security/cves.json"
DEBIAN_API = "https://security-tracker.debian.org/tracker/data/json"
UBUNTU_RELEASES = ["focal", "jammy", "noble", "questing", "resolute"]
DEBIAN_RELEASES = ["bullseye", "bookworm", "trixie", "forky"]
BUCKETS = 32
RELEASED_DAYS = 365  # what a release fixed this long ago is still reported for a package below the fix
BYTES = {"ubuntu": 2_000_000, "debian": 1_000_000}  # of the rules of a distribution as written (compact): the server takes 8 MB of the whole feed
MAX_RULE = 900_000  # of one rule: the server takes 1 MB of one file
SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low", "untriaged": "medium",
            "not yet assigned": "medium", "unimportant": "low"}
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
# The kernels a CVE lists by the hundred (linux-aws-5.4, linux-azure-fde, ...): the generic and the usual flavours.
KERNEL = re.compile(r"^linux(?:-(?:aws|azure|gcp|oracle|raspi|lowlatency|kvm|hwe|oem|nvidia|ibm|gke|riscv)(?:-[\d.]+)?)?$")


class FetchError(Exception):
    pass


def fetch(url, attempts=4, timeout=180):
    """A JSON document, gzip accepted (a page of the Ubuntu list is 4 MB without it); retries with a growing wait."""
    reason = ""
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "detection-policy-distro2feed", "Accept-Encoding": "gzip"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return json.loads(gzip.decompress(raw) if r.headers.get("Content-Encoding") == "gzip" else raw)
        except urllib.error.HTTPError as e:
            reason = f"HTTP {e.code}"
            if e.code not in (429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
            reason = str(e)
        time.sleep(min(60, 5 * 2 ** attempt))
    raise FetchError(f"{url.split('?')[0]}: {reason}")


# ---------------------------------------------------------------------------------------------------------------
# Ubuntu


def ubuntu_record(rec, releases=UBUNTU_RELEASES):
    """{'severity', 'published', 'packages': {source: {release: [status, fixed version]}}} of a CVE of the list, None when
    no supported release has anything to report (open: needed / pending, or fixed: released)."""
    packages = {}
    for package in rec.get("packages", []):
        name = package["name"]
        if name.startswith("linux") and not KERNEL.match(name):
            continue
        lines = {}
        for s in package.get("statuses", []):
            if s.get("release_codename") not in releases:
                continue
            status = s.get("status")
            if status in ("needed", "pending"):
                lines[s["release_codename"]] = [status, ""]
            elif status == "released" and s.get("description"):
                lines[s["release_codename"]] = ["released", str(s["description"]).strip()]
        if lines:
            packages[name] = dict(sorted(lines.items()))
    if not packages:
        return None
    return {"severity": SEVERITY.get(str(rec.get("priority", "")).lower(), "medium"),
            "published": str(rec.get("published", ""))[:10], "packages": dict(sorted(packages.items()))}


def merge(state, cid, entry):
    """Take an entry of a CVE; what two releases said of the same package is put together."""
    old = state.setdefault(cid, {"severity": entry["severity"], "published": entry["published"], "packages": {}})
    for name, lines in entry["packages"].items():
        old["packages"].setdefault(name, {}).update(lines)
        old["packages"][name] = dict(sorted(old["packages"][name].items()))
    old["packages"] = dict(sorted(old["packages"].items()))


def crawl_ubuntu(releases=UBUNTU_RELEASES, max_pages=None, today=None):
    """The CVEs of the Ubuntu tracker (critical and high): open in a release, and released lately (the list is newest first)."""
    cutoff = ((today or datetime.now(timezone.utc)) - timedelta(days=RELEASED_DAYS)).strftime("%Y-%m-%d")
    cves = {}
    for release in releases:
        for statuses, recent_only in ((("needed", "pending"), False), (("released",), True)):
            offset, pages = 0, 0
            while True:
                url = (f"{UBUNTU_LIST}?limit=20&offset={offset}&version={release}&priority=critical&priority=high&"
                       + "&".join(f"status={s}" for s in statuses))
                page = fetch(url)
                recs = page.get("cves", [])
                for rec in recs:
                    if recent_only and str(rec.get("published", ""))[:10] < cutoff:
                        continue
                    entry = ubuntu_record(rec, releases)
                    if entry:
                        merge(cves, rec["id"], entry)
                offset += 20
                pages += 1
                older = recs and all(str(r.get("published", ""))[:10] < cutoff for r in recs)
                if not recs or offset >= page.get("total_results", 0) or (recent_only and older) or (max_pages and pages >= max_pages):
                    break
    return cves


# ---------------------------------------------------------------------------------------------------------------
# Debian


def debian_record(releases_info, releases=DEBIAN_RELEASES, year=None):
    """({release: [status, fixed version]}, severity) of a CVE of one source package in the Debian tracker: open (not unimportant /
    end-of-life) with urgency medium or more, and fixed of this year or last, None when there is nothing to report."""
    lines, severity = {}, "low"
    for release, info in releases_info.items():
        if release not in releases:
            continue
        status, fixed, urgency = info.get("status"), str(info.get("fixed_version") or ""), str(info.get("urgency") or "").lower()
        level = SEVERITY.get(urgency.split("*")[0].strip(), "medium")
        if urgency.startswith(("unimportant", "end-of-life")) or RANK[level] < RANK["medium"]:
            continue
        if status == "open":
            lines[release] = ["needed", ""]
        elif status == "resolved" and fixed not in ("", "0"):
            lines[release] = ["released", fixed]
        else:
            continue
        if RANK[level] > RANK[severity]:
            severity = level
    return (dict(sorted(lines.items())), severity) if lines else None


def ingest_debian(data, today=None):
    """{CVE: {'severity', 'published', 'packages'}} of the Debian tracker JSON ({source: {CVE: {'releases': {...}}}})."""
    year = (today or datetime.now(timezone.utc)).year
    cves = {}
    for source, records in data.items():
        if source.startswith("linux") and not KERNEL.match(source):
            continue
        for cid, record in records.items():
            if not cid.startswith("CVE-"):
                continue
            found = debian_record(record.get("releases", {}))
            if not found:
                continue
            lines, severity = found
            # What is fixed is reported for this year's CVEs and last year's, what is open for all.
            if all(line[0] == "released" for line in lines.values()) and int(cid.split("-")[1]) < year - 1:
                continue
            entry = cves.setdefault(cid, {"severity": severity, "published": "", "packages": {}})
            if RANK[severity] > RANK[entry["severity"]]:
                entry["severity"] = severity
            entry["packages"][source] = lines
    for entry in cves.values():
        entry["packages"] = dict(sorted(entry["packages"].items()))
    return cves


# ---------------------------------------------------------------------------------------------------------------
# The rules


def bucket(source):
    """The rule a source package is in: the kernels together (one CVE has the same lines for all of them, see group), the rest by a hash."""
    return "kernel" if source.startswith("linux") else f"{int(hashlib.sha1(source.encode()).hexdigest()[:8], 16) % BUCKETS:02d}"


def prioritise(cves):
    """The CVE ids in the order they are given room: open ones first, the more severe, the newer."""
    def order(item):
        cid, e = item
        is_open = any(line[0] != "released" for lines in e["packages"].values() for line in lines.values())
        return (not is_open, -RANK[e["severity"]], -int(e.get("published", "").replace("-", "") or 0), cid)
    return [cid for cid, _ in sorted(cves.items(), key=order)]


def actionable(source, severity, lines):
    """The lines worth a finding. The kernel has hundreds of high CVEs that a release has not fixed (the tracker lists every one of
    kernel.org's): they would be a finding of 600 CVEs nobody can act on, so an open kernel CVE counts when it is critical, a fixed one
    (the kernel is below the fix: update and reboot) when it is high or critical."""
    if source.startswith("linux") and severity != "critical":
        return {release: line for release, line in lines.items() if line[0] == "released"}
    return lines


def group(packages):
    """{source package: lines} with the sources that have the same lines as one key ("linux,linux-aws,linux-gcp")."""
    same = {}
    for source, lines in sorted(packages.items()):
        same.setdefault(json.dumps(lines, sort_keys=True), []).append(source)
    return {",".join(sources): packages[sources[0]] for sources in same.values()}


def signed(sources):
    """The names the signed kernel packages are built from: linux-signed, linux-signed-amd64, linux-signed-aws."""
    out = set()
    for s in sources:
        if s == "linux":
            out |= {"linux-signed", "linux-signed-amd64", "linux-signed-arm64"}
        elif s.startswith("linux-"):
            out.add("linux-signed-" + s[len("linux-"):])
    return out


def covered():
    """{(tracker, CVE, source package)} the rules of cve2feed.py (from the NVD) already judge with the word of a tracker: a CVE is
    one entry for a package, so the rules of the trackers leave these out."""
    pairs = set()
    for path in (ROOT / "rules" / "any").glob("org.cve-*.json"):
        for cve in json.loads(path.read_text()).get("cves", []):
            for tracker in ("ubuntu", "debian"):
                pairs |= {(tracker, cve["id"], source.lower()) for names in cve.get(tracker, {}) for source in names.split(",")}
    return pairs


def build(distro, cves, taken=frozenset()):
    """({key: rule}, {key: fixture}) of the CVEs of one distribution ('ubuntu' or 'debian'); `taken`: see covered().

    The rules take as many CVEs as fit in BYTES[distro] as written, in the order of prioritise()."""
    cves = {cid: {**e, "packages": {s: l for s, l in ((s, actionable(s, e["severity"], l)) for s, l in e["packages"].items())
                                    if l and (distro, cid, s.lower()) not in taken}} for cid, e in cves.items()}
    ids = [cid for cid in prioritise(cves) if cves[cid]["packages"]]

    def fits(rules):
        sizes = [len(json.dumps(r, separators=(",", ":"))) for r in rules.values()]
        return sum(sizes) <= BYTES[distro] and max(sizes, default=0) <= MAX_RULE

    best = _build(distro, cves, ids)
    if fits(best[0]):
        return best
    low, high, best = 0, len(ids), ({}, {})
    while low < high:  # the most CVEs that fit
        mid = (low + high + 1) // 2
        built = _build(distro, cves, ids[:mid])
        if fits(built[0]):
            low, best = mid, built
        else:
            high = mid - 1
    return best


def _build(distro, cves, ids):
    buckets = {}
    for cid in sorted(ids):
        e = cves[cid]
        for source, lines in e["packages"].items():
            # A kernel CVE has a line per release and flavour: one rule per release keeps the files small (a device is of one release,
            # so only the rule of its release finds anything).
            parts = {f"kernel-{release}": {release: line} for release, line in lines.items()} if bucket(source) == "kernel" else {bucket(source): lines}
            for n, part in parts.items():
                b = buckets.setdefault(n, {"sources": set(), "cves": {}})
                b["sources"].add(source)
                b["cves"].setdefault(cid, {"id": cid, "severity": e["severity"], "ranges": [], distro: {}})[distro][source] = part
    rules, fixtures = {}, {}
    label = distro.capitalize()
    for n, b in sorted(buckets.items()):
        key = f"org.distro-{distro}-{n}"
        names = sorted(b["sources"] | signed(b["sources"]))
        select = {"all": [
            {"field": "Source", "op": "eq", "value": "dpkg"},
            {"any": [{"field": "SourcePackage", "op": "in", "value": names},
                     {"all": [{"field": "SourcePackage", "op": "empty"}, {"field": "Name", "op": "in", "value": names}]}]},
        ]}
        cve_list = [{**c, distro: group(c[distro])} for c in b["cves"].values()]
        rule = {
            "key": key,
            "name": f"{label} kernel: known vulnerabilities" if n.startswith("kernel") else f"{label} packages: known vulnerabilities",
            "description": f"What the {label} security tracker says of the source packages of this rule: the critical and high CVEs that a supported "
                           f"release has not fixed, and the ones it fixed lately. Judged one CVE at a time (installed < fixed), the changelog of the package "
                           f"counts as a fix; {len(cve_list)} CVEs of {len(b['sources'])} source packages.",
            "severity": max((c["severity"] for c in cve_list), key=RANK.get),
            "platform": "linux",
            "source": "software",
            "select": select,
            "cves": cve_list,
            "remediation": "Update the package: sudo apt update && sudo apt full-upgrade" + (" (then sudo apt autoremove --purge removes the old kernels)." if n.startswith("kernel") else "."),
            "urls": [f"https://nvd.nist.gov/vuln/detail/{cve_list[0]['id']}"],
        }
        if feed.rule_errors(rule, False):
            raise SystemExit(f"{key}: {'; '.join(feed.rule_errors(rule, False))}")
        rules[key] = rule
        fixtures[key] = fixture(rule, distro)
    return rules, fixtures


def fixture(rule, distro):
    """A fixture proven against the rule itself: a package that a release has an open CVE of (else one that is below a fix)
    must be found, and a package of another rule, a snap of the same name and a package whose changelog names the CVEs must not."""
    import cves as evaluator
    candidates = [(names.split(",")[0], release, line) for cve in rule["cves"] for names, lines in cve[distro].items() for release, line in lines.items()]
    source, release, _ = sorted(candidates, key=lambda c: c[2][0] == "released")[0]
    origin = distro.capitalize()
    item = {"Name": source, "Version": "0.0.1", "Source": "dpkg", "Origin": origin}
    named = [c["id"] for c in rule["cves"] if any(source in names.split(",") for names in c[distro])]
    negative = [{"Name": "not-a-package-of-this-rule", "Version": "1.0", "Source": "dpkg", "Origin": origin},
                {**item, "Source": "snap"},
                {**item, "FixedCves": "," + ",".join(named) + ","}]
    affects = lambda i: feed.test(rule["select"], i) and bool(evaluator.affecting(rule["cves"], i, release, distro))
    # A fixture is kept only when the rule really does what it says.
    assert affects(item) and not any(affects(n) for n in negative), rule["key"]
    return {"key": rule["key"], "context": {"release": release, "os": distro}, "positive": [item], "negative": negative}


def write(rules, fixtures):
    """Replace the generated files by these; True when something changed."""
    changed = False
    rule_dir, fixture_dir = ROOT / "rules" / "linux", ROOT / "tests" / "fixtures"
    wanted = {rule_dir / f"{k}.json": json.dumps(r, separators=(",", ":")) + "\n" for k, r in rules.items()}
    wanted |= {fixture_dir / f"{k.removeprefix('org.')}.json": json.dumps(f, indent=1) + "\n" for k, f in fixtures.items()}
    for old in list(rule_dir.glob("org.distro-*.json")) + list(fixture_dir.glob("distro-*.json")):
        if old not in wanted:
            old.unlink()
            changed = True
    for path, text in wanted.items():
        if not path.exists() or path.read_text() != text:
            path.write_text(text)
            changed = True
    return changed


def load_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {"ubuntu": {}, "debian": {}}


def save_state(state):
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, indent=None, sort_keys=True, separators=(",", ":")) + "\n")


def generate(state):
    rules, fixtures = {}, {}
    taken = covered()
    for distro in ("ubuntu", "debian"):
        if state.get(distro):
            r, f = build(distro, state[distro], taken)
            rules |= r
            fixtures |= f
    return rules, fixtures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="only regenerate from data/distro.json")
    ap.add_argument("--no-ubuntu", action="store_true")
    ap.add_argument("--no-debian", action="store_true")
    ap.add_argument("--import-debian", help="take the Debian tracker data of this JSON file instead of downloading it")
    ap.add_argument("--max-pages", type=int, help="at most N pages of the Ubuntu list per release and kind (to try it out)")
    args = ap.parse_args()

    state = load_state()
    if not args.offline:
        if not args.no_ubuntu:
            try:
                state["ubuntu"] = crawl_ubuntu(max_pages=args.max_pages)
                print(f"{len(state['ubuntu'])} CVE(s) of the Ubuntu tracker")
            except FetchError as e:
                print(f"::warning::Ubuntu tracker: {e}; the data stays as it was", file=sys.stderr)
        if not args.no_debian:
            try:
                data = json.loads(Path(args.import_debian).read_text()) if args.import_debian else fetch(DEBIAN_API, timeout=600)
                state["debian"] = ingest_debian(data)
                print(f"{len(state['debian'])} CVE(s) of the Debian tracker")
            except (FetchError, OSError, ValueError) as e:
                print(f"::warning::Debian tracker: {e}; the data stays as it was", file=sys.stderr)
        save_state(state)
    rules, fixtures = generate(state)
    changed = write(rules, fixtures)
    if changed and not args.offline:
        manifest = ROOT / "manifest.json"
        if manifest.exists():
            import cve2feed
            m = json.loads(manifest.read_text())
            manifest.write_text(json.dumps({"version": cve2feed.bump(m["version"]), "files": m["files"]}, indent=2) + "\n")
    print(f"{sum(len(state.get(d, {})) for d in ('ubuntu', 'debian'))} CVE(s) -> {len(rules)} rule(s)")


if __name__ == "__main__":
    main()
