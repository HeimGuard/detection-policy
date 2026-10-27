"""What a rule with `cves` finds on a package: the Python twin of SecurityCves of Laravel-MDM-Server.

A rule lists its CVEs ({id, severity, ranges, ubuntu, debian}); a package is affected by the CVEs it is below the fix of
(installed < fixed, never equal). Used by feed.py to check the fixtures of the rules that have no `when` (the rules of the
trackers), and by the tests. Keep it in step with app/Support/SecurityCves.php.
"""
import re

import feed

STATUSES = ["no_fix", "no_source", "fix_via_pro", "update_available", "not_triaged"]  # the most urgent first
UBUNTU_RELEASES = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute"}
DEBIAN_RELEASES = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}


def release(os_item):
    if not os_item:
        return None
    codename = str(os_item.get("Codename") or "").strip().lower()
    version = str(os_item.get("Version") or "").strip()
    if codename:
        return codename
    table = DEBIAN_RELEASES if str(os_item.get("Id") or "").lower() == "debian" else UBUNTU_RELEASES
    return table.get(version)


def tracker_of(os_id):
    os_id = str(os_id or "").strip().lower()
    return "debian" if os_id == "debian" else "ubuntu" if os_id in ("", "ubuntu") else None


def tracker_source(source):
    return re.sub(r"^linux-signed(?:-(?:amd64|arm64|i386))?", "linux", str(source).strip().lower())


def normal_arch(arch):
    """amd64 for x86_64, arm64 for aarch64: the names of dpkg, whatever `uname -m` says."""
    arch = str(arch or "").strip().lower()
    return {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64", "armv8l": "arm64"}.get(arch, arch)


def upstream(version):
    """The version of the project behind a package version: no epoch, no revision, no +dfsg / ~ds suffix."""
    _, up, _ = feed.dpkg_parts(str(version).strip())
    return re.sub(r"[+~](dfsg|ds|repack|really|git|svn|bzr)[^-]*$", "", up, flags=re.I)


def _in_ranges(ranges, version, cmp):
    for rng in ranges:
        start, excl, incl = (list(rng) + [None, None, None])[:3]
        if start and cmp(version, str(start)) < 0:
            continue
        if (cmp(version, str(excl)) < 0) if excl else (incl and cmp(version, str(incl)) <= 0):
            return True
    return False


def _fixed_in(ranges, version, cmp):
    for rng in ranges:
        start, excl = (list(rng) + [None, None])[:2]
        if excl and (not start or cmp(version, str(start)) >= 0) and cmp(version, str(excl)) < 0:
            return str(excl)
    return None


def _loose(a, b):
    ta, tb = feed.version_tuple(a), feed.version_tuple(b)
    return 0 if ta is None or tb is None else feed.version_compare(ta, tb)


def _tracker_lines(sources, source):
    """The lines for a source package; a key may name several with commas ("linux,linux-aws": the same lines for each)."""
    for names, releases in (sources or {}).items():
        if isinstance(releases, dict) and releases and any(tracker_source(n) == source for n in names.split(",")):
            return {k.lower(): v for k, v in releases.items()}
    return None


def _dpkg(cve, item, rel, os_id):
    version = str(item.get("Version") or "").strip()
    candidate = str(item.get("Candidate") or "").strip()
    origin = str(item.get("Origin") or "").strip().lower()
    source = tracker_source(item.get("SourcePackage") or item.get("Name") or "")
    tracker = tracker_of(os_id)
    if origin in ("", "ubuntu", "debian") and rel is not None and tracker is not None:
        known = _tracker_lines(cve.get(tracker), source)
        if known is not None:
            line = known.get(rel)
            if line is None:
                return None
            status, fixed = str(line[0]).lower(), str(line[1] if len(line) > 1 else "").strip()
            if status == "not-affected":
                return None
            if status == "released" and fixed:
                if version and feed.dpkg_compare(version, fixed) >= 0:
                    return None
                if candidate and feed.dpkg_compare(candidate, fixed) >= 0:
                    return {"status": "update_available", "fixed": fixed}
                return {"status": "fix_via_pro" if "esm" in fixed.lower() else "update_available", "fixed": fixed}
            return {"status": "not_triaged" if status == "needs-triage" else "no_fix", "fixed": None}
    ranges = cve.get("ranges") or []
    up = upstream(version)
    if not up or not _in_ranges(ranges, up, feed.dpkg_compare):
        return None
    fixed = _fixed_in(ranges, up, feed.dpkg_compare)
    if candidate and feed.dpkg_compare(candidate, version) > 0 and not _in_ranges(ranges, upstream(candidate), feed.dpkg_compare):
        return {"status": "update_available", "fixed": fixed}
    return {"status": "no_source" if origin == "dpkg/status" else "no_fix", "fixed": fixed}


def _other(cve, item):
    version = str(item.get("Version") or "").strip()
    ranges = cve.get("ranges") or []
    if not version or feed.version_tuple(version) is None or not _in_ranges(ranges, version, _loose):
        return None
    fixed = _fixed_in(ranges, version, _loose)
    if str(item.get("Source") or "").lower() == "snap" and str(item.get("Channel") or "").strip():
        candidate = str(item.get("Candidate") or "").strip()
        if candidate and not _in_ranges(ranges, candidate, _loose):
            return {"status": "update_available", "fixed": fixed}
        return {"status": "no_fix", "fixed": fixed}
    return {"status": "update_available", "fixed": fixed}


def affecting(cves, item, rel=None, os_id=None, arch=None):
    """{CVE id: {id, severity, status, fixed}} of the CVEs of a rule that affect the item."""
    found = {}
    dpkg = str(item.get("Source") or "").lower() == "dpkg"
    changelog = str(item.get("FixedCves") or "").lower()
    for cve in cves:
        if not cve.get("id"):
            continue
        if dpkg and changelog and f",{cve['id'].lower()}," in changelog:
            continue
        if arch and cve.get("arch") and normal_arch(arch) not in [normal_arch(a) for a in cve["arch"]]:
            continue  # a CVE of the cores of another CPU family
        result = _dpkg(cve, item, rel, os_id) if dpkg else _other(cve, item)
        if result is not None:
            found[cve["id"]] = {"id": cve["id"], "severity": cve.get("severity", "medium"), **result}
    return found
