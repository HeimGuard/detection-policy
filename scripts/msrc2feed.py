#!/usr/bin/env python3
"""Turn the security updates of Microsoft (MSRC CVRF API) into rules of the feed.

  python scripts/msrc2feed.py [--months 2]    # the latest monthly updates of the MSRC, update the state, regenerate
  python scripts/msrc2feed.py --offline       # regenerate rules / fixtures from data/msrc.json only

The CVRF API (https://api.msrc.microsoft.com/cvrf/v3.0, `/updates` and `/cvrf/{id}`) says for every CVE of a monthly
update, per product, the build that fixes it (`FixedBuild`). A rule is **a missing update**: the CVEs a build fixes
(10.0.19045.7807) are one rule, "older than that build" is its condition, so a host sees exactly the updates it lacks and the
CVEs each of them fixes (a host that lacks three cumulative updates has three findings; one that has the newest has none):

- **Windows 10 / 11 / Server 2016 and later** (the builds 10.0.x), one family per build of the operating system (10.0.19045 ...):
  the agent (1.27.0+) lists the operating system as the `os` source, its build with the revision is the version
  (10.0.19045.5555). Client and server with the same build share the fixes.
- **Microsoft Edge** (Windows: "Microsoft Edge", Linux: microsoft-edge-*) and **Visual Studio Code**, software.

Not here: Windows 7 to 8.1 and Server 2012 (security-only and monthly rollups have builds of their own, ESU), Hotpatch builds,
.NET, Office, SQL Server and Exchange (their names and versions in Programs and Features, and the bands of the .NET SDK,
whose fixed builds are not comparable with the runtime's, were not checked on a device).

data/msrc.json keeps, per monthly update, the CVEs each family fixes by build (not the 30 MB documents); the rules and
fixtures under rules/*/org.msrc-*.json and tests/fixtures/msrc-*.json are a pure function of it (CI checks `--offline`).
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cve2feed  # noqa: E402  (requests with retries, the manifest version)
import feed  # noqa: E402  (the same rule checks and matching as CI)

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.msrc.microsoft.com/cvrf/v3.0"
STATE = ROOT / "data" / "msrc.json"
SEVERITY = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}
RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
BUILD = re.compile(r"^\d+(\.\d+){2,3}$")
HEADERS = {"Accept": "application/json", "User-Agent": "detection-policy-msrc2feed"}


# ---------------------------------------------------------------------------------------------------------------
# What the MSRC says


def family_of(cpe, fixed):
    """The family of a product of the CVRF (by its CPE) and the version it is fixed in, None when we do not look at it."""
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    part, product = parts[2], parts[4]
    # The operating system by the build that fixes it (10.0.19045.7807). Some releases are listed with the part "a"
    # (Windows 11 version 26H2), and "a" has Windows Admin Center, Defender and the like: the product has to be an OS.
    if part in ("o", "a") and re.match(r"windows_(10|11|server)", product) and re.match(r"^10\.0\.\d+\.\d+$", fixed):
        return "windows:" + ".".join(fixed.split(".")[:3])
    # The Chromium version of Edge (154.0.4258.37, not the 7.1.0 of Edge for iOS the same CPE product also has) and the one of Code.
    if part == "a" and product == "microsoft_edge_chromium-based" and re.match(r"^\d{3}\.0\.\d+\.\d+$", fixed):
        return "edge"
    if part == "a" and product == "visual_studio_code" and re.match(r"^1\.\d+\.\d+$", fixed):
        return "vscode"
    return None


def fit(head, items, tail="", limit=1000):
    """head + as many items as fit (+ 'and n more') + tail within `limit` characters."""
    shown = []
    for item in items:
        more = len(items) - len(shown) - 1
        if len(head + ", ".join(shown + [item]) + (f" and {more} more" if more else "") + tail) > limit:
            break
        shown.append(item)
    more = len(items) - len(shown)
    return head + ", ".join(shown) + (f" and {more} more" if more else "") + tail


def newer(a, b):
    return b is None or feed.version_compare(feed.version_tuple(a), feed.version_tuple(b)) > 0


def extract(doc):
    """{"families": {family: {fixed build: "2026-1:h,2026-2:cx"}}, "names": {family: [...]}} of one CVRF document: the CVEs
    (without "CVE-") each family fixes by build, with the severity (c, h, m, l) and x when exploited."""
    products = {p["ProductID"]: p for p in doc["ProductTree"]["FullProductName"]}
    found, names = {}, {}
    for v in doc["Vulnerability"]:
        cve = v["CVE"].removeprefix("CVE-")
        severity, exploited = {}, {}
        for t in v.get("Threats", []):
            for pid in t.get("ProductID") or []:
                text = (t.get("Description") or {}).get("Value") or ""
                if t["Type"] == 3:
                    severity[pid] = SEVERITY.get(text.lower())
                elif t["Type"] == 1:
                    exploited[pid] = "Exploited:Yes" in text
        per_family = {}
        for r in v.get("Remediations", []):
            fixed = r.get("FixedBuild") or ""
            if r.get("Type") != 2 or not BUILD.match(fixed):
                continue
            for pid in r.get("ProductID") or []:
                product = products.get(pid)
                family = family_of(product["CPE"], fixed) if product and product.get("CPE") else None
                if not family:
                    continue
                entry = per_family.setdefault(family, {"fixed": fixed, "severity": None, "exploited": False})
                if newer(fixed, entry["fixed"]):
                    entry["fixed"] = fixed
                if severity.get(pid) and (entry["severity"] is None or RANK[severity[pid]] > RANK[entry["severity"]]):
                    entry["severity"] = severity[pid]
                entry["exploited"] = entry["exploited"] or exploited.get(pid, False)
                if family.startswith("windows:"):
                    names.setdefault(family, set()).add(re.sub(r"( for (x64-based|ARM64-based|32-bit|x86-based|Itanium-based) Systems| \(Server Core installation\))", "", product["Value"]).strip())
        for family, entry in per_family.items():
            letter = {"critical": "c", "high": "h", "medium": "m", "low": "l"}[entry["severity"] or "high"]
            found.setdefault(family, {}).setdefault(entry["fixed"], {})[cve] = letter + ("x" if entry["exploited"] else "")
    return {"families": {family: {fixed: ",".join(f"{cve}:{code}" for cve, code in sorted(cves.items())) for fixed, cves in sorted(builds.items())}
                         for family, builds in sorted(found.items())},
            "names": {family: sorted({n.lower(): n for n in sorted(values, reverse=True)}.values())[:3] for family, values in sorted(names.items())}}


def latest_updates(months):
    """[(id, CurrentReleaseDate, InitialReleaseDate)] of the latest `months` monthly updates, newest first."""
    page = cve2feed.request(f"{API}/updates", HEADERS)
    updates = sorted(page.get("value", []), key=lambda u: u.get("InitialReleaseDate") or "", reverse=True)
    return [(u["ID"], u["CurrentReleaseDate"], u.get("InitialReleaseDate") or "") for u in updates[:months]]


def refresh(state, months):
    """Downloads the updates that are new or revised and forgets the ones that are out of the window; True when changed."""
    wanted = {update_id: (released, initial) for update_id, released, initial in latest_updates(months)}
    changed = False
    for update_id in list(state["docs"]):
        if update_id not in wanted:
            del state["docs"][update_id]
            changed = True
    for update_id, (released, initial) in wanted.items():
        if state["docs"].get(update_id, {}).get("released") == released:
            continue
        print(f"{update_id}: downloading ({released})", file=sys.stderr)
        state["docs"][update_id] = {"released": released, "initial": initial, **extract(cve2feed.request(f"{API}/cvrf/{update_id}", HEADERS))}
        changed = True
    return changed


# ---------------------------------------------------------------------------------------------------------------
# The rules


def merge(state):
    """{(family, fixed build): {"cves": {cve: code}, "updates": [...]}, ...} and {family: [names]} over the updates of the window.
    A CVE that two updates list is the one of the newer update (its build), so every CVE is counted once."""
    groups, names, seen = {}, {}, set()
    for update_id, doc in sorted(state["docs"].items(), key=lambda d: d[1].get("initial", ""), reverse=True):
        for family, builds in doc["families"].items():
            names.setdefault(family, set()).update(doc["names"].get(family, []))
            for fixed, cves in builds.items():
                for item in filter(None, cves.split(",")):
                    cve, code = item.split(":")
                    if (family, cve) in seen:
                        continue
                    seen.add((family, cve))
                    group = groups.setdefault((family, fixed), {"cves": {}, "updates": []})
                    group["cves"][cve] = code
                    if update_id not in group["updates"]:
                        group["updates"].append(update_id)
    return groups, {family: sorted({n.lower(): n for n in sorted(values, reverse=True)}.values())[:3] for family, values in names.items()}


def label(family, names):
    if family == "edge":
        return "Microsoft Edge"
    if family == "vscode":
        return "Visual Studio Code"
    return f"{', '.join(names) or 'Windows'} (build {family.split(':', 1)[1]})"


def source_of(family):
    return "os" if family.startswith("windows:") else "software"


def when(family, fixed):
    older = {"field": "Version", "op": "version_lt", "value": fixed}
    if family.startswith("windows:"):
        # The operating system as the agent lists it (the os source, the build with the revision as the version, agents 1.27.0+).
        return {"all": [{"field": "Id", "op": "eq", "value": "windows"},
                        {"field": "Version", "op": "starts_with", "value": family.split(":", 1)[1] + "."}, older]}
    if family == "edge":
        return {"all": [{"any": [
            {"all": [{"field": "Source", "op": "ne", "value": "dpkg"}, {"field": "Name", "op": "matches", "value": r"^microsoft edge$"}]},
            {"all": [{"field": "Source", "op": "eq", "value": "dpkg"}, {"field": "Name", "op": "matches", "value": r"^microsoft-edge(-stable|-beta|-dev)?$"}]},
        ]}, older]}
    return {"all": [{"any": [
        {"field": "Name", "op": "matches", "value": r"^microsoft visual studio code( \(user\))?$"},
        {"all": [{"field": "Name", "op": "eq", "value": "code"}, {"field": "Source", "op": "in", "value": ["dpkg", "snap"]}]},
        {"field": "Name", "op": "eq", "value": "com.visualstudio.code"},
    ]}, older]}


def build_rule(family, fixed, group, names):
    name = label(family, names)
    cves = sorted(group["cves"].items(), key=lambda c: (not c[1].endswith("x"), "chml".index(c[1][0]), c[0]))
    exploited = [f"CVE-{cve}" for cve, code in cves if code.endswith("x")]
    texts = [f"CVE-{cve}{' (exploited)' if code.endswith('x') else ''}" for cve, code in cves]
    tail = f": the update {fixed} is missing ({len(cves)} CVEs)"
    slug = family.replace(":", "-").replace(".", "-") + "-" + (fixed.rsplit(".", 1)[1] if family.startswith("windows:") else fixed.replace(".", "-"))
    severity = {"c": "critical", "h": "high", "m": "medium", "l": "low"}[min((code[0] for _, code in cves), key=lambda l: "chml".index(l))]
    remediation = {"edge": "Update Microsoft Edge.", "vscode": "Update Visual Studio Code."}.get(family, "Install the latest cumulative update (Windows Update).")
    return {
        "key": f"org.msrc-{slug}",
        "name": f"{name[:120 - len(tail)]}{tail}",
        "description": fit(f"Microsoft's security update {fixed} of {name} fixes {len(cves)} CVEs ({', '.join(group['updates'])}).{(' Exploited: ' + ', '.join(exploited[:10]) + '.') if exploited else ''} CVEs: ", texts)[:1000],
        "severity": severity,
        "platform": "windows" if family.startswith("windows:") else "any",
        "source": source_of(family),
        "when": when(family, fixed),
        "message": fit("{Name} {Version} is older than " + fixed + f", the update that fixes {len(cves)} CVEs: ", texts)[:1000],
        "remediation": remediation,
        "urls": [f"https://msrc.microsoft.com/update-guide/vulnerability/CVE-{c[0]}" for c in cves[:6]] + ["https://msrc.microsoft.com/update-guide"],
    }


def before(version):
    """A version just under `version` (for the fixture)."""
    nums = [int(x) for x in re.findall(r"\d+", version)] or [1]
    for i in range(len(nums) - 1, -1, -1):
        if nums[i] > 0:
            nums[i] -= 1
            return ".".join(map(str, nums))
    return "0"


def make_fixture(rule, family, fixed):
    """A fixture proven against the rule itself, None when the rule does not behave."""
    below = before(fixed)
    if family.startswith("windows:"):
        build = family.split(":", 1)[1]
        os_item = lambda version, id="windows": {"Id": id, "Name": "Microsoft Windows", "Version": version}
        positive = [os_item(f"{build}.0"), os_item(below)]
        negative = [os_item(fixed), os_item(f"{fixed}.1"), os_item("10.0.1.0"), os_item(f"{build}.0", "ubuntu")]
    elif family == "edge":
        positive = [{"Name": "Microsoft Edge", "Version": below, "Source": "registry"},
                    {"Name": "microsoft-edge-stable", "Version": f"{below}-1", "Source": "dpkg"}]
        negative = [{"Name": "Microsoft Edge", "Version": fixed, "Source": "registry"}, {"Name": "Microsoft Edge WebView2 Runtime", "Version": below, "Source": "registry"},
                    {"Name": "Microsoft Edge Update", "Version": "1.3.1", "Source": "registry"}, {"Name": "microsoft-edge-stable", "Version": f"{fixed}-1", "Source": "dpkg"},
                    {"Name": "Microsoft Edge", "Version": below, "Source": "dpkg"}]
    else:
        positive = [{"Name": "Microsoft Visual Studio Code", "Version": below, "Source": "registry"},
                    {"Name": "Microsoft Visual Studio Code (User)", "Version": below, "Source": "registry (user)"},
                    {"Name": "code", "Version": f"{below}-1792691907", "Source": "dpkg"}]
        negative = [{"Name": "Microsoft Visual Studio Code", "Version": fixed, "Source": "registry"}, {"Name": "code", "Version": f"{fixed}-1", "Source": "dpkg"},
                    {"Name": "code", "Version": below, "Source": "registry"}, {"Name": "Visual Studio Code Insiders", "Version": below, "Source": "registry"}]
    if not all(feed.test(rule["when"], i) for i in positive) or any(feed.test(rule["when"], i) for i in negative):
        return None
    return {"key": rule["key"], "positive": positive, "negative": negative}


def generate(state):
    rules, fixtures, skipped = {}, {}, []
    groups, names = merge(state)
    for (family, fixed), group in sorted(groups.items()):
        rule = build_rule(family, fixed, group, names.get(family, []))
        errors = feed.rule_errors(rule, False)
        fixture = None if errors else make_fixture(rule, family, fixed)
        if errors or fixture is None:
            skipped.append(f"{rule['key']}: {'; '.join(errors) if errors else 'no valid fixture could be built'}")
            continue
        rules[rule["key"]] = rule
        fixtures[rule["key"]] = fixture
    return rules, fixtures, skipped


def write(rules, fixtures):
    """Replace the generated files by these; True when something changed."""
    changed = False
    wanted = {}
    for key, rule in rules.items():
        wanted[ROOT / "rules" / rule["platform"] / f"{key}.json"] = json.dumps(rule, indent=2) + "\n"
        wanted[ROOT / "tests" / "fixtures" / f"{key.removeprefix('org.')}.json"] = json.dumps(fixtures[key], indent=2) + "\n"
    for old in list((ROOT / "rules").glob("*/org.msrc-*.json")) + list((ROOT / "tests" / "fixtures").glob("msrc-*.json")):
        if old not in wanted:
            old.unlink()
            changed = True
    for path, text in wanted.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text() != text:
            path.write_text(text)
            changed = True
    return changed


def load_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {"docs": {}}


def save_state(state):
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=2, help="the latest N monthly updates")
    ap.add_argument("--offline", action="store_true", help="only regenerate from data/msrc.json")
    args = ap.parse_args()

    state = load_state()
    if not args.offline:
        try:
            refresh(state, args.months)
        except cve2feed.NvdError as e:
            sys.exit(f"{e}")
        save_state(state)
    rules, fixtures, skipped = generate(state)
    for reason in skipped:
        print(f"skipped {reason}", file=sys.stderr)
    changed = write(rules, fixtures)
    if changed and not args.offline:
        manifest = ROOT / "manifest.json"
        m = json.loads(manifest.read_text())
        manifest.write_text(json.dumps({"version": cve2feed.bump(m["version"]), "files": m["files"]}, indent=2) + "\n")
    print(f"{len(state['docs'])} update(s) -> {len(rules)} rule(s), {len(skipped)} skipped")


if __name__ == "__main__":
    main()
