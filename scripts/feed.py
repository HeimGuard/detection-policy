#!/usr/bin/env python3
"""Validate the rule feed for Laravel-MDM-Server and (re)generate manifest.json.

  python scripts/feed.py check    # validate rules, parsers, policies, fixtures and manifest
  python scripts/feed.py build    # regenerate manifest.json (SHA-256 of every file)

Mirrors the server's checks (app/Support/SecurityRules.php, SecurityParsers.php, CompliancePolicies.php,
SecurityFeed.php).
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
FIELD = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$")
PATH = re.compile(r"^(rules|parsers|policies)/[\w.-]+(/[\w.-]+)*\.json$")
CHECK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
STATUSES = ["fail", "warn", "manual", "pass", "na"]  # worst first
FEED_DIRS = ("rules", "parsers", "policies")
SEVERITIES = {"critical", "high", "medium", "low", "info"}
PLATFORMS = {"any", "windows", "linux"}
SOURCES = {
    "software": ["Name", "Version", "Publisher", "Source"],
    "processes": ["Name", "Path", "CommandLine", "User", "Count"],
    "listening": ["Protocol", "Address", "Port", "Process", "Path"],
    "startup": ["Name", "Command", "Location", "User"],
    "admins": ["Name", "Source", "Enabled"],
    "posture": ["FirewallEnabled", "AntivirusName", "AntivirusEnabled", "AntivirusUpToDate", "RealTimeProtection",
                "DiskEncrypted", "SecureBoot", "RdpEnabled", "RdpNla", "Smb1Enabled", "UacEnabled", "GuestEnabled",
                "AutoLogon", "SshRootLogin", "SshPasswordAuthentication", "AutomaticUpdates", "DaysSinceUpdate"],
    "sqlserver": ["Instance", "Version", "Edition", "Clustered", "Error",
                  "AdHocDistributedQueries", "ClrEnabled", "CrossDbOwnershipChaining", "DatabaseMailXps",
                  "OleAutomationProcedures", "RemoteAccess", "RemoteAdminConnections", "ScanForStartupProcs", "XpCmdshell",
                  "TrustworthyCount", "TrustworthyDatabases", "SaEnabled", "SaName", "WindowsAuthOnly",
                  "SysadminCount", "SysadminLogins", "WeakPolicyCount", "WeakPolicyLogins",
                  "NoFullBackupCount", "NoFullBackupDatabases", "NoLogBackupCount", "NoLogBackupDatabases",
                  "NoCheckDbCount", "NoCheckDbDatabases", "LinkedServerSaCount", "LinkedServersSa",
                  "OwnedBySaCount", "OwnedBySaDatabases", "ForceEncryption", "AllConnectionsEncrypted",
                  "NoTdeCount", "NoTdeDatabases", "ErrorLogCount", "LoginAuditLevel"],
    "events": ["Type", "Count", "User", "Source", "Message", "Last"],
}
# What compliance checks may look at: the inventory, not the events.
POLICY_SOURCES = {k for k in SOURCES if k != "events"}
LOG_SOURCES = {"windows.security", "windows.system", "windows.defender", "linux.auth"}
EVENT_FIELDS = {"type", "user", "source", "message", "count"}
UNARY = {"exists", "empty", "true", "false"}
OPS = {"eq", "ne", "contains", "not_contains", "starts_with", "ends_with", "matches", "not_matches",
       "in", "not_in", "gt", "gte", "lt", "lte", "exists", "empty", "true", "false"}


def rx(pattern):
    return re.compile(re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern), re.I)


def cond_errors(c, path, depth, count, errs):
    count[0] += 1
    if count[0] > 64:
        errs.append("at most 64 conditions")
        return
    if depth > 6:
        errs.append(f"{path}: nested too deep")
        return
    if not isinstance(c, dict):
        errs.append(f"{path}: a condition is an object")
        return
    for g in ("all", "any"):
        if g in c:
            if len(c) != 1 or not isinstance(c[g], list) or not c[g]:
                errs.append(f"{path}: '{g}' is a non-empty list and nothing else")
                return
            for i, ch in enumerate(c[g]):
                cond_errors(ch, f"{path}.{g}.{i}", depth + 1, count, errs)
            return
    if "not" in c:
        if len(c) != 1:
            errs.append(f"{path}: 'not' is one condition and nothing else")
            return
        cond_errors(c["not"], f"{path}.not", depth + 1, count, errs)
        return
    if not isinstance(c.get("field"), str) or not FIELD.match(c["field"]):
        errs.append(f"{path}: bad field")
    op = c.get("op")
    if op not in OPS:
        errs.append(f"{path}: unsupported op {op!r}")
        return
    extra = set(c) - {"field", "op", "value"}
    if extra:
        errs.append(f"{path}: unknown keys {sorted(extra)}")
    if op in UNARY:
        return
    if "value" not in c:
        errs.append(f"{path}: value missing")
        return
    v = c["value"]
    if op in ("in", "not_in"):
        ok = isinstance(v, list) and v and all(not isinstance(x, (list, dict)) for x in v)
    elif op in ("gt", "gte", "lt", "lte"):
        ok = isinstance(v, (int, float)) and not isinstance(v, bool)
    else:
        ok = isinstance(v, (str, int, float, bool))
    if not ok:
        errs.append(f"{path}: unsuitable value for {op}")
    elif op in ("matches", "not_matches"):
        try:
            rx(str(v))
        except re.error as e:
            errs.append(f"{path}: bad regex ({e})")


def get(item, field):
    cur = item
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def test(c, item):
    if "all" in c:
        return all(test(x, item) for x in c["all"])
    if "any" in c:
        return any(test(x, item) for x in c["any"])
    if "not" in c:
        return not test(c["not"], item)
    op, val, got = c["op"], c.get("value"), get(item, c["field"])
    if op == "exists":
        return got is not None and got != ""
    if op == "empty":
        return got in (None, "", [])
    if op == "true":
        return got is True
    if op == "false":
        return got is False
    if got is None:
        return False
    s = str(got).lower()
    if op == "eq":
        return s == str(val).lower()
    if op == "ne":
        return s != str(val).lower()
    if op == "contains":
        return str(val).lower() in s
    if op == "not_contains":
        return str(val).lower() not in s
    if op == "starts_with":
        return s.startswith(str(val).lower())
    if op == "ends_with":
        return s.endswith(str(val).lower())
    if op == "matches":
        return bool(rx(str(val)).search(str(got)))
    if op == "not_matches":
        return not rx(str(val)).search(str(got))
    if op == "in":
        return s in [str(x).lower() for x in val]
    if op == "not_in":
        return s not in [str(x).lower() for x in val]
    try:
        n = float(got)
    except (TypeError, ValueError):
        return False
    return {"gt": n > val, "gte": n >= val, "lt": n < val, "lte": n <= val}[op]


def rule_errors(r, parser):
    errs = []
    if not isinstance(r, dict):
        return ["not a JSON object"]
    if not isinstance(r.get("key"), str) or not KEY.match(r["key"]):
        errs.append("bad key")
    if not isinstance(r.get("name"), str) or not r["name"].strip() or len(r["name"]) > 120:
        errs.append("bad name")
    if parser:
        if r.get("source") not in LOG_SOURCES:
            errs.append(f"source must be one of {sorted(LOG_SOURCES)}")
        if "when" not in r and "pattern" not in r:
            errs.append("parser needs when or pattern")
        if "pattern" in r:
            try:
                rx(r["pattern"])
            except re.error as e:
                errs.append(f"bad pattern ({e})")
        ev = r.get("event")
        if not isinstance(ev, dict) or not re.match(r"^[a-z][a-z0-9_]{1,31}$", str(ev.get("type", ""))):
            errs.append("bad event.type")
        elif set(ev) - EVENT_FIELDS:
            errs.append(f"unknown event keys {sorted(set(ev) - EVENT_FIELDS)}")
    else:
        if r.get("severity") not in SEVERITIES:
            errs.append("bad severity")
        if r.get("platform", "any") not in PLATFORMS:
            errs.append("bad platform")
        if r.get("source") not in SOURCES:
            errs.append(f"source must be one of {sorted(SOURCES)}")
        t = r.get("threshold")
        if t is not None and (not isinstance(t, int) or not 1 <= t <= 10000):
            errs.append("bad threshold")
        for f in ("description", "message", "remediation"):
            if f in r and (not isinstance(r[f], str) or len(r[f]) > 1000):
                errs.append(f"bad {f}")
        if "when" not in r:
            errs.append("when missing")
    if "when" in r:
        cond_errors(r["when"], "when", 1, [0], errs)
    return errs


def policy_errors(p):
    """CompliancePolicies::errors of the server."""
    if not isinstance(p, dict):
        return ["not a JSON object"]
    errs = []
    if not isinstance(p.get("key"), str) or not KEY.match(p["key"]):
        errs.append("bad key")
    if not isinstance(p.get("name"), str) or not p["name"].strip() or len(p["name"]) > 120:
        errs.append("bad name")
    if "description" in p and (not isinstance(p["description"], str) or len(p["description"]) > 1000):
        errs.append("bad description")
    if "version" in p and (not isinstance(p["version"], str) or len(p["version"]) > 32):
        errs.append("bad version")
    if p.get("platform", "any") not in PLATFORMS:
        errs.append("bad platform")
    if "source" in p and p["source"] not in POLICY_SOURCES:
        errs.append(f"source must be one of {sorted(POLICY_SOURCES)}")
    for f in ("applies", "manual"):
        if f in p:
            cond_errors(p[f], f, 1, [0], errs)
    checks = p.get("checks")
    if not isinstance(checks, list) or not checks:
        return errs + ["checks: a list of at least one check"]
    if len(checks) > 300:
        return errs + ["checks: at most 300"]
    ids = set()
    for i, c in enumerate(checks):
        path = f"checks.{i}"
        if not isinstance(c, dict):
            errs.append(f"{path}: not an object")
            continue
        cid = c.get("id")
        if not isinstance(cid, str) or not CHECK_ID.match(cid):
            errs.append(f"{path}: bad id")
        elif cid.lower() in ids:
            errs.append(f"{path}: duplicate id {cid}")
        else:
            ids.add(cid.lower())
            path = cid
        if not isinstance(c.get("name"), str) or not c["name"].strip() or len(c["name"]) > 200:
            errs.append(f"{path}: bad name")
        if c.get("severity") not in SEVERITIES:
            errs.append(f"{path}: bad severity")
        if c.get("source", p.get("source")) not in POLICY_SOURCES:
            errs.append(f"{path}: source must be one of {sorted(POLICY_SOURCES)} (or the policy's)")
        if "reference" in c and (not isinstance(c["reference"], str) or len(c["reference"]) > 120):
            errs.append(f"{path}: bad reference")
        for f in ("description", "message", "remediation"):
            if f in c and (not isinstance(c[f], str) or len(c[f]) > 1000):
                errs.append(f"{path}: bad {f}")
        if "fail" not in c and "warn" not in c:
            errs.append(f"{path}: 'fail' or 'warn' is needed")
        for f in ("applies", "manual", "fail", "warn"):
            if f in c:
                cond_errors(c[f], f"{path}.{f}", 1, [0], errs)
        if "requires" in c and (not isinstance(c["requires"], list) or not all(isinstance(x, str) and FIELD.match(x) for x in c["requires"])):
            errs.append(f"{path}: requires is a list of field names")
        source = c.get("source", p.get("source"))
        if source in SOURCES:
            for field in condition_fields(c) + list(c.get("requires", []) if isinstance(c.get("requires"), list) else []):
                if field.split(".")[0] not in SOURCES[source]:
                    errs.append(f"{path}: {source} has no field {field}")
    return errs


def condition_fields(c, all_ops=True):
    """The fields a check's conditions name (with all_ops False: the ones it cannot be told without)."""
    fields = []

    def walk(x):
        if not isinstance(x, dict):
            return
        for g in ("all", "any"):
            if g in x and isinstance(x[g], list):
                for ch in x[g]:
                    walk(ch)
                return
        if "not" in x:
            walk(x["not"])
            return
        if isinstance(x.get("field"), str) and (all_ops or x.get("op") not in ("exists", "empty")):
            fields.append(x["field"])

    for part in (("applies", "manual", "fail", "warn") if all_ops else ("fail", "warn")):
        walk(c.get(part))
    return list(dict.fromkeys(fields))


def item_status(p, c, item):
    """CompliancePolicies::itemStatus of the server."""
    for applies in (p.get("applies"), c.get("applies")):
        if applies is not None and not test(applies, item):
            return "na"
    for manual in (p.get("manual"), c.get("manual")):
        if manual is not None and test(manual, item):
            return "manual"
    for field in c["requires"] if "requires" in c else condition_fields(c, all_ops=False):
        if get(item, field) in (None, ""):
            return "manual"
    if "fail" in c and test(c["fail"], item):
        return "fail"
    if "warn" in c and test(c["warn"], item):
        return "warn"
    return "pass"


def check_status(p, c, items):
    """The worst status of the items; without items the check does not apply."""
    statuses = [item_status(p, c, i) for i in items if isinstance(i, dict) and i]
    return min(statuses, key=STATUSES.index) if statuses else "na"


def load_policies():
    out = []
    for f in sorted((ROOT / "policies").rglob("*.json")):
        rel = f.relative_to(ROOT).as_posix()
        data = json.loads(f.read_text())
        for d in ([data] if isinstance(data, dict) and "key" in data else data):
            out.append((rel, d))
    return out


def load_definitions():
    out = []
    for f in sorted(list((ROOT / "rules").rglob("*.json")) + list((ROOT / "parsers").rglob("*.json"))):
        rel = f.relative_to(ROOT).as_posix()
        data = json.loads(f.read_text())
        items = [data] if isinstance(data, dict) and "key" in data else data
        for d in items:
            out.append((rel, rel.startswith("parsers/"), d))
    return out


def manifest_files():
    files = {}
    for f in sorted(f for d in FEED_DIRS for f in (ROOT / d).rglob("*.json")):
        files[f.relative_to(ROOT).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    return files


def build():
    mf = ROOT / "manifest.json"
    version = json.loads(mf.read_text())["version"] if mf.exists() else "0.0.0"
    mf.write_text(json.dumps({"version": version, "files": manifest_files()}, indent=2) + "\n")
    print(f"manifest.json: version {version}, {len(manifest_files())} file(s)")


def check():
    errors = []
    defs = load_definitions()
    seen = set()
    for rel, parser, d in defs:
        for e in rule_errors(d, parser):
            errors.append(f"{rel}: {e}")
        key = d.get("key") if isinstance(d, dict) else None
        if key in seen:
            errors.append(f"{rel}: duplicate key {key}")
        seen.add(key)

    policies = load_policies()
    for rel, p in policies:
        for e in policy_errors(p):
            errors.append(f"{rel}: {e}")
        key = p.get("key") if isinstance(p, dict) else None
        if key in seen:
            errors.append(f"{rel}: duplicate key {key}")
        seen.add(key)

    mf = ROOT / "manifest.json"
    if not mf.exists():
        errors.append("manifest.json missing (run: python scripts/feed.py build)")
    else:
        m = json.loads(mf.read_text())
        if not re.match(r"^[\w.+-]{1,32}$", str(m.get("version", ""))):
            errors.append("manifest.json: bad version")
        files = manifest_files()
        for p in files:
            if not PATH.match(p):
                errors.append(f"{p}: path not allowed by the server")
        if m.get("files") != files:
            errors.append("manifest.json is out of date (run: python scripts/feed.py build)")

    by_key = {d["key"]: (rel, parser, d) for rel, parser, d in defs if isinstance(d, dict) and "key" in d}
    covered = set()
    errors += check_policy_fixtures(policies)
    for f in sorted((ROOT / "tests" / "fixtures").rglob("*.json")):
        fx = json.loads(f.read_text())
        if "policy" in fx:
            continue
        entry = by_key.get(fx.get("key"))
        name = f.relative_to(ROOT).as_posix()
        if not entry:
            errors.append(f"{name}: unknown key {fx.get('key')!r}")
            continue
        covered.add(fx["key"])
        _, parser, d = entry
        for kind, expect in (("positive", True), ("negative", False)):
            if not fx.get(kind):
                errors.append(f"{name}: needs at least one {kind} item")
            for i, item in enumerate(fx.get(kind, [])):
                if parser:
                    ok = matches_parser(d, item)
                else:
                    ok = test(d["when"], item)
                if ok != expect:
                    errors.append(f"{name}: {kind}[{i}] {'did not match' if expect else 'matched'}")
    for key in by_key:
        if key not in covered:
            errors.append(f"{key}: no fixture in tests/fixtures")

    for e in errors:
        print("ERROR", e)
    checks = sum(len(p.get("checks", [])) for _, p in policies if isinstance(p, dict))
    print(f"Checked {len(defs)} definition(s), {len(policies)} policy(ies) with {checks} check(s), {len(errors)} error(s)")
    return 1 if errors else 0


def check_policy_fixtures(policies):
    """tests/fixtures/policies/*.json: {"policy": key, "cases": [{"name", "items": [...], "expect": {check id: status}}]}.
    Every check of every policy needs a case where it does not pass (fail or warn) and one where it passes."""
    errors = []
    by_key = {p["key"]: p for _, p in policies if isinstance(p, dict) and "key" in p}
    seen = {key: {} for key in by_key}
    for f in sorted((ROOT / "tests" / "fixtures").rglob("*.json")):
        fx = json.loads(f.read_text())
        if "policy" not in fx:
            continue
        name = f.relative_to(ROOT).as_posix()
        p = by_key.get(fx["policy"])
        if p is None:
            errors.append(f"{name}: unknown policy {fx['policy']!r}")
            continue
        checks = {c["id"]: c for c in p["checks"] if isinstance(c, dict) and "id" in c}
        for i, case in enumerate(fx.get("cases", [])):
            label = f"{name}: case {i} ({case.get('name', '')})"
            for cid, expected in case.get("expect", {}).items():
                if cid not in checks:
                    errors.append(f"{label}: unknown check {cid}")
                    continue
                got = check_status(p, checks[cid], case.get("items", []))
                if got != expected:
                    errors.append(f"{label}: {cid} is {got}, expected {expected}")
                seen[fx["policy"]].setdefault(cid, set()).add(got)
    for key, p in by_key.items():
        for c in p.get("checks", []):
            got = seen[key].get(c.get("id"), set())
            if "pass" not in got or not got & {"fail", "warn"}:
                errors.append(f"{key}: {c.get('id')} needs a fixture case that passes and one that fails or warns")
    return errors


def matches_parser(p, record):
    if "when" in p and not test(p["when"], record):
        return False
    if "pattern" in p:
        text = get(record, p.get("field", "Message"))
        return text is not None and bool(rx(p["pattern"]).search(str(text)))
    return True


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "build":
        build()
    elif cmd == "check":
        sys.exit(check())
    else:
        sys.exit("usage: feed.py [check|build]")
