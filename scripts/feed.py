#!/usr/bin/env python3
"""Validate the rule feed for Laravel-MDM-Server and (re)generate manifest.json.

  python scripts/feed.py check    # validate rules, parsers, fixtures and manifest
  python scripts/feed.py build    # regenerate manifest.json (SHA-256 of every file)

Mirrors the server's checks (app/Support/SecurityRules.php, SecurityParsers.php, SecurityFeed.php).
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
FIELD = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$")
PATH = re.compile(r"^(rules|parsers)/[\w.-]+(/[\w.-]+)*\.json$")
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
    "events": ["Type", "Count", "User", "Source", "Message", "Last"],
}
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
        return got is not None
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
    for f in sorted(list((ROOT / "rules").rglob("*.json")) + list((ROOT / "parsers").rglob("*.json"))):
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
    for f in sorted((ROOT / "tests" / "fixtures").rglob("*.json")):
        fx = json.loads(f.read_text())
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
    print(f"Checked {len(defs)} definition(s), {len(errors)} error(s)")
    return 1 if errors else 0


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
