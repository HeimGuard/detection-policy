#!/usr/bin/env python3
"""Convert Sigma rules (YAML) to rules and parsers of Laravel-MDM-Server.

  python scripts/sigma2feed.py sigma/*.yml            # writes rules/ and parsers/ files
  python scripts/sigma2feed.py --stdout rule.yml      # print instead of writing

Supported logsources:
  * windows|linux + category process_creation -> a rule over the "processes" source
    (rules/<platform>/org.sigma-<slug>.json)
  * windows + service security|system|windefend (EventID, EventData fields, Provider_Name) -> a parser
    (parsers/windows/org.sigma-<slug>-log.json) that makes an event plus a rule over "events"
    (rules/windows/org.sigma-<slug>.json). EventData fields become Data.<Field>.
Selections:
selections as maps / lists of maps; modifiers contains, startswith, endswith, re, all; wildcards
(* and ?); conditions with and / or / not, parentheses, "1 of x*", "all of x*", "1 of them".
Anything else (other log sources, fieldrefs, base64, ...) is reported and the rule is skipped.
After converting: add a fixture in tests/fixtures/, run `feed.py build` and `feed.py check`.
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LEVELS = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
# Sigma field -> field of the server's `processes` source
PROCESS_FIELDS = {"Image": "Path", "CommandLine": "CommandLine", "User": "User"}
# Sigma windows service -> log source of the server
LOG_SOURCES = {"security": "windows.security", "system": "windows.system", "windefend": "windows.defender"}


def process_field(name):
    if name not in PROCESS_FIELDS:
        raise Unsupported(f"field {name!r} has no counterpart in the server's processes source")
    return PROCESS_FIELDS[name]


def log_field(name):
    if name == "EventID":
        return "Id"
    if name == "Provider_Name":
        return "Provider"
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise Unsupported(f"field {name!r} is not an EventData field name")
    if name in ("Channel", "Computer", "Level", "Keywords", "Task", "Opcode"):
        raise Unsupported(f"field {name!r} is not collected by the agent")
    return f"Data.{name}"


class Unsupported(Exception):
    pass


def value_cond(field, mods, value):
    """One field/value pair -> server condition."""
    if "re" in mods:
        return {"field": field, "op": "matches", "value": str(value)}
    v = str(value)
    if "contains" in mods:
        v = f"*{v}*"
    elif "startswith" in mods:
        v = f"{v}*"
    elif "endswith" in mods:
        v = f"*{v}"
    if "*" not in v and "?" not in v:
        return {"field": field, "op": "eq", "value": int(v) if field == "Id" and v.isdigit() else v}
    core = v.strip("*")
    if "*" not in core and "?" not in core:
        start, end = v.startswith("*"), v.endswith("*")
        op = "contains" if start and end else "ends_with" if start else "starts_with"
        return {"field": field, "op": op, "value": core}
    regex = "".join(".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in v)
    return {"field": field, "op": "matches", "value": f"^{regex}$"}


def group(op, items):
    flat = []
    for i in items:
        flat.extend(i[op] if set(i) == {op} else [i])
    items = flat
    return items[0] if len(items) == 1 else {op: items}


def selection_cond(sel, fmap):
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):
            return group("any", [selection_cond(s, fmap) for s in sel])
        raise Unsupported("keyword selections are not supported")
    if not isinstance(sel, dict):
        raise Unsupported("unsupported selection")
    parts = []
    for key, val in sel.items():
        name, *mods = key.split("|")
        field = fmap(name)
        unknown = set(mods) - {"contains", "startswith", "endswith", "re", "all"}
        if unknown:
            raise Unsupported(f"modifier {sorted(unknown)[0]!r} is not supported")
        vals = val if isinstance(val, list) else [val]
        if any(v is None or isinstance(v, (dict, list)) for v in vals):
            raise Unsupported(f"unsupported value for {key}")
        conds = [value_cond(field, mods, v) for v in vals]
        parts.append(group("all" if "all" in mods else "any", conds))
    return group("all", parts)


def tokenize(text):
    return re.findall(r"\(|\)|[^\s()]+", text)


def parse_condition(text, selections):
    toks, pos = tokenize(text), [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def expr():
        left = term()
        while peek() and peek().lower() == "or":
            take()
            left = group("any", [left, term()])
        return left

    def term():
        left = factor()
        while peek() and peek().lower() == "and":
            take()
            left = group("all", [left, factor()])
        return left

    def factor():
        t = peek()
        if t is None:
            raise Unsupported("incomplete condition")
        if t.lower() == "not":
            take()
            return {"not": factor()}
        if t == "(":
            take()
            e = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return e
        if t.lower() in ("1", "all") and pos[0] + 1 < len(toks) and toks[pos[0] + 1].lower() == "of":
            quant = take().lower()
            take()
            pattern = take()
            names = list(selections) if pattern == "them" else [n for n in selections if re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), n)]
            if not names:
                raise Unsupported(f"no selection matches {pattern!r}")
            return group("all" if quant == "all" else "any", [selections[n] for n in names])
        take()
        if t not in selections:
            raise Unsupported(f"unknown selection {t!r}")
        return selections[t]

    result = expr()
    if peek() is not None:
        raise Unsupported(f"unexpected {peek()!r} in condition")
    return result


def slugify(title):
    return re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40].strip("-")


def convert(doc):
    """-> list of (kind, platform, definition); kind is "rules" or "parsers"."""
    ls = doc.get("logsource") or {}
    product, category, service = ls.get("product"), ls.get("category"), ls.get("service")
    det = doc.get("detection") or {}
    if isinstance(det.get("condition"), list):
        raise Unsupported("multiple conditions are not supported")
    slug = slugify(doc["title"])
    key = f"org.sigma-{slug}"
    severity = LEVELS.get(doc.get("level", "medium"), "medium")
    refs = "; ".join(doc.get("references") or [])
    remediation = ("False positives: " + "; ".join(doc["falsepositives"]))[:1000] if doc.get("falsepositives") else refs[:1000]
    note = f" Converted from Sigma rule {doc['id']}." if doc.get("id") else ""
    description = (doc.get("description", "") + note)[:1000]

    def build_when(fmap):
        selections = {k: selection_cond(v, fmap) for k, v in det.items() if k != "condition"}
        return parse_condition(det["condition"], selections)

    if product in ("windows", "linux") and category == "process_creation" and not service:
        return [("rules", product, {
            "key": key, "name": doc["title"][:120], "description": description, "severity": severity,
            "platform": product, "source": "processes", "when": build_when(process_field),
            "message": "{Name} {CommandLine}", "remediation": remediation,
        })]
    if product == "windows" and service in LOG_SOURCES and not category:
        event = "sg_" + slug.replace("-", "_")[:28].strip("_")
        parser = {
            "key": f"{key}-log", "name": doc["title"][:120], "description": description,
            "source": LOG_SOURCES[service], "when": build_when(log_field),
            "event": {"type": event, "user": "{Data.TargetUserName|Data.SubjectUserName}",
                      "source": "{Data.IpAddress|Data.WorkstationName}", "message": doc["title"][:480]},
        }
        rule = {
            "key": key, "name": doc["title"][:120], "description": description, "severity": severity,
            "platform": "windows", "source": "events",
            "when": {"field": "Type", "op": "eq", "value": event},
            "message": "{Message} ({Count}x)", "remediation": remediation,
        }
        return [("parsers", "windows", parser), ("rules", "windows", rule)]
    raise Unsupported(f"logsource {ls} is not supported (windows/linux process_creation, windows security/system/windefend)")


def main(argv):
    to_stdout = "--stdout" in argv
    files = [a for a in argv if a != "--stdout"]
    if not files:
        sys.exit(__doc__)
    failed = 0
    for f in files:
        try:
            outputs = convert(yaml.safe_load(Path(f).read_text()))
        except (Unsupported, KeyError) as e:
            print(f"SKIP {f}: {e}")
            failed += 1
            continue
        for kind, product, definition in outputs:
            out = json.dumps(definition, indent=2, ensure_ascii=False) + "\n"
            if to_stdout:
                print(out)
            else:
                path = ROOT / kind / product / f"{definition['key']}.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(out)
                print(f"OK   {f} -> {path.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
