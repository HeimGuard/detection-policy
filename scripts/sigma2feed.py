#!/usr/bin/env python3
"""Convert Sigma rules (YAML) to rules of Laravel-MDM-Server.

  python scripts/sigma2feed.py sigma/*.yml            # writes rules/<platform>/org.sigma-<slug>.json
  python scripts/sigma2feed.py --stdout rule.yml      # print instead of writing

Supported: logsource product windows|linux with category process_creation (-> source "processes");
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
        return {"field": field, "op": "eq", "value": v}
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


def selection_cond(sel):
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):
            return group("any", [selection_cond(s) for s in sel])
        raise Unsupported("keyword selections are not supported")
    if not isinstance(sel, dict):
        raise Unsupported("unsupported selection")
    parts = []
    for key, val in sel.items():
        name, *mods = key.split("|")
        if name not in PROCESS_FIELDS:
            raise Unsupported(f"field {name!r} has no counterpart in the server's processes source")
        unknown = set(mods) - {"contains", "startswith", "endswith", "re", "all"}
        if unknown:
            raise Unsupported(f"modifier {sorted(unknown)[0]!r} is not supported")
        field = PROCESS_FIELDS[name]
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


def convert(doc):
    ls = doc.get("logsource") or {}
    product, category = ls.get("product"), ls.get("category")
    if product not in ("windows", "linux") or category != "process_creation" or ls.get("service"):
        raise Unsupported(f"logsource {ls} is not supported (only windows/linux process_creation)")
    det = doc.get("detection") or {}
    if isinstance(det.get("condition"), list):
        raise Unsupported("multiple conditions are not supported")
    selections = {k: selection_cond(v) for k, v in det.items() if k != "condition"}
    when = parse_condition(det["condition"], selections)
    slug = re.sub(r"[^a-z0-9]+", "-", doc["title"].lower()).strip("-")[:48].strip("-")
    key = f"org.sigma-{slug}"
    refs = "; ".join(doc.get("references") or [])
    return product, {
        "key": key,
        "name": doc["title"][:120],
        "description": (doc.get("description", "") + (f" Converted from Sigma rule {doc['id']}." if doc.get("id") else ""))[:1000],
        "severity": LEVELS.get(doc.get("level", "medium"), "medium"),
        "platform": product,
        "source": "processes",
        "when": when,
        "message": "{Name} {CommandLine}",
        "remediation": ("False positives: " + "; ".join(doc["falsepositives"]))[:1000] if doc.get("falsepositives") else refs[:1000],
    }


def main(argv):
    to_stdout = "--stdout" in argv
    files = [a for a in argv if a != "--stdout"]
    if not files:
        sys.exit(__doc__)
    failed = 0
    for f in files:
        try:
            product, rule = convert(yaml.safe_load(Path(f).read_text()))
        except (Unsupported, KeyError) as e:
            print(f"SKIP {f}: {e}")
            failed += 1
            continue
        out = json.dumps(rule, indent=2, ensure_ascii=False) + "\n"
        if to_stdout:
            print(out)
        else:
            path = ROOT / "rules" / product / f"{rule['key']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(out)
            print(f"OK   {f} -> {path.relative_to(ROOT)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
