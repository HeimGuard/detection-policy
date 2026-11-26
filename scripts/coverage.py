#!/usr/bin/env python3
"""How well the software rules of the feed fit a real inventory: what no rule recognises and which rules never match.

  python scripts/coverage.py inventory.json [more.json ...]   (an export of the Security tab of a device, or a list of items) [--os ubuntu --release noble] [--top 40] [--json]

An inventory is a JSON list of software items ({"Name", "Version", "Source", "SourcePackage", ...} as the agent sends them) or an object
with such a list under "software" (what an export of the Security tab has); several files are one fleet. Nothing is sent anywhere.

  recognised   an item some rule is about (its `select`, or its `when` for a rule without CVEs), whatever its version
  vulnerable   a recognised item with at least one CVE that applies to its version (the same judgement as the server: scripts/cves.py)
  unmatched    the names no rule is about, most common first: the aliases to add (data/aliases.json) or products the feed has no CVE for
  silent rules the rules that matched no item of the inventory (of a feed that is the right size for the fleet most are silent: it is the
               ones that match a name only by accident, or never, that are worth looking at)
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cves as cve_judge  # noqa: E402
import feed  # noqa: E402


def load_inventory(path):
    """(software items, os item or None) of one file: an export of the Security tab ({"inventory": {"software": [...], "os": [...]}}),
    {"software": [...]} or a plain list of items."""
    data = json.loads(Path(path).read_text())
    inventory = data.get("inventory", data) if isinstance(data, dict) else {"software": data}
    items = [i for i in inventory.get("software", []) if isinstance(i, dict) and i.get("Name")]
    os_items = inventory.get("os") or []
    return items, (os_items[0] if os_items else None)


def load_items(paths):
    return [item for path in paths for item in load_inventory(path)[0]]


def software_rules():
    return [d for _, is_parser, d in feed.load_definitions() if not is_parser and isinstance(d, dict) and d.get("source") == "software"]


def recognises(rule, item):
    return feed.test(rule["select"] if "select" in rule else rule["when"], item) if ("select" in rule or "when" in rule) else False


def measure(items, rules, release=None, os_id=None):
    recognised, vulnerable, unmatched = set(), set(), Counter()
    hits = Counter()
    for index, item in enumerate(items):
        matched = [r for r in rules if recognises(r, item)]
        for rule in matched:
            hits[rule["key"]] += 1
        if matched:
            recognised.add(index)
            if any(cve_judge.affecting(r["cves"], item, release, os_id) for r in matched if r.get("cves")) or \
                    any(feed.test(r["when"], item) for r in matched if "when" in r and not r.get("cves")):
                vulnerable.add(index)
        else:
            unmatched[str(item["Name"]).strip().lower()] += 1
    silent = sorted(r["key"] for r in rules if hits[r["key"]] == 0)
    return {"items": len(items), "recognised": len(recognised), "vulnerable": len(vulnerable), "rules": len(rules),
            "silent_rules": silent, "unmatched": unmatched}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inventory", nargs="+")
    ap.add_argument("--os", dest="os_id", default=None, help="the distribution of the devices (ubuntu, debian) for the tracker's word")
    ap.add_argument("--release", default=None, help="the release codename (noble, bookworm)")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    rules = software_rules()
    # Every file is one device: its own distribution and release (an export says them), the options are for the files that do not.
    results = []
    for path in args.inventory:
        items, os_item = load_inventory(path)
        os_id = args.os_id or (os_item or {}).get("Id")
        release = args.release or cve_judge.release(os_item)
        result = measure(items, rules, release, os_id)
        result["file"] = Path(path).name
        results.append(result)
    result = results[0]
    if len(results) > 1:
        merged = Counter()
        for r in results:
            merged.update(r["unmatched"])
        result = {"items": sum(r["items"] for r in results), "recognised": sum(r["recognised"] for r in results),
                  "vulnerable": sum(r["vulnerable"] for r in results), "rules": results[0]["rules"],
                  "silent_rules": sorted(set.intersection(*[set(r["silent_rules"]) for r in results])), "unmatched": merged}
        for r in results:
            print(f"{r['file']}: {r['items']} items, recognised {r['recognised']}, vulnerable {r['vulnerable']}")
        print()
    if args.json:
        result["unmatched"] = dict(result["unmatched"].most_common(args.top))
        print(json.dumps(result, indent=1))
        return
    n = result["items"] or 1
    print(f"{result['items']} items, {result['rules']} software rules")
    print(f"recognised by a rule: {result['recognised']} ({100 * result['recognised'] / n:.1f} %), vulnerable: {result['vulnerable']} ({100 * result['vulnerable'] / n:.1f} %)")
    print(f"rules that matched nothing: {len(result['silent_rules'])} of {result['rules']}")
    print(f"\nnames no rule is about ({len(result['unmatched'])}), most common first:")
    for name, count in result["unmatched"].most_common(args.top):
        print(f"  {count:5d}  {name}")


if __name__ == "__main__":
    main()
