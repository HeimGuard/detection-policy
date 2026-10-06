#!/usr/bin/env python3
"""Validate detection rules: required fields, valid values, and a matching test fixture."""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["title", "id", "status", "description", "author", "date",
            "logsource", "detection", "falsepositives", "level", "references"]
STATUS = {"experimental", "test", "stable"}
LEVEL = {"low", "medium", "high", "critical"}


def main() -> int:
    errors = []
    fixtures = {}
    for f in (ROOT / "tests" / "fixtures").rglob("*.json"):
        fixtures[json.loads(f.read_text())["rule"]] = f

    ids = set()
    rules = sorted((ROOT / "detections").rglob("*.yml"))
    for rule in rules:
        rel = rule.relative_to(ROOT).as_posix()
        doc = yaml.safe_load(rule.read_text())
        for key in REQUIRED:
            if key not in doc:
                errors.append(f"{rel}: missing '{key}'")
        if doc.get("status") not in STATUS:
            errors.append(f"{rel}: invalid status")
        if doc.get("level") not in LEVEL:
            errors.append(f"{rel}: invalid level")
        if doc.get("id") in ids:
            errors.append(f"{rel}: duplicate id")
        ids.add(doc.get("id"))
        if rel not in fixtures:
            errors.append(f"{rel}: no test fixture in tests/fixtures")

    for err in errors:
        print(f"ERROR {err}")
    print(f"Checked {len(rules)} rule(s), {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
