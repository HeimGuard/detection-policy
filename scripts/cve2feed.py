#!/usr/bin/env python3
"""Turn newly published / changed CVEs from the NVD into `software` rules of the feed.

  python scripts/cve2feed.py [--days 2] [--limit 50]

Only CVEs on the CISA Known Exploited Vulnerabilities list (NVD `hasKev`) are taken, and only those with
a product and a version range in their CPE configuration (versionEndExcluding / versionEndIncluding).
Each CVE + product becomes rules/any/org.cve-<year>-<id>-<product>.json with a fixture; an existing
key is never overwritten, so a rule edited by hand stays. Set NVD_API_KEY for a higher rate limit.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGET_SW = {"*", "-", "windows", "linux", "debian", "ubuntu"}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def fetch(days):
    since = datetime.now(timezone.utc) - timedelta(days=days)
    params = {
        "hasKev": "",
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"User-Agent": "detection-policy-cve2feed"}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    out, start = [], 0
    while True:
        query = urllib.parse.urlencode({**params, "startIndex": start}).replace("hasKev=&", "hasKev&")
        for attempt in range(5):
            try:
                with urllib.request.urlopen(urllib.request.Request(f"{API}?{query}", headers=headers), timeout=60) as r:
                    page = json.load(r)
                break
            except Exception as e:  # rate limit (403 / 429) or a hiccup: wait and retry
                if attempt == 4:
                    raise
                print(f"NVD: {e}; retrying", file=sys.stderr)
                time.sleep(10 * (attempt + 1))
        out += page.get("vulnerabilities", [])
        start += page.get("resultsPerPage", 0)
        if not page.get("resultsPerPage") or start >= page.get("totalResults", 0):
            return out
        time.sleep(1 if headers.get("apiKey") else 7)


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


def bump(version):
    now = datetime.now(timezone.utc)
    prefix = f"{now.year}.{now.month}."
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version)
    if m and f"{m[1]}.{m[2]}." == prefix:
        return prefix + str(int(m[3]) + 1)
    return prefix + "1"


def before(version):
    """A version just under `version` (for the fixture)."""
    nums = [int(x) for x in re.findall(r"\d+", version)] or [1]
    for i in range(len(nums) - 1, -1, -1):
        if nums[i] > 0:
            nums[i] -= 1
            return ".".join(map(str, nums))
    return "0"


def range_cond(rng):
    start, end_excl, end_incl = rng
    conds = []
    if start:
        conds.append({"field": "Version", "op": "version_gte", "value": start})
    conds.append({"field": "Version", "op": "version_lt" if end_excl else "version_lte", "value": end_excl or end_incl})
    return conds, start, end_excl, end_incl


def build_rule(cve, vendor, product, ranges):
    cid = cve["id"]
    name = re.sub(r"[_\s]+", " ", product).strip()
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), cid)
    items = [range_cond(r) for r in sorted(set(ranges), key=lambda r: tuple(x or "" for x in r))[:8]]
    ranged = [{"all": c} if len(c) > 1 else c[0] for c, *_ in items]
    when = {"all": [
        {"field": "Name", "op": "contains", "value": name},
        ranged[0] if len(ranged) == 1 else {"any": ranged},
    ]}
    key = re.sub(r"[^a-z0-9.-]+", "-", f"org.cve-{cid[4:]}-{product}".lower()).strip("-")[:64].rstrip("-.")
    rule = {
        "key": key,
        "name": f"{name} affected by {cid}",
        "description": f"{cid} (CISA Known Exploited Vulnerabilities): {desc}"[:1000],
        "severity": severity(cve),
        "platform": "any",
        "source": "software",
        "when": when,
        "message": f"{{Name}} {{Version}} is affected by {cid}",
        "remediation": "Update the software to a fixed version, see the vendor advisory."[:1000],
        "urls": [f"https://nvd.nist.gov/vuln/detail/{cid}"] + [
            r["url"] for r in cve.get("references", [])
            if re.match(r"^https?://[^/\s]+\S*$", r.get("url", "")) and len(r["url"]) <= 500][:4],
    }
    _, start, end_excl, end_incl = items[0]
    inside = before(end_excl) if end_excl else end_incl
    if start and tuple(map(int, re.findall(r"\d+", inside) or [0])) < tuple(map(int, re.findall(r"\d+", start) or [0])):
        inside = start
    outside = end_excl or f"{end_incl}.1"
    fixture = {
        "key": key,
        "positive": [{"Name": name, "Version": inside, "Source": "x"}],
        "negative": [
            {"Name": name, "Version": outside, "Source": "x"},
            {"Name": "Unrelated tool", "Version": inside, "Source": "x"},
        ],
    }
    return rule, fixture


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=2)
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    existing = {p.name for p in (ROOT / "rules").rglob("*.json")}
    added = 0
    for v in fetch(args.days):
        cve = v["cve"]
        for (vendor, product), ranges in sorted(products(cve).items()):
            rule, fixture = build_rule(cve, vendor, product, ranges)
            if f"{rule['key']}.json" in existing:
                continue
            if added >= args.limit:
                print(f"limit of {args.limit} reached")
                break
            (ROOT / "rules" / "any" / f"{rule['key']}.json").write_text(json.dumps(rule, indent=2) + "\n")
            (ROOT / "tests" / "fixtures" / f"{rule['key'].removeprefix('org.')}.json").write_text(
                json.dumps(fixture, indent=2) + "\n")
            print("added", rule["key"])
            added += 1
    if added:
        mf = ROOT / "manifest.json"
        m = json.loads(mf.read_text())
        mf.write_text(json.dumps({"version": bump(m["version"]), "files": m["files"]}, indent=2) + "\n")
    print(f"{added} new rule(s)")


if __name__ == "__main__":
    main()
