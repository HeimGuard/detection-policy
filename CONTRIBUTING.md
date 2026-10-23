# Contributing

- One rule or parser per file, named after its `key` (`org.<source>-<what>.json`) in `rules/<platform>/` or `parsers/<platform>/`.
- A rule needs: `key`, `name`, `severity`, `platform`, `source`, `when`, plus `description`, `message` and `remediation`.
- Optional `urls`: up to 10 `http(s)` links (MITRE ATT&CK, vendor docs, write-ups), shown with the rule and its findings.
- Every rule or parser needs a fixture in `tests/fixtures/` with at least one `positive` and one `negative` item.
- Do not duplicate bundled rules of the server (`resources/security/rules.json`); a feed rule with the same key replaces the bundled one.
- After any change to `rules/` or `parsers/`: bump `version` in `manifest.json`, run `python scripts/feed.py build` and `python scripts/feed.py check`.
- Never commit secrets, credentials, or real customer/production data. Use sanitized samples.
- Changes go through pull requests; direct pushes to `main` should be avoided.
- Rules `org.cve-*` (and their fixtures) are generated from `data/cves.json` by `scripts/cve2feed.py`, do not edit them: change the generator
  or the data and run `python scripts/cve2feed.py --offline`. `python -m unittest discover -s tests -p 'test_*.py'` tests the generator.
- Rules `org.msrc-*` are generated from `data/msrc.json` by `scripts/msrc2feed.py` (`--offline`), do not edit them either.
