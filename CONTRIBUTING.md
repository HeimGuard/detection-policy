# Contributing

- One rule or parser per file, named after its `key` (`org.<source>-<what>.json`) in `rules/<platform>/` or `parsers/<platform>/`.
- A rule needs: `key`, `name`, `severity`, `platform`, `source`, `when`, plus `description`, `message` and `remediation`.
- Every rule or parser needs a fixture in `tests/fixtures/` with at least one `positive` and one `negative` item.
- Do not duplicate bundled rules of the server (`resources/security/rules.json`); a feed rule with the same key replaces the bundled one.
- After any change to `rules/` or `parsers/`: bump `version` in `manifest.json`, run `python scripts/feed.py build` and `python scripts/feed.py check`.
- Never commit secrets, credentials, or real customer/production data. Use sanitized samples.
- Changes go through pull requests; direct pushes to `main` should be avoided.
