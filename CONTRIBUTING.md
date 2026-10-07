# Contributing

- One rule or parser per file, named after its `key` (`org.<source>-<what>.json`) in `rules/<platform>/` or `parsers/<platform>/`.
- A rule needs: `key`, `name`, `severity`, `platform`, `source`, `when`, plus `description`, `message` and `remediation`.
- Every rule or parser needs a fixture in `tests/fixtures/` with at least one `positive` and one `negative` item.
- A compliance policy goes in `policies/<platform>/<key>.json` (one policy with its checks). Check ids name the area and what passes (`Sql.XpCmdshellDisabled`); give each a `reference` to the benchmark section, or `custom (...)` for checks of our own.
- Every policy needs `tests/fixtures/policies/<key>.json` with cases (`items` and the `expect`ed status per check id); every check needs a case where it passes and one where it fails or warns. Cover what the agent may not report (Manual) and when a check does not apply.
- Do not duplicate bundled rules of the server (`resources/security/rules.json`); a feed rule with the same key replaces the bundled one.
- After any change to `rules/`, `parsers/` or `policies/`: bump `version` in `manifest.json`, run `python scripts/feed.py build` and `python scripts/feed.py check`.
- Never commit secrets, credentials, or real customer/production data. Use sanitized samples.
- Changes go through pull requests; direct pushes to `main` should be avoided.
