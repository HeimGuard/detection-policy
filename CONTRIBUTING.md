# Contributing

- One rule or policy per file, named in `kebab-case`.
- Every detection needs: title, description, severity, data source, false positives, references.
- Every rule or policy change needs a matching test in `tests/`.
- Never commit secrets, credentials, or real customer/production data. Use sanitized samples.
- Changes go through pull requests; direct pushes to `main` should be avoided.
