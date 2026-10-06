# detection-policy

Detection-as-code repository: detection rules and security policies, versioned, reviewed and tested like software.

## Structure

```
detections/   # detection rules (Sigma, YARA, KQL, ...)
policies/     # policies (OPA/Rego, YAML, ...)
tests/        # test logs, fixtures and validation
docs/         # conventions and documentation
```

## Workflow

1. Create a branch and add or change a rule or policy.
2. Add or update tests in `tests/`.
3. Open a pull request; CI validates the content.
4. Merge to `main` after review.

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions.
