# detection-policy

Detection-as-code repository for the MDM project: detection rules and security policies for managed devices (macOS, Windows, iOS, Android), versioned, reviewed and tested like software.

## Structure

```
detections/sigma/<platform>/   # Sigma rules per platform (macos, windows, ...)
policies/mdm/                  # MDM policies (compliance baselines, ...)
tests/fixtures/<platform>/     # positive/negative event samples per rule
scripts/validate.py            # rule validation (run locally and in CI)
docs/                          # conventions and rule template
```

## Workflow

1. Create a branch and add or change a rule or policy.
2. Add or update tests in `tests/`.
3. Open a pull request; CI validates the content.
4. Merge to `main` after review.

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions.

## Local validation

```
pip install pyyaml
python scripts/validate.py
```
