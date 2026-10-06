# detection-policy

Security rule feed for [Laravel-MDM-Server](https://github.com/PanoptiPulse/Laravel-MDM-Server):
detection rules and log parsers (Windows, Debian / Ubuntu), versioned, reviewed and tested like software.
The server pulls this repository once a day and applies it on top of its built-in rules.

## Use it

On the server set:

```
MDM_SECURITY_FEED_URL=https://github.com/PanoptiPulse/detection-policy
MDM_SECURITY_FEED_REF=main        # optional: branch or tag
```

Or press **Update now** on the **Rules** tab of **Security**. Everything is verified against
`manifest.json` first and applied in one go; a bad file changes nothing.

## Structure

```
rules/<platform>/*.json      # detection rules (windows, linux), one rule or a list per file
parsers/<platform>/*.json    # log parsers that turn raw log records into events
tests/fixtures/*.json        # positive / negative items for every rule and parser
manifest.json                # feed version and SHA-256 of every rule / parser file
scripts/feed.py              # validation and manifest generation
```

Rule format: see [Security scanner](https://github.com/PanoptiPulse/Laravel-MDM-Server/blob/main/docs/security-scanner.md).
Rules use a `key` prefixed `org.`; the same key as a bundled rule would replace it.

## Workflow

1. Add or change a rule / parser and a fixture in `tests/fixtures/`.
2. Bump `version` in `manifest.json` and run `python scripts/feed.py build`.
3. Run `python scripts/feed.py check` (CI does the same on every pull request).
4. Merge to `main`; servers pick it up within a day.

The server only reads Windows and Debian / Ubuntu agents and these sources: `software`, `processes`,
`listening`, `startup`, `admins`, `posture`, `events` (from parsers on `windows.security`,
`windows.system`, `windows.defender`, `linux.auth`). macOS, iOS and Android are not supported.
