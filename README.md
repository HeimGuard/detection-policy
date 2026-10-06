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
sigma/*.yml                  # optional Sigma sources, converted to rules/ by sigma2feed.py
manifest.json                # feed version and SHA-256 of every rule / parser file
scripts/feed.py              # validation and manifest generation
scripts/sigma2feed.py        # Sigma -> server rule converter
```

Rule format: see [Security scanner](https://github.com/PanoptiPulse/Laravel-MDM-Server/blob/main/docs/security-scanner.md).
Rules use a `key` prefixed `org.`; the same key as a bundled rule would replace it.

## Sigma rules

Put a Sigma rule in `sigma/` and convert it:

```
pip install pyyaml
python scripts/sigma2feed.py sigma/*.yml
```

Two kinds of rules convert:

- Windows / Linux `process_creation` -> a rule over the `processes` source (`Image` becomes `Path`, plus
  `CommandLine` and `User`).
- Windows `service: security | system | windefend` -> a **parser** (`parsers/windows/*-log.json`, `EventID` becomes
  `Id`, EventData fields become `Data.<Field>`) that makes an event, plus a **rule** over `events` that alerts on it.
  The server asks agents only for the event ids that parsers read, so the new id is collected after the next sync.
  Event ids that a bundled parser already handles (4625, 4720, 4732, 4740, 4698, 1102, 104, 7045, ...) may be
  claimed by that parser first.

Modifiers `contains`, `startswith`, `endswith`, `re`, `all`, wildcards and `and` / `or` / `not` / `1 of` /
`all of` conditions are supported. Other rules are skipped with the reason. Generated files in `rules/` and
`parsers/` are overwritten by the converter; CI fails when they differ from `sigma/`. Add a fixture for every
generated key, then build the manifest.

## Workflow

1. Add or change a rule / parser and a fixture in `tests/fixtures/`.
2. Bump `version` in `manifest.json` and run `python scripts/feed.py build`.
3. Run `python scripts/feed.py check` (CI does the same on every pull request).
4. Merge to `main`; servers pick it up within a day.

The server only reads Windows and Debian / Ubuntu agents and these sources: `software`, `processes`,
`listening`, `startup`, `admins`, `posture`, `events` (from parsers on `windows.security`,
`windows.system`, `windows.defender`, `linux.auth`). macOS, iOS and Android are not supported.
