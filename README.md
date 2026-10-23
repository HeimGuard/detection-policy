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

## Sign-ins

`org.linux-sshd-accepted` (sshd `Accepted ...`) and `org.windows-4624-logon` (4624 of people: logon
types 2, 3, 7, 10, 11, without services, SYSTEM and computer accounts) turn successful sign-ins into
one event type, `logon` (user, and the address or workstation it came from). Rules over it with
`"unseen_days": 10` alert only on a user / address combination no device had in the last 10 days
(`org.events-ssh-publickey-new-source`, `org.events-logon-new-source`); `unseen_days` needs a server
with that option, an older one ignores it and alerts on every sign-in. Windows agents collect every
4624 once this parser is in the feed (a busy log; agents send it in parts).

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

## Nightly CVE rules

`.github/workflows/cve-rules.yml` runs every night (and on demand) `scripts/cve2feed.py`: it asks the NVD for the
CVEs changed in the last 4 days that have a product with a version range, asks the
[Ubuntu security tracker](https://ubuntu.com/security/cves) what it says about their packages, bumps the manifest
version, runs `feed.py check` and opens a pull request (`automation/cve-rules`) for review.

`data/cves.json` keeps what the NVD and Ubuntu said of every CVE; the rules (`rules/any/org.cve-*.json`) and their
fixtures are generated from it, so a CVE the NVD corrects is corrected in its rule, and CI fails when a generated file
differs from `python scripts/cve2feed.py --offline`. A rule of your own has another key (`org.<source>-<what>`).

- **One rule per product, version ranges and Ubuntu fixes**: 320 Chrome CVEs fixed in one release are one finding
  (`chrome affected by 320 CVEs`), not 320.
- **Bounds the server can read**: only numbers and dots (`7.1.2-31` is written `7.1.2.31`, as Debian numbers it);
  a bound that cannot be written that way (`b7653`, `2.0-rc1`) leaves its range out. A product whose name says nothing
  (`tools`, `core`, `server`) is left out.
- **Distribution packages**: a dpkg package is only the product when its name is (`php8.5-cli`, not `php-enum`,
  `libaccounts-glib0` or the metapackage `php-cli`); the binary packages of a source package come from its name
  (`glib2.0` is `libglib2.0-0t64` and `gir1.2-glib-2.0`). Ubuntu fixes a vulnerability without changing the upstream
  version, so a package at or after the version the tracker names as the fix (`dpkg_gte`, server with the `dpkg_*`
  operators; an older server skips these rules) is not reported, nor is one of a source package the CVE does not
  touch. A release the tracker has no fix for is judged by the NVD range. A changelog that names the CVE (agents
  1.23.0+, `FixedCves`) hides it as well.

`--cve CVE-2026-1 ...` takes named CVEs, `--days 120` goes further back (the NVD allows 120 days).

## Security updates of Microsoft

`.github/workflows/msrc-rules.yml` runs every night (and on demand) `scripts/msrc2feed.py`, apart from the NVD rules:
it reads the latest monthly security updates of the MSRC (CVRF API, `api.msrc.microsoft.com`) and writes
`org.msrc-*` rules for what the inventory can tell, opening a pull request (`automation/msrc-rules`) for review.
Per family the CVEs are one rule over the build that fixes the newest of them, the message tells the build that fixed
each CVE (a package between two fixes sees what applies):

- **Windows**, one rule per build of the operating system (`10.0.19045`, `10.0.22631`, ...): agents 1.27.0+ list the
  operating system as software (`Source` `windows`, its build with the revision as the version, `10.0.19045.5555`); client
  and server with the same build share the fixes. A build older than the newest fix is a finding.
- **Microsoft Edge** (`Microsoft Edge` on Windows, `microsoft-edge-*` on Linux) and **Visual Studio Code**.
- Not here: .NET, Office, SQL Server, Exchange. Their names and versions in Programs and Features, and the bands of the
  .NET SDK (whose fixed builds are not comparable with the runtime's), were not checked on a device.

`data/msrc.json` keeps what the rules need of each monthly update (the newest fixed build, the number of CVEs and the most
severe ones per family), not the 30 MB documents; the rules are generated from it (`python scripts/msrc2feed.py --offline`, CI
checks that nothing changes). A rule of your own has another key (`org.<source>-<what>`).

## Workflow

1. Add or change a rule / parser and a fixture in `tests/fixtures/`.
2. Bump `version` in `manifest.json` and run `python scripts/feed.py build`.
3. Run `python scripts/feed.py check` (CI does the same on every pull request).
4. Merge to `main`; servers pick it up within a day.

The server only reads Windows and Debian / Ubuntu agents and these sources: `software`, `processes`,
`listening`, `startup`, `admins`, `posture`, `events` (from parsers on `windows.security`,
`windows.system`, `windows.defender`, `linux.auth`). macOS, iOS and Android are not supported.
