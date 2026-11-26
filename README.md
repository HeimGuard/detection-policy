# detection-policy

Security rule feed for [Laravel-MDM-Server](https://github.com/HeimGuard/Laravel-MDM-Server):
detection rules and log parsers (Windows, Debian / Ubuntu), versioned, reviewed and tested like software.
The server pulls this repository once a day and applies it on top of its built-in rules.

## Use it

On the server set:

```
MDM_SECURITY_FEED_URL=https://github.com/HeimGuard/detection-policy
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

Rule format: see [Security scanner](https://github.com/HeimGuard/Laravel-MDM-Server/blob/master/docs/security-scanner.md).
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

## Nightly update of the feed

`.github/workflows/update-feed.yml` runs the three generators below every night at midnight UTC (and on demand
from the **Actions** tab, with the number of days of the NVD and of months of the MSRC), each as a job of its own (`generate (cve)` and
`generate (msrc)` in parallel, then `distro`, which leaves out the CVEs the new NVD rules already judge). The last job, `pull-request`, applies what they made, bumps the manifest version,
runs `feed.py check` and opens one pull request (`automation/feed-update`) for review. A generator that fails does not stop the others;
the run ends red and says which one failed.

## Nightly CVE rules

`scripts/cve2feed.py` asks the NVD for the
CVEs changed in the last 4 days that have a product with a version range, asks the
[Ubuntu security tracker](https://ubuntu.com/security/cves) what it says about their packages, bumps the manifest
version of the CVEs it changed.

`data/cves.json` keeps what the NVD and Ubuntu said of every CVE; the rules (`rules/any/org.cve-*.json`) and their
fixtures are generated from it, so a CVE the NVD corrects is corrected in its rule, and CI fails when a generated file
differs from `python scripts/cve2feed.py --offline`. A rule of your own has another key (`org.<source>-<what>`).

- **One rule per product, version ranges and Ubuntu fixes**: 320 Chrome CVEs fixed in one release are one finding
  (`chrome has known vulnerabilities`), not 320; the finding names the CVEs that apply to the package.
- **Bounds the server can read**: numbers and dots, and what `feed.version_tuple` reads after them: letters (`1.1.1w`, `1.0.2zk`, `9.8p1`),
  `alpha` / `beta` / `rc` / ... (`2.0-rc1`); `7.1.2-31` is written `7.1.2.31`, as Debian numbers it. A bound that is none of these (`b7653`, `r81`,
  a date) leaves its range out. The order is the same as the server's `VersionService`; `tests/version-vectors.json` is the same file as
  `tests/fixtures/version-vectors.json` there (change both). A server from before this reads `1.1.1w` as `1.1.1`: it misses what the new bounds find,
  it does not report more. A product whose name says nothing (`tools`, `core`, `server`) is left out.
- **Aliases** (`data/aliases.json`): what a device calls a product when that is not its CPE name (`nodejs` is `node.js`, `apache2` is `http_server`,
  `docker-ce` is `docker`): regular expressions for any software item (`names`) and for dpkg packages (`dpkg`), and `examples` the rule of the product must find
  (a rule that does not is not shipped). A product without an entry is found by its CPE name. Whether a product is recognised at all depends on the feed having
  CVEs for it: see `data/watchlist.json` (`--watch N`) and `scripts/coverage.py` for what a real inventory lacks.
- **Distribution packages**: a dpkg package is only the product when its name is (`php8.5-cli`, not `php-enum`,
  `libaccounts-glib0` or the metapackage `php-cli`); the binary packages of a source package come from its name
  (`glib2.0` is `libglib2.0-0t64` and `gir1.2-glib-2.0`); agents 1.24.0+ also send the source package of a binary one
  (`SourcePackage`: `libssl3t64` is `openssl`), which the rules use as well, an older agent is judged by the name. Ubuntu fixes a vulnerability without changing the upstream
  version, so a package at or after the version the tracker names as the fix (`dpkg_gte`, server with the `dpkg_*`
  operators; an older server skips these rules) is not reported, nor is one of a source package the CVE does not
  touch. A release the tracker has no fix for is judged by the NVD range. A changelog that names the CVE (agents
  1.23.0+, `FixedCves`) hides it as well.

- **CVE by CVE (servers with `cves`)**: a rule still has one `when` (the newest fix, for a server that does not know the
  rest), and next to it `select` (which packages the rule is about, without versions) and `cves`: each CVE with its
  severity, its own `ranges` and what the Ubuntu tracker says per release. A server judges every CVE alone: **installed < fixed**
  (never equal; Debian versions as `dpkg --compare-versions`, the epoch and the revision taken off for a comparison with the
  project's version), a CVE the changelog names is fixed, and for an Ubuntu / Debian package the tracker decides (*fixed*,
  *update available*, *no fix yet*, *via Ubuntu Pro*). Only the CVEs that apply are in the finding, none left means no finding.
  The binary packages of one source package are one finding. The text "not all of them if it is newer than a fix" is gone.

- **Debian and Ubuntu trackers**: next to `ubuntu` every CVE carries `debian`, what the Debian Security Tracker says of its source
  packages per release (`bullseye`, `bookworm`, `trixie`, ...), in the words of the Ubuntu one. A server judges a package by the
  tracker of the device's distribution (Ubuntu, Debian); another one (Mint, ...) by the NVD ranges. The Debian data is downloaded
  whole every night (`--no-debian` skips it, `--import-debian FILE` takes a file); when it is not reachable the data stays as it was.
- **One entry per CVE**: the same CVE under two names of one product (or two rules about the same source package) is one entry,
  `feed.py check` fails when a CVE is in two rules about the same package.
- **Severity like a vulnerability scanner**: a CVE carries `severity`, its CVSS score `cvss` (the NVD, or the `cvss3` of the Ubuntu tracker) and `kev`
  when it is on the CISA list of the exploited ones. The severity of a CVE of a tracker is the more severe of the priority of the distribution and the
  band of its score (Debian says *medium* to CVEs the NVD scores 9.8: `distro2feed.enrich` takes what the NVD data says of the same CVE), and a
  CVE on the KEV list is at least *high*. The server shows the score and the exploited CVEs and never lowers a severity because there is no fix yet.
- **Watchlist** (`data/watchlist.json`): the nightly run sees only what the NVD changed in the last days, so software that is in no recent CVE (nginx, Apache
  httpd, OpenSSL, Redis) had no rule at all. `cve2feed.py --watch N` takes the whole history of up to N products of the list that were not taken yet
  (`state["watched"]`; one that failed is tried again the next night). The CPE is `vendor:product`.
- **Corrections of the NVD ranges** go to `data/overrides.json`, never into a generated file:
  `{"CVE-2025-54289": {"lxd": {"fixed_in": ["5.0.5"], "not_affected": [["4.0.0", "4.0.12"]]}}}`. The NVD gives one range for what a
  vendor fixed per release series; `fixed_in` lists the versions at which a series got its fix (what is at or after one, up to the next
  minor series, is not vulnerable), `not_affected` ranges (start, end excluding) are not vulnerable whatever the NVD says. A CVE
  that nothing is left of produces no rule.

`--cve CVE-2026-1 ...` takes named CVEs, `--days 120` goes further back (the NVD allows 120 days).

## Rules of the Ubuntu and Debian trackers

The CVE rules above start from the NVD, which has no product for a third of the new CVEs yet and none at all for the kernel.
`scripts/distro2feed.py` reads the
[Ubuntu CVE tracker](https://ubuntu.com/security/cves) (critical and high CVEs that `focal`, `jammy`, `noble`, `questing` or
`resolute` has not fixed, and the ones it fixed in the last year) and the [Debian Security Tracker](https://security-tracker.debian.org/tracker/data/json)
(open CVEs of urgency medium and up, and the fixes of this and last year), and writes `org.distro-ubuntu-NN` and `org.distro-debian-NN`
rules (`rules/linux`).

- **Same format**: `select` (the source packages of the rule, as dpkg packages) and `cves` (id, severity, no ranges, `ubuntu` or
  `debian`: per source package and release `[status, fixed version]`), no `when` (an older server skips the rule as invalid).
  The server judges every CVE alone: installed < fixed, the changelog of the package counts as a fix, `linux-signed*` is judged by
  the tracker of `linux*`.
- **One entry per CVE**: a CVE a rule of the NVD already judges for a source package (with the word of the tracker) is left out
  here; `feed.py check` fails when a CVE is in two rules about the same package.
- **Stable keys**: the source packages are spread over 32 rules by a hash of the name, so a rule keeps its key and its findings
  their acknowledgements when a package comes or goes. The rules fit 1.8 MB per distribution (the server takes 8 MB of the whole
  feed): open CVEs go first, the more severe, the newer.
- Fixtures say the release and the distribution (`"context": {"release": "noble", "os": "ubuntu"}`) and are checked by
  `scripts/cves.py`, the Python twin of the server's `SecurityCves`.

## Security updates of Microsoft

`scripts/msrc2feed.py` reads the latest monthly security updates of the MSRC (CVRF API, `api.msrc.microsoft.com`) and writes `org.msrc-*`
rules for what the inventory can tell.

**A rule is a missing update**: the CVEs a build fixes (`10.0.19045.7807`) are one rule and "older than that build" is its
condition, so a host sees exactly the updates it lacks and the CVEs each of them fixes (three cumulative updates behind: three
findings; the newest one installed: none). Its severity is that of what the update fixes. A CVE that two monthly updates list
counts once, for the newer one.

- **Windows 10 / 11 / Server 2016 and later** (the builds `10.0.x`), one family per build of the operating system: the rules
  are of the `os` source, agents 1.27.0+ list the operating system there (`Id` `windows`, its build with the revision as the
  `Version`, `10.0.19045.5555`); client and server with the same build share the fixes.
- **Microsoft Edge** (`Microsoft Edge` on Windows, `microsoft-edge-*` on Linux) and **Visual Studio Code**, software.
- Not here: Windows 7 to 8.1 and Server 2012 (security-only updates and monthly rollups have builds of their own, ESU), Hotpatch
  builds, .NET, Office, SQL Server and Exchange. The names and versions of the last ones in Programs and Features, and the bands
  of the .NET SDK (whose fixed builds are not comparable with the runtime's), were not checked on a device.

`data/msrc.json` keeps, per monthly update, the CVEs each family fixes by build (not the 30 MB documents); the rules are
generated from it (`python scripts/msrc2feed.py --offline`, CI checks that nothing changes). A rule of your own has another
key (`org.<source>-<what>`).

## Measuring the feed on a real inventory

`python scripts/coverage.py inventory.json [--os ubuntu --release noble]` takes the software items of one or more devices (a JSON list, or `{"software": [...]}`)
and says how many a software rule of the feed recognises, how many of those have a CVE that applies to their version (judged like the server,
`scripts/cves.py`), which names **no rule is about** (most common first: what to alias or to write a rule for) and which rules matched nothing.
It reads the feed only: the rules bundled in the server (7-Zip, WinRAR, PuTTY, ...) are not in it, so those names are listed as unmatched too.
`tests/coverage-sample.json` is a small inventory to try it on.

## Workflow

1. Add or change a rule / parser and a fixture in `tests/fixtures/`.
2. Bump `version` in `manifest.json` and run `python scripts/feed.py build`.
3. Run `python scripts/feed.py check` (CI does the same on every pull request).
4. Merge to `main`; servers pick it up within a day.

The server only reads Windows and Debian / Ubuntu agents and these sources: `software`, `processes`,
`listening`, `startup`, `admins`, `posture`, `events` (from parsers on `windows.security`,
`windows.system`, `windows.defender`, `linux.auth`). macOS, iOS and Android are not supported.
