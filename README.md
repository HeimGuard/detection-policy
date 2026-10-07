# detection-policy

Security rule feed for [Laravel-MDM-Server](https://github.com/PanoptiPulse/Laravel-MDM-Server):
detection rules, log parsers and compliance policies (Windows, Debian / Ubuntu), versioned, reviewed and
tested like software.
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
policies/<platform>/*.json   # compliance policies (benchmarks, baselines), one policy with its checks per file
tests/fixtures/*.json        # positive / negative items for every rule and parser
tests/fixtures/policies/     # cases with the expected status of every check of every policy
sigma/*.yml                  # optional Sigma sources, converted to rules/ by sigma2feed.py
manifest.json                # feed version and SHA-256 of every rule / parser / policy file
scripts/feed.py              # validation and manifest generation
scripts/sigma2feed.py        # Sigma -> server rule converter
```

Rule format: see [Security scanner](https://github.com/PanoptiPulse/Laravel-MDM-Server/blob/main/docs/security-scanner.md).
Rules use a `key` prefixed `org.`; the same key as a bundled rule would replace it.

## Compliance policies

A policy is a list of checks over a source of the inventory; every check gives each device **Pass**,
**Fail**, **Warn**, **Manual** (the agent did not report what it needs) or **Not applicable**. The
server shows them on the **Compliance** tab of **Security**. Format: see
[Compliance policies](https://github.com/PanoptiPulse/Laravel-MDM-Server/blob/main/docs/security-scanner.md#compliance-policies).

| Policy | Platform | Checks |
|---|---|---|
| `org.cis-mssql-2019-2022`: CIS Microsoft SQL Server 2019 / 2022 Benchmark | Windows (`sqlserver`, agent 1.18.0+) | 23 |
| `org.windows-baseline`: Windows workstation baseline | Windows (`posture`) | 10 |
| `org.linux-baseline`: Linux server baseline | Debian / Ubuntu (`posture`) | 5 |

### CIS Microsoft SQL Server 2019 / 2022

References are to the CIS Microsoft SQL Server 2019 / 2022 Benchmark unless noted.

| Check | Reference | Severity | Fails / warns when |
|---|---|---|---|
| `Sql.AdHocDistributedQueriesDisabled` | 2.1 | Medium | Ad Hoc Distributed Queries != 0 |
| `Sql.ClrEnabledDisabled` | 2.2 | Medium | clr enabled != 0 |
| `Sql.CrossDbOwnershipChainingDisabled` | 2.3 | High | cross db ownership chaining != 0 |
| `Sql.DatabaseMailXpsDisabled` | 2.4 | Low | Database Mail XPs != 0 |
| `Sql.OleAutomationDisabled` | 2.5 | High | Ole Automation Procedures != 0 |
| `Sql.RemoteAccessDisabled` | 2.6 | Medium | remote access != 0 |
| `Sql.RemoteAdminConnectionsDisabled` | 2.7 | Medium | remote admin connections != 0 (Not applicable on a failover cluster instance) |
| `Sql.ScanForStartupProcsDisabled` | 2.8 | Medium | scan for startup procs != 0 |
| `Sql.TrustworthyOff` | 2.9 | High | a user database with TRUSTWORTHY ON (msdb exempt) |
| `Sql.SaDisabled` | 2.13 | High | the SID 0x01 login is enabled |
| `Sql.SaRenamed` | 2.14 | Medium | the SID 0x01 login is still named sa |
| `Sql.XpCmdshellDisabled` | 2.15 | Critical | xp_cmdshell != 0 |
| `Sql.WindowsAuthOnly` | 3.1 | Medium | warns in mixed authentication mode |
| `Sql.SysadminCount` | custom (least privilege) | Medium | warns with more than 3 enabled non-service sysadmin logins |
| `Sql.PasswordPolicyEnforced` | 4.2, 4.3 | Medium | an enabled SQL login without CHECK_POLICY / CHECK_EXPIRATION |
| `Sql.FullBackupWithin24h` | custom (backup) | High | an online user database without a full backup in 24 h |
| `Sql.LogBackupWithin1hForFullRecovery` | custom (RPO) | High | a FULL / BULK_LOGGED user database without a log backup in 1 h |
| `Sql.CheckDbWithin7d` | custom (integrity) | High | a user database without a good CHECKDB in 7 days (Manual before SQL Server 2016 SP2) |
| `Sql.LinkedServerNoSa` | 3.x (linked servers) | High | a linked server mapped to sa |
| `Sql.DbOwnerNotSa` | custom (ownership) | Medium | a user database owned by sa |
| `Sql.ForceEncryptionOrTde` | 7.x (encryption) | Medium | warns without Force Encryption (or all-encrypted connections) and without TDE on every user database |
| `Sql.ErrorLogCount` | 5.1 | Low | fewer than 12 error log files |
| `Sql.LoginAuditingFailedOrBoth` | 5.4 | Medium | login auditing not Failure / Both (Manual when the registry is not readable) |

The agent signs in to each local instance with Windows authentication as `NT AUTHORITY\SYSTEM` (no
stored credentials). Give that login read access once per instance, or the checks it cannot read stay
**Manual**:

```sql
USE master;
GRANT VIEW SERVER STATE, VIEW ANY DEFINITION, VIEW ANY DATABASE TO [NT AUTHORITY\SYSTEM];
USE msdb;
CREATE USER [NT AUTHORITY\SYSTEM] FOR LOGIN [NT AUTHORITY\SYSTEM];
GRANT SELECT ON dbo.backupset TO [NT AUTHORITY\SYSTEM];
```

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

1. Add or change a rule / parser / policy and a fixture in `tests/fixtures/` (`tests/fixtures/policies/` for policies).
2. Bump `version` in `manifest.json` and run `python scripts/feed.py build`.
3. Run `python scripts/feed.py check` (CI does the same on every pull request).
4. Merge to `main`; servers pick it up within a day.

The server only reads Windows and Debian / Ubuntu agents and these sources: `software`, `processes`,
`listening`, `startup`, `admins`, `posture`, `sqlserver` (Windows, agent 1.18.0+), `events` (from parsers
on `windows.security`, `windows.system`, `windows.defender`, `linux.auth`; not for policies). macOS, iOS and Android are not supported.
