# Acceptance procedure

The software is implemented and tested with synthetic inputs on Windows and Linux.
Real protected-file reads were captured and ingested into MariaDB on Kali Linux on
2026-09-23 and 2026-10-01. The October check also verified live inventory, privileged
execution, bulk reads, failed-login grouping, restart replay, and administrator review.
See the [live audit check](LIVE_AUDIT_CHECK.md). Physical USB removal/reconnection,
device enrollment on a spare device, live USB-enumeration failure handling, and
Oracle MySQL remain unverified. This host's Cruzer Blade is the Kali boot drive and
must not be removed for testing. Do not submit sample screenshots as evidence of
the outstanding checks.

## Automated checks available now

From an activated virtual environment:

```bash
python -m pytest tests -q
python -m scripts.evaluate
python -m scripts.check_environment
```

The environment command exits 2 when lab prerequisites are missing. This is an
explicit incomplete-readiness result, not an application test failure. The MySQL
test is opt-in: set KERNELGUARD_TEST_MYSQL_URL to a disposable test database, then
run `python -m pytest tests/test_mysql.py -q`. It may create missing tables; test
records are rolled back. Never point the test at an unrelated/production database.

## Linux lab acceptance

Follow LINUX_SETUP.md in a disposable x86_64 Linux VM, then verify and record:

| Check | Expected evidence |
| --- | --- |
| Ordinary protected read | Linux audit event, separate UID values, stored path |
| Outside-hours read | Alert and linked successful event |
| Login threshold | Grouped authentication evidence without duplicate replay |
| Bulk reads | Threshold of distinct paths in a single observed session |
| Privileged execution | Selected harmless executable, original login UID and EUID 0 |
| Audit restart | Per-boot checkpoint resumes without duplicate current-format events |
| Inventory poll | Users, boot/session IDs and process start identities |
| USB first observation | Device row, presence event and unapproved-device alert |
| USB enrollment | Approved decision with administrator and note |
| Remove, poll, reconnect, poll | Absence/reappearance events; approved reconnection adds no unknown-device alert |
| Revoke then remove/reconnect | A new unapproved-device alert with preserved old decisions |
| Permission failure | Visible error/warning; no fabricated complete process or USB state |
| MySQL rollback/FKs | Integration test passes; schema uses InnoDB; invalid relationships rejected |
| Review workflow | CSRF rejection, stale-form rejection, immutable history |

On the Kali host, the ordinary read, outside-hours alert, login threshold, bulk
reads, privileged execution, audit restart, inventory poll, USB first observation,
MariaDB rollback/foreign-key test, and review workflow have been observed. An
unprivileged inventory poll also marked inaccessible process data incomplete and
saved a warning. USB enrollment/reconnect and live USB-enumeration failure remain
open. The MySQL integration test passed against a disposable MariaDB database;
Oracle MySQL was not
available. All 17 live database tables use InnoDB, and `sql/analysis.sql` executed
successfully with the read-only dashboard account.
The opt-in MariaDB test also covers synthetic USB approval, removal, approved
reconnection, revocation, and a new alert after reconnection. It does not replace
the outstanding physical USB observations.

For a harmless privilege demonstration, set privileged_executables to
`["/usr/bin/id"]` in a lab config, restart collectors/dashboard with that config,
then run `sudo /usr/bin/id` from a normal login session. Restore policy afterward.

For bulk activity, prepare ten dummy files in the monitored directory, wait beyond
the configured window, then read those files as the same normal user. File creation
can itself generate audit events, so inspect evidence rather than assuming one row
per shell command. Repeat one path to show it does not meet a distinct-path threshold.

For USB, use an expendable lab device and pass it through to the VM if necessary.
The device must be visible to pyudev inside Linux. Do not perform tests against
external machines/accounts or modify unrelated audit rules.

## Evidence to retain

Record OS/kernel and MySQL versions, configuration, timing, screenshots of actual
evidence, test outputs and any gaps. Do not include database passwords, session
secrets, personal file contents or raw command arguments in the submitted report.
A readiness probe or a mocked collector is not a substitute for these observations.
