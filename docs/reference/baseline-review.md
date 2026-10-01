# OS and DBMS review — 8 September 2026

Historical review. Current inventory, rules and review behavior are documented in
[architecture](../ARCHITECTURE.md); validation is described in [acceptance](../ACCEPTANCE.md).

## Assessment

The project applies OS auditing and relational data handling in a meaningful way.
It is a focused Phase 2 event-monitoring prototype, not the full inventory and detection
system described for all project phases. It should not be described as implementing
CPU scheduling, virtual memory management, kernel interception, a new DB engine or ML.

## Corrections made

| Finding | Correction | Verification |
|---|---|---|
| `uid` and `auid` were collapsed into one actor label | Added canonical OS details with separate login, real and effective UID fields; documented the legacy actor field | Elevated-process identity regression |
| USER_AUTH `uid` was displayed as effective UID without evidence | Missing euid remains unknown; UI reads canonical OS fields | Authentication identity regression |
| Unset OS identities looked like ordinary numeric IDs | Map unset values to NULL in OS details | Unknown identity/session regression |
| Syscall, architecture, inode and device metadata were discarded | Store them in an optional event extension table | Metadata persistence regression |
| Hexadecimal filenames containing a newline were not decoded | Preserve valid decoded UTF-8 even when not printable | Protected-path newline regression |
| Alert explanations lacked historical policy configuration | Deduplicated rule policy snapshots linked to every new alert | Policy reuse and change regression |
| A single writer was assumed but unenforced | CLI writer lock for SQLite/OS and MySQL/named locks | Local contention and release regression; MySQL lab check remains |
| Configuration could accept booleans/floats as rule numbers | Strict integer and documented-key validation | Invalid configuration regressions |
| Foreign keys and cursor rollback needed direct evidence | Added tests for orphan rejection and failure after an event insert | SQLite regression suite |

The update is additive: `init-db` creates three new tables and preserves existing rows.
Old alerts retain their evidence without a fabricated policy snapshot. Reimporting known
raw input may enrich older events with OS details. Existing base tables are not rebuilt;
`init-db` is not a general migration engine.

## Concepts present

OS: system-call audit records, users and credentials, process/session metadata,
file access results, user-space subprocesses, scoped permissions and mutual exclusion.

DBMS: primary/unique/foreign keys, one-to-one and many-to-many relationships,
policy normalization, parameterized queries, aggregation, joins, indexes and transactions.
Persistence uses SQLite for preview and InnoDB/MySQL for the intended lab deployment.

## Remaining validation and limitations

- Windows automated tests exercise parsing, rules, SQLite persistence, rollback,
  locking and Flask responses. Linux collector calls are mocked.
- No live Linux auditd or MySQL server is available on this development machine.
  MySQL DDL is generated; execution, advisory locking, isolation and EXPLAIN output
  still need the lab acceptance run.
- The parser supports a selected raw audit format, not every audit record, filesystem
  namespace or non-UTF-8 filename. The detailed explanation lists path limitations.
- No evidence supports claims about detection accuracy, resource overhead, throughput
  or protection against a privileged attacker changing local logs/database rows.
- Current alert severity is fixed policy output. It is not a probability of malicious intent.
- The original proposal's persistent user/session/device tables and further rules remain
  Phase 3 work; the event store records identity snapshots in Phase 2.

Review evidence is in `tests/test_concepts.py`, `tests/test_pipeline.py`, and the optional
`tests/test_mysql.py`. Full explanation: `PROJECT_EXPLAINED.md`. Attribution:
`ORIGINALITY_AND_ATTRIBUTION.md`.

## Recorded local result

`python -m pytest -q`: **36 passed, 1 skipped**. The skipped test is the explicitly
configured MySQL integration test. MySQL DDL export completed. Updating the existing
SQLite schema and replaying its fixture preserved 9 events and 2 alerts, inserting
zero duplicate events. A separate fresh review database produced 9 events and 2 alerts
with new policy snapshots. Browser verification confirmed separate OS identities,
saved policy version/settings and syscall/inode evidence on the alert page.

## Library simplification follow-up

Portalocker replaces manual Windows/POSIX locking branches (locking module: 52 to 39
lines). Pydantic replaces handwritten field/type/range validation with a declarative
configuration model; cross-field policy checks remain project code. The affected
Python modules, including the new configuration module, total 252 lines versus 260
before this refactor. The main benefit is less platform and validation code to maintain.

Verification after the refactor: **43 passed, 1 skipped**, with the real MySQL test
still skipped. Dependency consistency passed, the example configuration initialized
the existing SQLite schema, and replay inserted zero duplicate events. SQL schema,
detection thresholds and historical records were not changed by this refactor.
