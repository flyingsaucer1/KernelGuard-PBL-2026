# Arshpreet Singh

Role: **Team leader and Linux data-collection developer**

Detailed responsibilities and demonstration commands are recorded in
[`docs/ARSHPREET_WORK.md`](../ARSHPREET_WORK.md).

## Primary files

| File | Assigned responsibility |
| --- | --- |
| `kernelguard/parser.py` | Group and normalize raw Linux Audit records. |
| `kernelguard/locking.py` | Coordinate collector writers and report lock contention. |
| `kernelguard/inventory/models.py` | Validate user, session, process and USB snapshots. |
| `kernelguard/inventory/collector.py` | Collect Linux users, processes, sessions, boot identity and USB metadata. |
| `kernelguard/inventory/__init__.py` | Export inventory package components. |
| `linux/kernelguard.rules` | Audit the controlled protected directory. |
| `linux/services/kernelguard-audit.service` | Start the Linux audit collector as a service. |
| `linux/services/kernelguard-inventory.service` | Start the inventory collector as a service. |
| `fixtures/inventory.json` | Provide repeatable synthetic inventory input. |
| `scripts/check_environment.py` | Check Linux, audit, pyudev and MySQL readiness. |
| `docs/LINUX_SETUP.md` | Explain real Linux installation and collection. |
| `docs/ARSHPREET_WORK.md` | Record Arshpreet's individual work and evidence checklist. |

## Shared files

| File | Arshpreet's section |
| --- | --- |
| `kernelguard/__main__.py` | `import-audit`, `collect`, `inventory`, boot checkpoints and collector loops. Primary integration owner: Ahmed. |
| `config.example.json` | Host ID, protected path and collector policy settings. Shared with Ankit and Ahmed. |
| `tests/test_pipeline.py` | Parser, replay and collector behavior. Primary test-rule owner: Ankit. |
| `tests/test_inventory.py` | Snapshot validation and Linux identity behavior. Database portions are shared with Ahmed. |
| `docs/ARCHITECTURE.md` | OS concepts and collection limitations. Team-level file. |
| `docs/ACCEPTANCE.md` | Linux and physical USB evidence. Team-level file. |

## What Arshpreet should explain

- AUID, UID and EUID differences.
- Audit-record grouping and replay protection.
- Host/boot-scoped checkpoints.
- PID reuse and process start-time identity.
- Incomplete scans, USB polling limitations and collector startup.
