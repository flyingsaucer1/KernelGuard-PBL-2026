# Arshpreet Singh — Assigned Work and Contribution Record

Project: **KernelGuard**

Role: **Team leader and Linux data-collection developer**

This file records Arshpreet's individual responsibilities. It can be used while
explaining the project, preparing the contribution sheet, or selecting files for
an individual GitHub commit. The main application still depends on the team's
database, detection and dashboard modules.

## Phase 2 responsibilities

1. Design the overall flow from Linux audit evidence to normalized application events.
2. Parse Linux Audit records and group related records using their audit serial number.
3. Extract only required metadata: event time, host, login UID, real UID, effective
   UID, process ID, audit session, path, executable and success/failure result.
4. Avoid storing file contents, passwords and raw command arguments.
5. Add replay protection by generating stable source identifiers for imported records.
6. Implement live audit collection checkpoints scoped to the host and boot ID.
7. Handle missing audit access, command failures and database-writer contention visibly.
8. Document the Linux audit setup and safe demonstration procedure.

### Main Phase 2 files

| File | Arshpreet's work and purpose |
| --- | --- |
| `kernelguard/parser.py` | Converts raw Linux Audit output into normalized KernelGuard records. |
| `kernelguard/__main__.py` | Provides `import-audit` and `collect` commands, boot-aware checkpoints and collector startup. |
| `kernelguard/locking.py` | Prevents two cooperating collectors from writing at the same time and reports busy writers. |
| `linux/kernelguard.rules` | Watches the controlled protected directory in the Linux lab. |
| `config.example.json` | Supplies the host identity, protected path, allowed hours and detection thresholds. |
| `docs/LINUX_SETUP.md` | Explains audit installation, permissions, collector startup and real-event testing. |

## Phase 3 responsibilities

1. Collect the Linux user inventory using the operating-system account database.
2. Collect process identity using `psutil` and `/proc`, including PID, parent PID,
   start time, real user, audit session and boot identity.
3. Collect connected USB metadata using `pyudev`, while excluding root hubs.
4. Validate snapshots before database integration and reject duplicate or ambiguous
   user, process and USB identities.
5. Keep process and audit-session identities separate across reboots and PID reuse.
6. Mark incomplete process scans honestly instead of treating missing processes as exited.
7. Treat a failed USB scan as an error instead of recording false removals.
8. Provide one-time and continuous inventory collector commands.
9. Help integrate real Linux observations with the database and dashboard through a
   documented snapshot contract.
10. Run the final automated regression and policy evaluation checks.

### Main Phase 3 files

| File | Arshpreet's work and purpose |
| --- | --- |
| `kernelguard/inventory/models.py` | Defines and validates the user, session, process and USB snapshot contract. |
| `kernelguard/inventory/collector.py` | Reads real Linux users, processes, sessions, boot information and USB devices. |
| `kernelguard/inventory/__init__.py` | Exposes the inventory components as an application package. |
| `kernelguard/__main__.py` | Provides `inventory --once` and continuous inventory polling. |
| `fixtures/inventory.json` | Supplies a clearly labelled synthetic snapshot for repeatable demonstrations. |
| `tests/test_inventory.py` | Checks snapshot validation, boot/PID identity, partial scans, USB behavior and persistence integration. |
| `scripts/check_environment.py` | Reports whether Linux, `ausearch`, `pyudev` and MySQL prerequisites are available. |
| `docs/ACCEPTANCE.md` | Lists the final Linux, physical USB and MySQL evidence that must be recorded. |

## How the Phase 3 flow works

```text
Linux pwd + /proc + psutil + pyudev
                |
                v
       validated inventory snapshot
                |
                v
      transactional database storage
                |
                v
 users / sessions / processes / USB history / alerts
                |
                v
        authenticated web dashboard
```

The collector records observations rather than claiming complete historical truth.
For example, a process can start and finish between two polls, and a USB device can be
connected briefly between polls. KernelGuard shows timestamps and warnings so these
limits are visible during evaluation.

## Current completion status

- Phase 2 audit parsing and collector software: **complete and automatically tested**.
- Phase 3 inventory and USB software: **complete and automatically tested**.
- Synthetic policy evaluation: **11 of 11 expected outcomes pass**.
- Full automated suite on the Windows development machine: **87 passed, 1 MySQL test skipped**.
- Real Kali audit capture: **must be recorded on the Kali system**.
- Physical USB remove/reconnect test: **must be recorded on the Kali system**.
- Real MySQL integration test: **must be run after a disposable MySQL test database is configured**.

The final three items require the actual Linux lab and hardware. Synthetic fixtures
or Windows test results must not be presented as proof that those checks were performed.

## Commands Arshpreet should demonstrate on Kali

From the project directory, after following `docs/LINUX_SETUP.md`:

```bash
. .venv/bin/activate
python -m scripts.check_environment
sudo --preserve-env=KERNELGUARD_DB_URL "$PWD/.venv/bin/python" -m kernelguard --config config.example.json collect
sudo --preserve-env=KERNELGUARD_DB_URL "$PWD/.venv/bin/python" -m kernelguard --config config.example.json inventory
```

In another terminal, run the dashboard without `sudo`:

```bash
. .venv/bin/activate
python -m kernelguard --config config.example.json serve
```

For the final contribution record, keep screenshots of the environment check, a real
protected-file event, process/user inventory, a physical USB observation and the final
test output. Do not include database passwords, session secrets or personal file contents.
