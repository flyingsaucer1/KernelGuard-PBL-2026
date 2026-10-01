# KernelGuard

A Linux host activity monitor combining operating-system evidence with a relational
database, explainable detection rules and administrator review.

## Start on Linux

The copied `.venv` contains Windows executables. Create a separate Linux environment:

```bash
python3 -m venv .venv-linux
. .venv-linux/bin/activate
python -m pip install -r requirements.txt
export KERNELGUARD_DB_URL=sqlite:///data/kernelguard-linux.db
python -m kernelguard demo
python -m kernelguard serve
```

Open http://127.0.0.1:5000. Run `python -m pytest tests -q` and
`python -m scripts.evaluate` from the activated environment. For live audit and
USB collection, follow [Linux setup](docs/LINUX_SETUP.md) and the
[acceptance procedure](docs/ACCEPTANCE.md).

## Start on Windows

From PowerShell:

```powershell
cd C:\Users\arshp\OneDrive\Desktop\KernalGuard
.\scripts\start.ps1
```

Open http://127.0.0.1:5000. A fresh demo has **21 events, 5 alerts, 2 users,
1 audit session, 3 processes and 1 USB device**. All sample input is labelled synthetic.

If PowerShell blocks script execution, run:

```powershell
.\.venv\Scripts\python.exe -m kernelguard demo
.\.venv\Scripts\python.exe -m kernelguard serve
```

A new checkout needs Python 3.11+:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Features

- Linux audit ingestion with grouped records, identity metadata, replay protection
  and transactional checkpoints scoped to host/boot.
- Five policies: failed logins, after-hours file access, bulk distinct-path activity,
  selected privileged commands and unapproved USB observations.
- Persistent user, audit-session, process and USB inventories. Process identities
  include host, source, boot, PID and start time; parent links require supporting observations.
- Administrator login, CSRF protection, alert acknowledgement/reopening and device
  approval/revocation with notes and retained history.
- MySQL/InnoDB support, a SQLite demo, exclusive writer locks and Waitress serving on loopback.
- Automated regression tests, a reproducible evaluation script and Linux acceptance instructions.

## Organization

```text
kernelguard/
  core.py                 relational event schema and original activity policies
  activity_rules.py       privileged-command and bulk-file policies
  parser.py               Linux Audit normalization
  config.py               validated policy settings
  locking.py              database writer mutual exclusion
  auth.py / reviews.py    administrator authentication and alert decisions
  web.py                  activity and evidence routes
  inventory/              models, Linux collector, schema, persistence, routes
  templates/ / static/    interface
fixtures/                 synthetic audit and inventory inputs
scripts/                  launch, evaluation, environment check and schema export
linux/                    audit rules and optional service templates
sql/                      generated MySQL schema and analysis queries
tests/                    functional and regression checks
docs/                     operations, architecture, acceptance and evaluation
data/                     ignored local databases; never commit credentials or evidence
```

## Documentation and checks

- [Operations and demo](docs/OPERATIONS.md)
- [Which files are needed](docs/FILE_GUIDE.md)
- [Architecture and module responsibilities](docs/ARCHITECTURE.md)
- [Linux setup](docs/LINUX_SETUP.md)
- [Acceptance procedure and outstanding real-hardware checks](docs/ACCEPTANCE.md)
- [Evaluation results and limits](docs/EVALUATION.md)
- [Arshpreet's assigned work and contribution record](docs/ARSHPREET_WORK.md)
- [Team file ownership and member-wise grouping](docs/contributions/README.md)
- [AI assistance and attribution](docs/ORIGINALITY_AND_ATTRIBUTION.md)

With either platform's virtual environment active:

```bash
python -m pytest tests -q
python -m scripts.evaluate
python -m scripts.check_environment
```

The local software/demo is implemented. Real protected-file reads were captured
and ingested into MariaDB on a Kali Linux lab host. On 2026-10-01, the live
inventory collector and administrator login were enabled, and controlled file,
privileged-command, bulk-read, failed-login and review checks passed. The audit,
inventory and localhost dashboard services are enabled for boot. See the
[live audit check](docs/LIVE_AUDIT_CHECK.md).
The live deployment uses MariaDB through the MySQL driver; the default SQLite URL
below is for a standalone demo. Physical USB removal/reconnection and Oracle MySQL
acceptance remain unverified because this host has no spare USB device or Oracle
MySQL instance.
Snapshots and unit mocks do not establish those results. KernelGuard detects policy
matches; it does not block attacks, prove data copying or establish malicious intent.

The default database is now `sqlite:///data/kernelguard.db`. Earlier local SQLite
databases are preserved in `data/archive/sqlite-snapshots/`. To use one, set
KERNELGUARD_DB_URL explicitly and run `init-db` before serving.
The role backup, if retained separately, is not a runtime dependency.
