# Project file guide

The outer `KernalGuard/` directory is the project folder. The inner
`kernelguard/` directory is its Python application package. Commands such as
`python -m kernelguard collect` import code from that inner directory. It is not
a second copy of the project, so keep its Python files, `templates/`, and
`static/` together.

| Path | Why it is useful |
| --- | --- |
| `kernelguard/` | Running application: audit parser, policies, database models, inventory collector, and dashboard. |
| `config.example.json` | Policy and host settings used by the live collector and dashboard services. |
| `requirements.txt` | Lists Python dependencies needed to recreate an environment. |
| `.venv-linux/` | Installed Linux Python environment used by the live services on this host. |
| `.venv/` | Copied Windows Python environment used by `scripts/start.ps1`; not used by the Kali services. |
| `linux/` | Audit rules and portable systemd service templates. |
| `scripts/` | Demo launchers, evaluation, environment check, and schema export tools. |
| `tests/` and `fixtures/` | Regression tests and controlled sample input. |
| `sql/` | MySQL schema export and analysis queries; reference material, not runtime code. |
| `docs/` | Setup, operations, evidence, and team documentation. `docs/reference/` contains historical design notes. |
| `data/kernelguard.db` | Default SQLite demo database, separate from the live MariaDB database. |

The live database is `kernelguard_live` in the host MariaDB installation under
`/var/lib/mysql`. The running services are installed under `/etc/systemd/system`.
Their source code, Linux environment, and configuration remain in this project.

## Separated local artifacts

- `data/archive/sqlite-snapshots/` holds older phase/demo SQLite databases and
  their writer lock files. No current project command refers to these names.
- `data/archive/old-server-logs/` holds old local server logs.
- `tmp/archive/generated-caches/` holds Python and pytest caches that were
  already present. Python or pytest may create new caches during future runs.
- `tmp/pdfs/` and other `tmp/` files are presentation or evaluation artifacts;
  they are not needed to run the application.

Nothing in these archive folders was deleted. The active Kali services do not
use them. Keep `.venv-linux/` and the inner `kernelguard/` package in their
current locations while the services are installed.
