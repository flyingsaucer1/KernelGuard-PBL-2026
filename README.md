# KernelGuard — Phase 2 PBL

This repository contains one Phase 2 application at its root. It demonstrates Linux Audit events moving through a parser, into a **MySQL** database, through two detection rules, and onto a read-only dashboard with supporting evidence. Live collection includes file opens in the Kali home and mounted drives, process launches by logged-in users, and failed SSH or console logins.

It is a presentation copy reconstructed from the completed project, not a historical Git snapshot of the team's original Phase 2 submission. The completed project remains separate.
See [code provenance and similarity](docs/CODE_PROVENANCE.md) before using this copy in a submission.

## One database

Phase 2 uses one dedicated MySQL database, normally named `kernelguard_phase2`. The fixture importer, live Linux collector, and dashboard all use the same `KERNELGUARD_PHASE2_DB_URL`. There is no SQLite runtime or automatic database fallback. The application rejects a database containing tables or event types from later phases.
The database schema and analysis queries are in `sql/`. `app.py init-db` creates the database tables in MySQL; the repository does not store live data or database passwords.

The fixture is optional and clearly marked `origin=demo`. Linux Audit records are marked `origin=live`. For a live-only presentation, leave the fixture unimported.

## Linux setup

On Kali, use the [Kali MySQL setup](docs/KALI_SETUP.md). Kali's `default-mysql-server` package [currently depends on MariaDB](https://www.kali.org/tools/mysql-defaults/), so it is not the Oracle MySQL server used for this project. On supported Debian or Ubuntu releases, you can instead install MySQL Community Server using the [official MySQL APT guide](https://dev.mysql.com/doc/mysql-apt-repo-quick-guide/en/). From this folder:

```bash
sudo apt update
sudo apt install python3-venv auditd openssh-server
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
sudo systemctl enable --now auditd ssh
```

For a native Debian/Ubuntu MySQL install, start its `mysql` service and open the MySQL shell as an administrator (`mysql -u root -p`, or `sudo mysql` if socket login is configured). Use your own lab password:

```sql
CREATE DATABASE kernelguard_phase2 CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'kg_phase2'@'127.0.0.1' IDENTIFIED BY 'CHOOSE_A_LAB_PASSWORD';
GRANT SELECT, INSERT, UPDATE, CREATE, INDEX, REFERENCES
  ON kernelguard_phase2.* TO 'kg_phase2'@'127.0.0.1';
```

In **each** project terminal, set the same URL and activate the virtual environment:

```bash
export KERNELGUARD_PHASE2_DB_URL='mysql+pymysql://kg_phase2:CHOOSE_A_LAB_PASSWORD@127.0.0.1/kernelguard_phase2?charset=utf8mb4'
python app.py init-db
```

URL-encode special characters in the password. Keep credentials out of Git and screenshots. `init-db` creates the eight tables. [sql/schema.mysql.sql](sql/schema.mysql.sql) is reviewable DDL generated from the Python models; do not apply it a second time after `init-db`.

## Windows setup

On Windows with MySQL Server already installed, create this project's own Python environment from PowerShell:

```powershell
cd C:\KernalGuard-Phase2-PBL
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the `CREATE DATABASE`, `CREATE USER`, and `GRANT` statements above in MySQL Workbench. Then set the URL for that dedicated database and initialize Phase 2:

```powershell
$env:KERNELGUARD_PHASE2_DB_URL = 'mysql+pymysql://kg_phase2:CHOOSE_A_LAB_PASSWORD@127.0.0.1/kernelguard_phase2?charset=utf8mb4'
.\.venv\Scripts\python.exe app.py init-db
.\.venv\Scripts\python.exe app.py demo
.\.venv\Scripts\python.exe app.py serve
```

Use the same URL in each new terminal. The Windows dashboard and fixture use MySQL; live audit collection requires Linux.


## Run and demonstrate

For an empty dashboard, run `python app.py` or `python app.py serve`. Open `http://127.0.0.1:5002/` on that machine. The dashboard binds to localhost.

For a repeatable **synthetic** demonstration, run `python app.py demo` before starting the dashboard. Expect 9 events, 2 alerts, and 6 alert-to-event evidence links. Repeating `demo` inserts no duplicates. Synthetic events do not prove live Linux collection.

To collect live file events, create the watched folder and load the supplied x86_64 audit rule:

```bash
sudo mkdir -p /srv/kernelguard/protected
printf 'PBL test data only\n' | sudo tee /srv/kernelguard/protected/demo.txt
sudo chmod 755 /srv/kernelguard/protected
sudo chmod 644 /srv/kernelguard/protected/demo.txt
sudo install -m 640 linux/kernelguard.rules /etc/audit/rules.d/kernelguard.rules
sudo augenrules --load
sudo auditctl -l
```

Check that `kernelguard_protected`, `kernelguard_file_access`, and `kernelguard_process_exec` appear in the rule list. The protected path must match `config.example.json`. The new rules record file opens in `/home/kali`, `/run/media/kali/Acer`, `/media`, and `/mnt`, plus process launches from logged-in user sessions. They exclude services with an unset login UID. They can generate many audit and MySQL rows during normal use. A newly mounted drive may need the rules reloaded or an added path rule. In a separate terminal with the same database URL:

```bash
sudo --preserve-env=KERNELGUARD_PHASE2_DB_URL "$PWD/.venv/bin/python" app.py collect --config config.example.json
```

Run the dashboard without sudo in another terminal:

```bash
python app.py serve --config config.example.json
```

Read the dummy file as a regular lab user and confirm the event with `sudo ausearch -k kernelguard_protected --start recent -i`. Launch a program such as `id` and open a file in your home directory to see `process_exec` and `file_access` events in the timeline. File access here means an audited open or creation; it does not record each read or write on an already-open file. The two alert rules still apply only to after-hours protected-folder access and repeated failed logins. To demonstrate an after-hours alert during class, copy the config to `config.lab.json`, set allowed hours that exclude the current local hour, and restart collector and dashboard with that config. Do not change the system clock. Five failed SSH or console authentications for a controlled local test account within five minutes demonstrate the other rule, subject to your lab's lockout policy.

The collector stores its audit cursor in the **same MySQL transaction** as new events and alerts. A successful recent poll appears as `Active` on the dashboard. Real Linux collection still needs verification on your own lab machine.

On Windows, the same MySQL database and fixture command can show the DBMS and dashboard. Live `collect` remains Linux-only.

## DBMS model

| Table | Purpose |
| --- | --- |
| `events` | Audit event metadata; unique `source_id` prevents duplicate imports. |
| `audit_details` | Original audit IDs, UID fields, syscall and inode details. |
| `event_context` | Boot ID for live events. |
| `alerts` | Rule, severity, reason and deduplication key. |
| `alert_events` | Many-to-many links from alerts to supporting events. |
| `rule_policies` | Saved detection settings. |
| `alert_policies` | Connects each alert to its policy snapshot. |
| `checkpoints` | Collector cursor and health status. |

The models use primary keys, foreign keys, unique constraints, indexes, InnoDB transactions, and `utf8mb4_bin` collation. Run [sql/analysis.sql](sql/analysis.sql) in MySQL to show grouping, joins, evidence, and policy history.

## Files and checks

See [docs/FILE_GUIDE.md](docs/FILE_GUIDE.md) for every file and [docs/TEAM.md](docs/TEAM.md) for presentation areas. The teammate map is a speaking guide, not proof of exact file authorship.

```bash
python -m pytest -q
python -m scripts.export_schema
```

The ordinary tests check the parser, schema definitions, and database URL without starting a database server. For the optional MySQL integration test, set `KERNELGUARD_PHASE2_TEST_DB_URL` to a **separate empty disposable database whose name ends in `_test`**; that test creates and drops its own tables. It is skipped when the variable is unset. On 2026-10-08, all four tests passed on this Windows machine using an isolated MySQL 8.0.46 database. The CLI created the schema and imported 9 events, 2 alerts, and 6 evidence links; the overview and alert pages returned HTTP 200. Kali live audit collection and the MySQL 8.4 container still need verification on the target Kali machine.
