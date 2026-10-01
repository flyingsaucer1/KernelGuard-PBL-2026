# Running and demonstrating KernelGuard

## Database and startup

The default URL is `sqlite:///data/kernelguard.db`. Set KERNELGUARD_DB_URL to choose
another database. This variable must match across the audit collector, inventory
collector and dashboard. Config files validate policy fields; .env files are not
loaded automatically. Keep database passwords and session secrets out of Git.

From the project root, the launcher is `.\scripts\start.ps1`.
It imports the complete synthetic demo and serves the website on port 5000.
The equivalent commands are `python -m kernelguard demo` followed by
`python -m kernelguard serve`. Use `serve --port 5001` if needed.

Expected fresh-demo totals: **21 events and 5 alerts**. Inventory contains **2 users,
1 session, 3 processes and 1 USB device**. Replay adds no duplicate events/snapshots.
The original nine-event example is available through `demo --baseline`.
Custom policies and existing evidence can change totals.

## Administrator setup

Stop the dashboard before creating accounts. In the same terminal/database:

```powershell
.\.venv\Scripts\python.exe -m kernelguard create-admin arshpreet
$env:KERNELGUARD_SECRET_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.\.venv\Scripts\python.exe -m kernelguard serve
```

Choose a password of 12–256 characters when prompted. No default administrator or
password is shipped. Werkzeug stores salted scrypt password hashes. Account creation
rejects duplicate usernames and does not overwrite existing credentials.

Until an administrator exists, the dashboard is a read-only preview: all writes are
denied. Once an administrator exists, login and a secret of at least 32 characters
are required. Restart after account creation. A missing secret fails startup instead
of falling back to preview. Generate a fresh secret per lab session, or keep it in a
protected environment file for stable sessions. Rotating it invalidates old cookies.

Cookies are HttpOnly and SameSite=Strict; signed sessions expire after 30 minutes.
All POST forms require CSRF tokens, including login and logout. Five login attempts
per five minutes are allowed per serving process; successful login clears the count.
This local lab limit is shared across users and resets on restart.

## Demo sequence

1. Show the synthetic-data notice and the five rule cards.
2. Open the failed-login alert: five supporting authentication failures.
3. Open the after-hours alert: successful watched access outside configured hours.
4. Open the bulk alert: ten distinct paths in one user/session within sixty seconds.
5. Open the privileged-command alert: login UID 1001 and effective UID 0.
6. Open the USB alert and follow its device-enrollment link.
7. Sign in, approve the synthetic device with a note, and inspect enrollment history.
8. Acknowledge an activity alert with a note, then reopen it; both decisions remain.
9. Visit Host inventory and inspect users, boot-scoped sessions and process relationships.
10. Repeat the demo command and show unchanged counts.

USB first-seen observations do not identify the person who connected the device.
Enrollment changes the handling of future reappearance observations. It does not
clear an old alert, change its policy snapshot, block the hardware or prove authenticity.

## Commands

| Command | Purpose |
| --- | --- |
| `init-db` | Create missing schema tables, preserving existing data |
| `demo` | Complete synthetic activity and inventory demo |
| `demo --baseline` | Original small audit fixture |
| `import-audit PATH` | Import raw audit records; `--origin demo` labels synthetic input |
| `collect [--once]` | Linux audit polling; default five seconds |
| `inventory [--once]` | Linux metadata/USB polling; default ten seconds |
| `import-inventory PATH` | Import a validated snapshot JSON document |
| `create-admin USERNAME` | Privately prompt for a new administrator password |
| `serve [--port 5000]` | Run Waitress on 127.0.0.1 |
| `python -m scripts.evaluate` | Regenerate synthetic policy and timing results |
| `python -m scripts.check_environment` | Report Linux/MySQL readiness without changing the host |

Prefix commands with `python -m kernelguard`; choose a config with
`python -m kernelguard --config config.example.json ...`.
Inventory exports require host, origin, boot ID and observation timestamp; see
`fixtures/inventory.json`. Imported origin is a label supplied by the caller, not
cryptographic provenance. Keep JSON imports in a controlled local workflow.

## Update and recovery

Stop all project processes, select the intended database and run `init-db`. The
current upgrade adds tables; no existing table definitions or evidence are rewritten.
Old audit records without boot metadata remain explicitly unscoped; current live
collection uses a boot-aware source namespace and new per-boot checkpoint. Therefore
the first new live poll can overlap evidence previously stored by older releases.
Retain the older database separately when demonstrating the transition.

Raw exports have unknown boot context unless collected through the live path. They
are not automatically joined to inventory solely by PID or session number. Snapshot
replay is deduplicated; a different snapshot older than the latest accepted host/source
observation is rejected to prevent stale state from replacing newer observations.

Audit rotation can destroy unread evidence. Record the gap, preserve the remaining raw
logs, and inspect the exact checkpoint before any manual recovery. Do not delete all
checkpoints. Audit and inventory loops retry a busy cooperating writer; actual source
or database failures stop visibly. UI decisions return HTTP 409 if the writer is busy
or a stale form conflicts with newer history.

## Deployment scope

Waitress serves locally; no public listener is configured. Optional systemd templates
under linux/services assume installation at /opt/kernelguard. Review paths, service
users and environment files before installing them. Audit access and full /proc
metadata typically need elevation; the web service must run without root.

For MySQL, separate the schema/account setup role from the collector and web role.
The web role needs SELECT on required tables and INSERT on alert_reviews and
device_decisions; it does not need permission to edit event evidence. Create
administrators using the setup account. Preserve transaction/foreign-key support.

For HTTPS behind a trusted reverse proxy, set KERNELGUARD_HTTPS=1 to enable Secure
cookies. Do not set it for the plain HTTP localhost demo. Distributed rate limits,
MFA, account recovery, retention and Internet exposure are outside this single-host
student prototype. Approval history is append-only through the application, not
tamper-proof against a privileged database administrator.
