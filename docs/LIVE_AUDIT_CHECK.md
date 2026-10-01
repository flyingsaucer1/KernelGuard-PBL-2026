# Live protected-file audit check

On 2026-09-23, a Kali Linux lab host captured real reads of
`/srv/kernelguard/protected/demo.txt`. KernelGuard ingested them first into a
disposable MariaDB database, then into a dedicated persistent MariaDB database.
This verifies the protected-file path on this host; it does not complete the full
acceptance checklist.

## Host setup

- The existing `auditd -f` foreground process was stopped and the managed
  `auditd.service` was started and enabled for boot. Its log changed from a stale
  2026-09-15 timestamp to current records.
- The example protected directory and harmless `demo.txt` were created under
  `/srv/kernelguard/protected`.
- `linux/kernelguard.rules` was installed as
  `/etc/audit/rules.d/kernelguard.rules` and loaded with `augenrules --load`.
  `auditctl -l` showed the `kernelguard_protected` rule on that directory.

## Observed result

The regular user ran `cat /srv/kernelguard/protected/demo.txt`. A raw `ausearch`
query for `kernelguard_protected` showed a successful `openat` syscall
with the file path, UID 1000, and audit serial 362. A one-shot KernelGuard collector
poll against a disposable MariaDB database inserted three file-access events from
the new rule, including this successful read. The stored row had
`origin=live`, `outcome=success`, `uid=1000`, `effective_uid=1000`, the exact file
path, and audit serial 362. An earlier controlled-folder replay check inserted
zero events on a second poll.

The disposable database was used only to verify ingestion. A continuously running
collector was then configured as follows:

- MariaDB was initialized under `/var/lib/mysql`, started, and enabled for boot.
- A dedicated `kernelguard_live` database was created. The
  `kernelguard_collector` account authenticates from the local root process through
  the Unix socket; it has only SELECT, INSERT, UPDATE, CREATE, INDEX, and REFERENCES
  on that database. No database password is stored in the service unit.
- The project Linux environment is `.venv-linux`. The installed
  `/etc/systemd/system/kernelguard-audit.service` runs the collector every five
  seconds using `config.example.json`. It is active and enabled for boot.
- The collector initially restarted on idle polls because this host's `ausearch`
  returns exit code 1 with empty output for no new records. The collector now treats
  that form as an empty poll while still raising on reported errors. It stayed
  active through repeated idle polls after the fix.
- With the service running, another regular-user `cat` produced a successful
  `file_access` row in `kernelguard_live` with UID 1000, audit serial 649,
  `origin=live`, and the exact protected path. The collector reported three new
  events, then returned to zero on idle polls.

## Live dashboard

The dashboard runs at <http://127.0.0.1:5000/> through
`kernelguard-web.service`, active and enabled for boot. It runs as the unprivileged
`kali` user and uses `kernelguard_viewer`, a separate Unix-socket MariaDB account
with SELECT access to `kernelguard_live`. The overview returned HTTP 200 and showed
12 stored live events, three alerts, and an Active collector. The alert evidence
and inventory routes also returned HTTP 200.

At the time of this 2026-09-23 check, no administrator existed, so the dashboard
showed its read-only preview. The following 2026-10-01 follow-up supersedes that
operational status. To inspect the running services:

```bash
sudo systemctl status auditd mariadb kernelguard-audit.service kernelguard-web.service
sudo journalctl -u kernelguard-audit.service -n 20 --no-pager
sudo ausearch -k kernelguard_protected --start recent --raw
```

## 2026-10-01 live follow-up

The running deployment uses `/home/kali/Desktop/KernalGuard`, while the project
copy on the mounted Acer volume is separate. Both copies had matching application
code for the checked modules. The live database remains `kernelguard_live` in
MariaDB 11.8.6, using Unix-socket accounts for the root collector and unprivileged
dashboard. The auditd, MariaDB, audit collector, inventory collector and dashboard
services were active; the project services were enabled for boot.

- A one-shot inventory poll stored 59 users, 434 processes and three USB devices
  without warnings. The recurring `kernelguard-inventory.service` was installed
  and enabled; subsequent polls continued to store live snapshots. The first
  observations created three unapproved-device alerts. The devices included the
  Kali boot drive, which was not unplugged or enrolled.
- A separate unprivileged inventory poll into a temporary SQLite database stored
  93 visible processes and reported 356 unavailable or exited processes. It saved
  `processes_complete=false` and the warning, so this process-permission failure
  did not become a falsely complete snapshot. The temporary database was removed.
- The dashboard's `kernelguard_viewer` account received INSERT permission only on
  `alert_reviews` and `device_decisions`, in addition to its existing SELECT grant.
  An administrator was created and a root-owned, mode 0600 session-secret file was
  configured. HTTP login, dashboard, inventory and alert evidence pages worked.
  The administrator password is not stored in this report.
- A fresh ordinary-user read of `demo.txt` produced a successful live file event
  with login, real and effective UID 1000 and the exact path. The three earlier
  outside-hours alerts retained linked successful file evidence.
- The targeted privileged-execution audit rule was installed. A harmless
  `passwd --help` execution as root produced a successful `/usr/bin/passwd` event
  with login UID 1000 and effective UID 0, plus a privileged-command alert.
- Ten controlled files were created in the protected folder and read as the
  regular user. A bulk alert linked ten distinct successful user-read events.
  Fixture creation also produced a separate bulk alert; its evidence has effective
  UID 0, illustrating why the linked identity details matter during review.
- Five incorrect console logins to a temporary test account produced five distinct
  `USER_AUTH`-derived events and one grouped failed-login alert with five linked
  events. The account was removed after the test. Restarting the audit collector
  left exactly five distinct stored events for that account.
- On the live bulk alert, an invalid CSRF token returned HTTP 400, a stale review
  returned HTTP 409, and acknowledge/reopen left two retained review records. The
  final alert state is Open.
- The opt-in MySQL integration test passed against a disposable MariaDB database,
  which was then removed. It was extended and rerun against another disposable
  MariaDB database to verify synthetic USB approval, removal, approved
  reconnection, revocation, and a fresh alert after reconnecting. The test also
  verified invalid foreign-key rejection. All 17 live tables use InnoDB. Every
  read-only query in `sql/analysis.sql` executed successfully.

Physical USB removal/reconnection and enrollment on a spare device remain untested:
none was available, and the Cruzer Blade is the Kali boot medium. A live
USB-enumeration failure was not induced against the functioning services.
Oracle MySQL was not available; the MariaDB result does not establish Oracle MySQL
compatibility.
