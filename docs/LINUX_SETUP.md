# Linux lab setup and acceptance run

Target: disposable x86_64 Ubuntu Linux VM, Python 3.11+, MySQL, sudo access.
Commands below install the project in your current copied project directory.
Live audit and physical USB acceptance still require a configured Linux lab.

## 1. Dependencies

```bash
sudo apt update
sudo apt install python3-venv python3-pip auditd mysql-server openssh-server
python3 -m venv .venv-linux
. .venv-linux/bin/activate
pip install -r requirements.txt
sudo service auditd start
sudo service mysql start
sudo service ssh start
```

## 2. Database

Open `sudo mysql`. Choose your own local lab password; replace the placeholder below.

```sql
CREATE DATABASE kernelguard CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'kernelguard'@'localhost' IDENTIFIED BY 'REPLACE_WITH_YOUR_LAB_PASSWORD';
GRANT SELECT, INSERT, UPDATE, CREATE, INDEX, REFERENCES ON kernelguard.* TO 'kernelguard'@'localhost';
```

In the project terminal:

```bash
export KERNELGUARD_DB_URL='mysql+pymysql://kernelguard:REPLACE_WITH_YOUR_LAB_PASSWORD@127.0.0.1/kernelguard?charset=utf8mb4'
python -m kernelguard init-db
```

The database URL must URL-encode password special characters. Keep it out of submitted screenshots.
`init-db` creates missing tables; it does not migrate existing tables or delete data.
The equivalent DDL is in `sql/schema.mysql.sql`; choose either method, not both.

After schema initialization, use a SELECT-only account for the dashboard. In `sudo mysql`:

```sql
CREATE USER 'kernelguard_viewer'@'localhost' IDENTIFIED BY 'REPLACE_WITH_A_DIFFERENT_LAB_PASSWORD';
GRANT SELECT ON kernelguard.* TO 'kernelguard_viewer'@'localhost';
GRANT INSERT ON kernelguard.alert_reviews TO 'kernelguard_viewer'@'localhost';
GRANT INSERT ON kernelguard.device_decisions TO 'kernelguard_viewer'@'localhost';
```

In the dashboard terminal, set `KERNELGUARD_DB_URL` to the same database using this
viewer account. The collector retains its original account. Schema creation needs
the schema-capable account; the viewer cannot run `init-db` or `demo`.

## 3. Controlled folder and audit rule

```bash
sudo mkdir -p /srv/kernelguard/protected
printf 'Dummy PBL test data only\n' | sudo tee /srv/kernelguard/protected/demo.txt
sudo chmod 755 /srv/kernelguard/protected
sudo chmod 644 /srv/kernelguard/protected/demo.txt
sudo install -m 640 linux/kernelguard.rules /etc/audit/rules.d/kernelguard.rules
sudo augenrules --load
sudo auditctl -l
```

Verify the output includes `kernelguard_protected`. This rule is for x86_64/native
64-bit processes; adapt architecture rules if your lab uses another architecture.
If an immutable audit configuration prevents loading rules, use the lab administrator's
approved configuration/reboot procedure; do not clear existing audit rules.
Changing the protected directory requires updating both the audit rule and JSON config.

## 4. Collector and dashboard

Create the schema before starting the collector. In terminal A (same exported DB URL):

```bash
sudo --preserve-env=KERNELGUARD_DB_URL "$PWD/.venv-linux/bin/python" -m kernelguard --config config.example.json collect
```

Sudo is used to read audit logs; the collector is the only elevated component.
If your sudo policy forbids preserving that variable, have the lab administrator
configure audit-log read access or an appropriate environment policy for this lab.

In terminal B, activate `.venv-linux`, export the URL for the same database with the
SELECT-only viewer credentials, and run **without sudo**:

```bash
python -m kernelguard --config config.example.json serve
```

Open <http://127.0.0.1:5000> inside the VM. Refresh to see new data. For a browser on
the Windows host, use an SSH local port forward instead of publicly binding Flask.
Successful polling should show `Active`; stopping the collector makes it stale within 30 seconds.

Create an administrator first with the schema/setup database account:
`python -m kernelguard create-admin USERNAME`. Set KERNELGUARD_SECRET_KEY to a random
secret of at least 32 characters in the web terminal, as described in OPERATIONS.md.
The viewer's two INSERT grants permit reviews/enrollment; it cannot edit event evidence.

In terminal C, use the collector database account and poll inventory:

```bash
sudo --preserve-env=KERNELGUARD_DB_URL "$PWD/.venv-linux/bin/python" -m kernelguard inventory
```

Inventory uses pwd, /proc, psutil and pyudev. Elevated access helps obtain complete
process metadata; keep the web process unprivileged. The inventory and audit loops
release the writer lock between polls and retry contention. Both persist source
failures visibly; neither substitutes an empty snapshot for a failed USB scan.

Install the additional execution rule for the privileged-command policy:

```bash
sudo install -m 640 linux/privileged-execution.rules /etc/audit/rules.d/kernelguard-execution.rules
sudo augenrules --load
sudo auditctl -l
```

This audits native x86_64 execve/execveat with effective UID 0 from login AUID >= 1000.
The application stores executable and identity metadata, not raw command arguments.
The underlying audit log itself may contain arguments. See ACCEPTANCE.md for harmless
privilege, bulk and USB demonstrations, including physical USB passthrough to a VM.

## 5. Real protected-file event

As a regular logged-in lab user:

```bash
cat /srv/kernelguard/protected/demo.txt
sudo ausearch -k kernelguard_protected --start recent -i
```

Refresh the dashboard: a `file_access` record should appear. To reproduce an after-hours
alert during daytime, copy the example config to `config.lab.json` and set an allowed
one-hour interval that excludes the current local hour. Restart BOTH collector and
dashboard using `--config config.lab.json`, then repeat `cat`. Keep a screenshot of
the demo policy to explain this intentional setting. Do not change the machine clock.
An allowed-hours read should be stored without an alert. Some commands produce multiple
watched syscalls, so real event counts need not equal the number of shell commands.

## 6. Real failed-login events

Create a dedicated test account, then use interactive SSH against localhost:

```bash
sudo adduser kgtest
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no kgtest@localhost
```

Enter an incorrect test password. Reconnect as needed for five failures within five
minutes. Inspect `sudo ausearch -m USER_AUTH --start recent -i` to confirm the host
emits failed authentication records from SSH. Password authentication and PAM must
already be enabled for this controlled test; do not weaken unrelated host policies.
If password authentication is disabled, use the VM console login with the test account.
Some lockout policies prevent five attempts: lower `login_threshold` in the lab config
and state the configured threshold during the demonstration.

Expected: one threshold alert with links to at least the configured number of distinct
events. Further failures form a new episode only after enough unused evidence accumulates.
Never perform this test against external accounts or hosts.

## 7. Acceptance checklist

- [ ] MySQL schema created; SQL analysis queries execute.
- [ ] Real file event stored with original UID, effective UID, path and timestamp.
- [ ] Outside-hours access produces an alert with supporting evidence.
- [ ] Allowed-hours access produces an event without that alert.
- [ ] Login threshold produces a grouped alert with the expected evidence.
- [ ] Stop/restart collector: no duplicates from previously processed events.
- [ ] Dashboard reports stale collection after stopping the collector.
- [ ] Take screenshots of real events, alert evidence, MySQL rows and configured policy.

## Checkpoint recovery

If audit files disappear before collection, the lost evidence cannot be reconstructed.
Stop the collector, preserve/export the remaining audit logs, and record the coverage gap.
After reviewing the error, a lab administrator can remove only this host's checkpoint:

The current checkpoint key is `audit:` followed by SHA-256 of `host_id:boot_id`.
List checkpoint names and identify the exact host/boot key before any manual change.
Older releases used `audit:HOST`; those old entries are retained for reference.

Restarting will scan the current boot again, and the unique source IDs prevent duplicates
for already stored events. Archived raw records can be imported separately with
`python -m kernelguard import-audit exported.audit`. Keep `host_id` stable and use raw,
not interpreted (`-i`), input. Use only one collector/import process at a time.
