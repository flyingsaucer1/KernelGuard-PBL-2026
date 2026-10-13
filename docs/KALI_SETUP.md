# Phase 2 on Kali: start-to-finish guide

This runs the Phase 2 Python app and Linux Audit collector on Kali, with **one MySQL database** in a local container. Kali's [`default-mysql-server` package](https://www.kali.org/tools/mysql-defaults/) currently installs MariaDB, so use the [official MySQL image](https://hub.docker.com/_/mysql/) for a MySQL demonstration. These instructions target an x86_64 Kali VM and still need to be verified on your machine.

## 1. Get the project on Kali

Clone the Phase 2 repository. It contains the application, schema, audit rules,
tests, and setup instructions at one root:

```bash
git clone https://github.com/flyingsaucer1/KernelGuard-PBL-2026.git ~/KernalGuard-Phase2-PBL
```

Then on Kali:

```bash
cd ~/KernalGuard-Phase2-PBL
ls app.py requirements.txt linux/kernelguard.rules
uname -m
```

The supplied audit rule is for x86_64. Create a new Linux virtual environment below.

## 2. Install Kali packages

Follow [Kali's Docker installation guide](https://www.kali.org/docs/containers/installing-docker-on-kali/) for `docker.io`. Install the project prerequisites:

```bash
sudo apt update
sudo apt install -y docker.io python3-venv auditd openssh-server
sudo systemctl enable --now docker auditd ssh
```

If Docker or auditd does not start, resolve that service error before continuing.

## 3. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The terminal prompt should show `(.venv)`. Run all project commands from this folder.

## 4. Set MySQL passwords

```bash
cp .env.mysql.example .env.mysql
chmod 600 .env.mysql
nano .env.mysql
```

Replace `CHOOSE_A_DIFFERENT_ROOT_PASSWORD` and `CHOOSE_A_LAB_PASSWORD` with two passwords you choose. For the simplest first setup, use long letters-and-numbers passwords; URL-encode special characters if you later use them in the application URL. `.env.mysql` is ignored by Git. Keep it out of screenshots.

## 5. Start the one MySQL database

```bash
sudo docker volume create kg-phase2-mysql-data
sudo docker run -d --name kg-phase2-mysql --restart unless-stopped \
  --env-file .env.mysql \
  -p 127.0.0.1:3307:3306 \
  -v kg-phase2-mysql-data:/var/lib/mysql \
  mysql:8.4 --character-set-server=utf8mb4 --collation-server=utf8mb4_bin
```

The first start downloads MySQL and initializes it. Check:

```bash
sudo docker ps
sudo docker logs kg-phase2-mysql
sudo docker exec -it kg-phase2-mysql mysql -u kg_phase2 -p \
  -D kernelguard_phase2 -e 'SELECT VERSION();'
```

Enter the `MYSQL_PASSWORD` from `.env.mysql` when prompted. The version result should identify MySQL. The container exposes port `3307` only on Kali's localhost, avoiding a conflict with a service on `3306`. The named volume keeps the same database across restarts.

## 6. Connect Phase 2 and create its tables

Use the same password as `MYSQL_PASSWORD`:

```bash
export KERNELGUARD_PHASE2_DB_URL='mysql+pymysql://kg_phase2:YOUR_LAB_PASSWORD@127.0.0.1:3307/kernelguard_phase2?charset=utf8mb4'
python app.py init-db
```

The output should say `Phase 2 schema ready (mysql).` This creates eight tables. If it cannot connect, check `sudo docker ps`, the password, and port `3307`. The fixture importer, collector, and dashboard must all use this exact URL.

## 7. Choose a demo, then start the dashboard

For a repeatable synthetic demo, run:

```bash
python app.py demo
python app.py serve
```

The fixture creates **9 demo events, 2 alerts, and 6 evidence links**. For a live-only demonstration, skip `demo` and run `python app.py serve`. Open <http://127.0.0.1:5002/> in Kali's browser. Leave the dashboard terminal running.

## 8. Enable live protected-file auditing

In a second Kali terminal, from the project folder:

```bash
sudo mkdir -p /srv/kernelguard/protected
printf 'PBL test data only\n' | sudo tee /srv/kernelguard/protected/demo.txt
sudo chmod 755 /srv/kernelguard/protected
sudo chmod 644 /srv/kernelguard/protected/demo.txt
sudo install -m 640 linux/kernelguard.rules /etc/audit/rules.d/kernelguard.rules
sudo augenrules --load
sudo auditctl -l
```

Confirm `kernelguard_protected`, `kernelguard_file_access`, and `kernelguard_process_exec` appear in the rule list. The folder must exist before loading the rule. The path must match `config.example.json`. File-open rules cover `/home/kali`, `/run/media/kali/Acer`, `/media`, and `/mnt`; the process rules cover launches from logged-in Kali user sessions. Background services with an unset login UID are excluded. Expect more audit and database records during normal use.

## 9. Start the live collector

In that second terminal, activate its Python environment and export the **same** MySQL URL from step 6. Then run:

```bash
source .venv/bin/activate
export KERNELGUARD_PHASE2_DB_URL='mysql+pymysql://kg_phase2:YOUR_LAB_PASSWORD@127.0.0.1:3307/kernelguard_phase2?charset=utf8mb4'
sudo --preserve-env=KERNELGUARD_PHASE2_DB_URL "$PWD/.venv/bin/python" app.py collect --config config.example.json
```

The collector needs audit-log access, so only it uses `sudo`. The dashboard remains unprivileged. If your sudo policy blocks preserving the variable, configure approved audit-log access or ask your lab administrator to permit that environment variable.

## 10. Verify real events and DBMS rows

In a third terminal as a regular lab user:

```bash
cat /srv/kernelguard/protected/demo.txt
sudo ausearch -k kernelguard_protected --start recent -i
```

Refresh the dashboard. The new event should show `origin=live`; collector status should show `Active` after a recent poll. Inspect the same MySQL database:

```bash
sudo docker exec -it kg-phase2-mysql mysql -u kg_phase2 -p \
  -D kernelguard_phase2
```

In the MySQL prompt:

```sql
SHOW TABLES;
SELECT origin, kind, COUNT(*) AS total FROM events GROUP BY origin, kind;
SELECT id, rule, score, reason FROM alerts;
SELECT alert_id, event_id FROM alert_events;
```

An after-hours alert appears only when a successful access is outside the configured `09:00`–`18:00` window in `Asia/Kolkata`. For a daytime class demo, copy `config.example.json` to `config.lab.json`, adjust the allowed hours to exclude the current hour, and restart **both** collector and dashboard with `--config config.lab.json`. Do not change the system clock. The failed-login rule requires five failed authentications for one controlled local account within five minutes, subject to your lab's lockout policy.

## Stop and restart

Press `Ctrl+C` in the collector and dashboard terminals. The MySQL data persists in the Docker volume. To restart MySQL later, use `sudo docker start kg-phase2-mysql`, then start the Python dashboard and collector again with the same URL.
