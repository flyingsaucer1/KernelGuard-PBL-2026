# MySQL 8.4 Docker deployment on the Kali host

On 2026-10-02, KernelGuard was started against the official `mysql:8.4` image
(server version 8.4.11) in a separate deployment alongside the existing MariaDB
deployment. The MySQL image and Docker Engine were installed using Kali's
`docker.io` package. The MySQL container is `kernelguard-mysql84`, with a named
volume `kernelguard-mysql84-data` and a localhost-only database port, `3307`.
The application database is `kernelguard84`.

The MySQL-backed dashboard is <http://127.0.0.1:5001>. It uses the `admin`
account. Its password and database credentials are not stored in this repository.
Database credentials and the dashboard session secret are root-owned files under
`/etc/kernelguard/mysql84/`. The web process has a separate database account
with SELECT access plus INSERT access for reviews and device decisions.

The three boot-enabled systemd units are:

```text
kernelguard-mysql84-web.service
kernelguard-mysql84-audit.service
kernelguard-mysql84-inventory.service
```

They run from `/home/kali/Desktop/KernalGuard` and use its `.venv-linux` virtual
environment. To check the deployment:

```bash
sudo docker ps --filter name=kernelguard-mysql84
sudo docker exec kernelguard-mysql84 mysql --defaults-extra-file=/run/secrets/root-client.cnf -N -e 'SELECT VERSION();'
sudo systemctl status kernelguard-mysql84-web.service kernelguard-mysql84-audit.service kernelguard-mysql84-inventory.service
curl -I http://127.0.0.1:5001/
```

The dashboard redirects unauthenticated requests to `/login`. The original
MariaDB-backed dashboard remains at <http://127.0.0.1:5000>. On 2026-10-02,
the new admin login, overview and inventory pages were verified. The audit and
inventory services ingested live host data, and `tests/test_mysql.py` passed
against a disposable MySQL 8.4 database. That test database was removed after
the test.

To restart the MySQL-backed application after Docker starts:

```bash
sudo systemctl restart kernelguard-mysql84-web.service kernelguard-mysql84-audit.service kernelguard-mysql84-inventory.service
```

Keep the database volume if the container is recreated; it holds the live data.
The application schema is created by `python -m kernelguard init-db`. MySQL's
entrypoint creates the database and collector account only for a fresh data
volume. The services do not install or update the application source copy.
