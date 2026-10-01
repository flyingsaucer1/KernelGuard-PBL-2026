# Optional Linux service setup

The templates in linux/services are deployment artifacts, not installed services.
They assume a reviewed copy of this project at /opt/kernelguard, a virtual environment
there, and an existing dedicated kernelguard user/group for the dashboard. Collectors
run elevated to read audit/procfs; the dashboard runs as the dedicated user.

Use MySQL for these separate-privilege services. A shared SQLite file created by root
with mode 0600 cannot be read by the web user; do not weaken permissions blindly.
Create /opt/kernelguard/data for runtime paths even when using MySQL.

Create /etc/kernelguard/collector.env and /etc/kernelguard/web.env with root-only
read permissions. Each contains a KERNELGUARD_DB_URL for the same database with its
appropriate role. The web file additionally contains KERNELGUARD_SECRET_KEY.
systemd reads the protected environment file before launching the unprivileged web
process. Do not place these files in the repository. Complete database initialization
and administrator creation first.

Review paths and settings, install the service files under /etc/systemd/system,
run systemctl daemon-reload, then enable/start the selected services. Inspect status
and journalctl output for each component. No installation command was run on the
Windows development host, and these service templates require Linux acceptance.

The web server listens only on loopback. Use an SSH tunnel to view it remotely.
Do not expose the lab database or dashboard directly to the Internet. Keep audit
and inventory health separate: a successful metadata poll does not establish that
auditd rules are producing the required events.

## Kali lab deployment

The 2026-10-01 Kali deployment runs from `/home/kali/Desktop/KernalGuard` and
uses MariaDB over a Unix socket. Its installed inventory unit is captured in
`linux/services/kernelguard-inventory-kali.service`; the `/opt/kernelguard`
templates above remain examples for a separate deployment. Review the absolute
paths and socket account before installing the Kali unit on another host.

The live dashboard has a systemd drop-in that loads
`/etc/kernelguard/web-secret.env`, owned by root with mode 0600. The secret and
administrator password are not stored in this repository. After changing a unit,
run `systemd-analyze verify`, `systemctl daemon-reload`, and restart that service;
then check `systemctl is-active` and its recent journal entries.
