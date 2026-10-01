"""Regenerate reproducible synthetic Linux Audit input. No live host actions."""
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

def stamp(hour, minute=0):
    return int(datetime(2026, 9, 8, hour, minute, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp())

lines = []
for i in range(5):
    lines.append(f'''type=USER_AUTH msg=audit({stamp(14, i)}.100:{100+i}): pid=2300 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct="testuser" exe="/usr/sbin/sshd" hostname=? addr=127.0.0.1 terminal=ssh res=failed' ''')
for serial, hour, path, success in [
    (200, 10, "/srv/kernelguard/protected/budget.txt", "yes"),
    (201, 22, "/srv/kernelguard/protected/budget.txt", "yes"),
    (202, 22, "/srv/kernelguard/protected/notes.txt", "no"),
    (203, 11, "/srv/kernelguard/protected/notes.txt", "yes"),
]:
    identity = f"msg=audit({stamp(hour)}.200:{serial}):"
    lines += [f'type=SYSCALL {identity} arch=c000003e syscall=257 success={success} exit=3 ppid=2000 pid=2400 auid=1001 uid=1001 euid=1001 ses=4 exe="/usr/bin/cat" key="kernelguard_protected"',
              f'type=CWD {identity} cwd="/home/testuser"',
              f'type=PATH {identity} item=0 name="{path}" inode=123 dev=08:01 mode=0100644 nametype=NORMAL',
              f'type=EOE {identity}']
Path("fixtures").mkdir(exist_ok=True)
Path("fixtures/demo.audit").write_text("\n".join(lines) + "\n", encoding="utf-8")
