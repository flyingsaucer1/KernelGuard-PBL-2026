"""Deterministic synthetic activity examples; never represented as live collection."""
from datetime import datetime
from zoneinfo import ZoneInfo


def activity_audit():
    stamp = int(datetime(2026, 9, 10, 10, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp())
    lines = []
    for index in range(10):
        marker = f"audit({stamp + index}.100:{300 + index})"
        lines.extend([
            f'type=SYSCALL msg={marker}: arch=c000003e syscall=257 success=yes exit=3 auid=1001 uid=1001 euid=1001 ses=8 pid=2800 exe="/usr/bin/cat" key="kernelguard_protected"',
            f'type=PATH msg={marker}: name="/srv/kernelguard/protected/report-{index}.txt" inode={400 + index} dev=08:01 nametype=NORMAL',
        ])
    lines.append(f'type=SYSCALL msg=audit({stamp + 30}.100:400): arch=c000003e syscall=59 success=yes exit=0 auid=1001 uid=0 euid=0 ses=8 pid=2900 exe="/usr/sbin/useradd" key="kernelguard_privileged"')
    return "\n".join(lines) + "\n"
