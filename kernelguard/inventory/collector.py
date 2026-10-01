"""Read Linux metadata with psutil, pwd, procfs and pyudev. No command arguments."""
import sys
import time
from pathlib import Path
import psutil
from .models import Snapshot, User, Process, Device


def audit_id(path):
    value = path.read_text().strip()
    return None if value in ("4294967295", "-1") else value


def collect_snapshot(host):
    if sys.platform != "linux":
        raise RuntimeError("Live inventory needs Linux; use the synthetic demo on Windows")
    import pwd
    import pyudev
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    boot = boot_path.read_text().strip()
    users = [User(uid=str(u.pw_uid), username=u.pw_name) for u in pwd.getpwall()]
    rows, skipped = [], 0
    psutil.process_iter.cache_clear()
    for process in psutil.process_iter():
        try:
            with process.oneshot():
                credentials = process.uids()
                row = Process(pid=process.pid, ppid=process.ppid(),
                    started=f"{process.create_time():.6f}", uid=str(credentials.real),
                    effective_uid=str(credentials.effective), executable=process.exe() or None,
                    login_uid=audit_id(Path(f"/proc/{process.pid}/loginuid")),
                    session=audit_id(Path(f"/proc/{process.pid}/sessionid")))
            if process.is_running():
                rows.append(row)
            else:
                skipped += 1
        except (psutil.Error, OSError):
            skipped += 1
    devices = []
    for device in pyudev.Context().list_devices(subsystem="usb", DEVTYPE="usb_device"):
        # Root hubs are controllers, not enrollment candidates.
        if device.sys_name.startswith("usb"):
            continue
        def attr(name):
            value = device.attributes.get(name)
            return value.decode("utf-8", errors="replace").strip() if value else None
        vendor, product = attr("idVendor"), attr("idProduct")
        if not vendor or not product:
            raise RuntimeError("USB enumeration was incomplete; refusing removal inference")
        devices.append(Device(vendor=vendor.lower(), product=product.lower(), serial=attr("serial"),
            port=device.device_path, label=(attr("product") or "USB device")[:256]))
    if boot_path.read_text().strip() != boot:
        raise RuntimeError("Boot changed during inventory; retry the snapshot")
    return Snapshot(host=host, origin="live", boot_id=boot, timestamp=int(time.time()),
        users=users, processes=rows, devices=devices, processes_complete=skipped == 0,
        warnings=[f"{skipped} processes unavailable or exited during enumeration"] if skipped else [])
