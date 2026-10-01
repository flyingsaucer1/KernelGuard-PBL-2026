"""A snapshot, inventory changes and device evidence commit in one transaction."""
import json
import time
from sqlalchemy import select
from ..core import digest, events, ingest, add_alert, save_policy
from ..reviews import ReviewConflict
from .models import Snapshot
from .schema import snapshots, users, sessions, processes, devices, device_events, device_decisions


def key(*parts):
    return digest(json.dumps(parts, separators=(",", ":")))


def device_id(snapshot, device):
    return key(snapshot.host, snapshot.origin, device.vendor, device.product,
               "serial" if device.serial else "port", device.serial or device.port)


def save_row(conn, table, identity, values):
    old = conn.execute(select(table).where(table.c.id == identity)).mappings().first()
    if old:
        conn.execute(table.update().where(table.c.id == identity).values(**values))
    else:
        conn.execute(table.insert().values(id=identity, **values))
    return old


def latest_decision(conn, identity):
    return conn.execute(select(device_decisions).where(device_decisions.c.device_id == identity)
        .order_by(device_decisions.c.id.desc()).limit(1)).mappings().first()


def decide_device(conn, identity, admin_id, approved, note, expected_id):
    if not note.strip() or len(note.strip()) > 1000 or type(approved) is not bool:
        raise ValueError("A decision and a note of 1–1000 characters are required")
    if not conn.execute(select(devices.c.id).where(devices.c.id == identity)).scalar():
        raise LookupError("Device not found")
    previous = latest_decision(conn, identity)
    if (previous["id"] if previous else 0) != expected_id:
        raise ReviewConflict("Device enrollment changed; reload before deciding")
    if bool(previous and previous["approved"]) == approved:
        raise ReviewConflict("Device already has that enrollment status")
    conn.execute(device_decisions.insert().values(device_id=identity, administrator_id=admin_id,
        approved=approved, note=note.strip(), timestamp=int(time.time())))


def store_snapshot(conn, snapshot, cfg):
    if not isinstance(snapshot, Snapshot):
        snapshot = Snapshot.model_validate(snapshot)
    identity = digest(snapshot.model_dump_json())
    if conn.execute(select(snapshots.c.id).where(snapshots.c.id == identity)).scalar():
        return False
    scope = dict(host=snapshot.host, origin=snapshot.origin)
    latest = conn.execute(select(snapshots.c.timestamp).filter_by(**scope)
        .order_by(snapshots.c.timestamp.desc()).limit(1)).scalar()
    if latest is not None and snapshot.timestamp <= latest:
        raise ValueError("Snapshot must be newer than the last accepted observation")
    conn.execute(snapshots.insert().values(id=identity, **scope, boot_id=snapshot.boot_id,
        timestamp=snapshot.timestamp, processes_complete=snapshot.processes_complete,
        warnings_json=json.dumps(snapshot.warnings)))
    conn.execute(users.update().filter_by(**scope).values(present=False))
    user_keys = {}
    for user in snapshot.users:
        uid_key = key(*scope.values(), user.uid)
        user_keys[user.uid] = uid_key
        save_row(conn, users, uid_key, dict(**scope, uid=user.uid, username=user.username,
            last_seen=snapshot.timestamp, present=True))
    if snapshot.processes_complete:
        for table in (processes, sessions):
            conn.execute(table.update().filter_by(**scope).values(present=False))
    session_keys, session_actors = {}, {}
    for process in snapshot.processes:
        if process.session is None:
            continue
        if process.session in session_actors and session_actors[process.session] != process.login_uid:
            raise ValueError("Conflicting login identities for one audit session")
        session_actors[process.session] = process.login_uid
        sid = key(*scope.values(), snapshot.boot_id, process.session)
        session_keys[process.session] = sid
        old = conn.execute(select(sessions.c.first_seen).where(sessions.c.id == sid)).scalar()
        save_row(conn, sessions, sid, dict(**scope, boot_id=snapshot.boot_id,
            audit_session=process.session, user_id=user_keys.get(process.login_uid),
            first_seen=old if old is not None else snapshot.timestamp,
            last_seen=snapshot.timestamp, present=True))
    process_keys = {p.pid: key(*scope.values(), snapshot.boot_id, p.pid, p.started) for p in snapshot.processes}
    by_pid = {p.pid: p for p in snapshot.processes}
    for process in snapshot.processes:
        save_row(conn, processes, process_keys[process.pid], dict(**scope,
            boot_id=snapshot.boot_id, pid=process.pid, ppid=process.ppid, started=process.started,
            parent_id=None, session_id=session_keys.get(process.session),
            user_id=user_keys.get(process.uid), effective_uid=process.effective_uid,
            executable=process.executable, last_seen=snapshot.timestamp, present=True))
    # Insert all processes before parent foreign keys. Equal-time parents stay unknown.
    for process in snapshot.processes:
        parent = by_pid.get(process.ppid)
        if parent and float(parent.started) < float(process.started):
            conn.execute(processes.update().where(processes.c.id == process_keys[process.pid])
                .values(parent_id=process_keys[parent.pid]))
    previous_devices = {row["id"]: row for row in conn.execute(select(devices).filter_by(**scope))
                        .mappings().all()}
    present_ids = set()
    for device in snapshot.devices:
        did = device_id(snapshot, device)
        present_ids.add(did)
        previous = previous_devices.get(did)
        save_row(conn, devices, did, dict(**scope, **device.model_dump(),
            identity_basis="serial" if device.serial else "port", boot_id=snapshot.boot_id,
            first_seen=previous["first_seen"] if previous else snapshot.timestamp,
            last_seen=snapshot.timestamp, present=True))
        if not previous or not previous["present"] or previous["boot_id"] != snapshot.boot_id:
            record = device_record(snapshot, did, identity, "usb_seen", device.label)
            ingest(conn, record, cfg)
            eid = conn.execute(select(events.c.id).where(events.c.source_id == record["source_id"])).scalar_one()
            conn.execute(device_events.insert().values(event_id=eid, device_id=did, snapshot_id=identity))
            approval = latest_decision(conn, did)
            if not approval or not approval["approved"]:
                policy = save_policy(conn, "unknown_usb", dict(severity=65,
                    device_id=did, identity_basis="serial" if device.serial else "port",
                    enrollment_decision=approval["id"] if approval else None))
                add_alert(conn, "Unapproved USB device", record, [eid], 65,
                    f"USB device {device.label} first observed or reappeared on {snapshot.host} "
                    "without enrollment. No responsible user or data transfer is inferred.",
                    "usb:" + record["source_id"], policy)
    for did, previous in previous_devices.items():
        if previous["present"] and did not in present_ids:
            conn.execute(devices.update().where(devices.c.id == did).values(present=False))
            record = device_record(snapshot, did, identity, "usb_absent", previous["label"])
            ingest(conn, record, cfg)
            eid = conn.execute(select(events.c.id).where(events.c.source_id == record["source_id"])).scalar_one()
            conn.execute(device_events.insert().values(event_id=eid, device_id=did, snapshot_id=identity))
    return True


def device_record(snapshot, did, snapshot_id, kind, label):
    return dict(source_id=key(snapshot_id, did, kind), host=snapshot.host,
        timestamp=snapshot.timestamp, kind=kind, account="unattributed", uid=None,
        effective_uid=None, session=None, pid=None, executable=None, resource=label,
        outcome="observed", origin=snapshot.origin)
