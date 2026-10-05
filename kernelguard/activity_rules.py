"""Privileged execution and bulk-file indicators based on observed metadata."""
from pathlib import PurePosixPath
from sqlalchemy import select
from .core import events, alerts, alert_events, event_context, save_policy, add_alert


# START Ankit: detect privileged execution and bulk protected-file activity.
def protected(path, root):
    candidate, directory = PurePosixPath(path or "/"), PurePosixPath(root)
    return candidate == directory or directory in candidate.parents


def evaluate(conn, record, eid, cfg, boot_id=None):
    if (record["kind"] == "privileged_exec" and record["outcome"] == "success"
            and record.get("effective_uid") == "0"
            and record.get("uid") not in (None, "0", "unknown")
            and record.get("executable") in cfg["privileged_executables"]):
        policy = save_policy(conn, "privileged_command", dict(
            executables=cfg["privileged_executables"], effective_uid="0", severity=75))
        add_alert(conn, "Sensitive privileged command", record, [eid], 75,
            f"{record['account']} executed {record['executable']} with effective UID 0 "
            f"on {record['host']}. Review whether this administration was authorized.",
            "privileged:" + record["source_id"], policy)
    if (record["kind"] != "file_access" or record["outcome"] != "success"
            or not record.get("session") or not record.get("uid")
            or not protected(record.get("resource"), cfg["protected_path"])):
        return
    group = (events.c.kind == "file_access", events.c.outcome == "success",
        events.c.host == record["host"], events.c.origin == record["origin"],
        events.c.account == record["account"], events.c.session == record["session"])
    seconds = cfg["bulk_window_seconds"]
    query = select(events).outerjoin(event_context).where(
        event_context.c.boot_id == boot_id if boot_id else event_context.c.boot_id.is_(None))
    endings = conn.execute(query.where(*group,
        events.c.timestamp >= record["timestamp"],
        events.c.timestamp <= record["timestamp"] + seconds)
        .order_by(events.c.timestamp, events.c.id)).mappings().all()
    for end in endings:
        window = conn.execute(query.where(*group,
            events.c.timestamp >= end["timestamp"] - seconds,
            events.c.timestamp <= end["timestamp"])
            .order_by(events.c.timestamp, events.c.id)).mappings().all()
        used = set(conn.execute(select(alert_events.c.event_id).join(alerts).where(
            alerts.c.rule == "Bulk protected-file activity",
            alert_events.c.event_id.in_([row["id"] for row in window]))).scalars())
        fresh = [row for row in window if row["id"] not in used
                 and protected(row["resource"], cfg["protected_path"])]
        distinct = len({row["resource"] for row in fresh})
        if distinct < cfg["bulk_file_threshold"]:
            continue
        evidence = [row["id"] for row in fresh]
        policy = save_policy(conn, "bulk_files", dict(threshold=cfg["bulk_file_threshold"],
            window_seconds=seconds, protected_path=cfg["protected_path"], severity=70,
            grouping="same host, origin, account and audit session; distinct paths"))
        add_alert(conn, "Bulk protected-file activity", end, evidence, 70,
            f"{record['account']} accessed {distinct} distinct protected paths within "
            f"{seconds} seconds on {record['host']}. This does not prove copying or exfiltration.",
            "bulk:" + ":".join(map(str, evidence)), policy)
# END Ankit: activity rules using shared alert and policy persistence.
