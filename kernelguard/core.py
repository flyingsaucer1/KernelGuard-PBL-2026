"""Relational storage and the original two detection policies.

Event identity snapshots are separate from policy snapshots: changing tomorrow's
threshold must not change the explanation for yesterday's alert.
"""
import hashlib
import json
import posixpath
from datetime import datetime, timezone
from pathlib import PurePosixPath
from zoneinfo import ZoneInfo

from sqlalchemy import (Column, ForeignKey, Index, Integer, MetaData, String,
                        Table, Text, create_engine, select)
from sqlalchemy.engine import make_url
from .config import settings

# START Mohd Ahmed Khan: define the relational schema and MySQL storage helpers.
metadata = MetaData()
events = Table("events", metadata,
    Column("id", Integer, primary_key=True),
    Column("source_id", String(64), nullable=False, unique=True),
    Column("host", String(128), nullable=False),
    Column("timestamp", Integer, nullable=False),
    Column("kind", String(32), nullable=False),
    Column("account", String(128), nullable=False),
    Column("uid", String(32)), Column("effective_uid", String(32)),
    Column("session", String(64)), Column("pid", String(32)),
    Column("executable", Text), Column("resource", Text),
    Column("outcome", String(32), nullable=False),
    Column("origin", String(16), nullable=False),
    Index("ix_event_account_time", "host", "account", "timestamp"),
    Index("ix_event_kind_time", "kind", "timestamp"))
alerts = Table("alerts", metadata,
    Column("id", Integer, primary_key=True),
    Column("dedup_key", String(64), nullable=False, unique=True),
    Column("rule", String(48), nullable=False),
    Column("timestamp", Integer, nullable=False),
    Column("account", String(128), nullable=False),
    Column("score", Integer, nullable=False),
    Column("reason", Text, nullable=False))
alert_events = Table("alert_events", metadata,
    Column("alert_id", ForeignKey("alerts.id"), primary_key=True),
    Column("event_id", ForeignKey("events.id"), primary_key=True))
checkpoints = Table("checkpoints", metadata,
    Column("name", String(128), primary_key=True),
    Column("value", Text, nullable=False))
event_context = Table("event_context", metadata,
    Column("event_id", ForeignKey("events.id"), primary_key=True),
    Column("boot_id", String(64), nullable=False))
audit_details = Table("audit_details", metadata,
    Column("event_id", ForeignKey("events.id"), primary_key=True),
    Column("audit_timestamp", String(40), nullable=False),
    Column("audit_serial", String(32), nullable=False),
    Column("record_type", String(32), nullable=False),
    Column("login_uid", String(32)),
    Column("real_uid", String(32)),
    Column("effective_uid", String(32)),
    Column("session_id", String(64)),
    Column("syscall", String(32)),
    Column("architecture", String(32)),
    Column("inode", String(32)),
    Column("device", String(32)))
rule_policies = Table("rule_policies", metadata,
    Column("id", String(64), primary_key=True),
    Column("rule_code", String(48), nullable=False),
    Column("version", Integer, nullable=False),
    Column("parameters_json", Text, nullable=False))
alert_policies = Table("alert_policies", metadata,
    Column("alert_id", ForeignKey("alerts.id"), primary_key=True),
    Column("policy_id", ForeignKey("rule_policies.id"), nullable=False),
    Index("ix_alert_policy", "policy_id"))
# Preserve case-sensitive Linux account identity and transactional foreign keys
# regardless of the MySQL server's default collation/storage engine.
for table in metadata.tables.values():
    table.dialect_options["mysql"]["engine"] = "InnoDB"
    table.dialect_options["mysql"]["charset"] = "utf8mb4"
    table.dialect_options["mysql"]["collate"] = "utf8mb4_bin"

def database(url):
    parsed = make_url(url)
    if parsed.drivername != "mysql+pymysql" or not parsed.database:
        raise ValueError("Phase 2 requires a MySQL URL using mysql+pymysql")
    return create_engine(parsed, pool_pre_ping=True)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def utc_display(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%d %b %Y · %H:%M:%S UTC")


def checkpoint_get(conn, name):
    return conn.execute(select(checkpoints.c.value).where(checkpoints.c.name == name)).scalar()


def checkpoint_set(conn, name, value):
    if checkpoint_get(conn, name) is None:
        conn.execute(checkpoints.insert().values(name=name, value=value))
    else:
        conn.execute(checkpoints.update().where(checkpoints.c.name == name).values(value=value))


def save_policy(conn, rule_code, parameters):
    encoded = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
    policy_id = digest(f"{rule_code}:1:{encoded}")
    if conn.execute(select(rule_policies.c.id).where(rule_policies.c.id == policy_id)).scalar() is None:
        conn.execute(rule_policies.insert().values(id=policy_id, rule_code=rule_code,
            version=1, parameters_json=encoded))
    return policy_id


def add_alert(conn, rule, record, evidence, score, reason, key, policy_id):
    key = digest(key)
    if conn.execute(select(alerts.c.id).where(alerts.c.dedup_key == key)).scalar():
        return
    aid = conn.execute(alerts.insert().values(dedup_key=key, rule=rule,
        timestamp=record["timestamp"], account=record["account"], score=score,
        reason=reason)).inserted_primary_key[0]
    conn.execute(alert_events.insert(), [dict(alert_id=aid, event_id=eid) for eid in evidence])
    conn.execute(alert_policies.insert().values(alert_id=aid, policy_id=policy_id))
# END Mohd Ahmed Khan: schema, connection, checkpoints, and alert persistence.


def ingest(conn, record, cfg):
    """One writer; caller commits events, alerts and cursor in one transaction."""
    # START Mohd Ahmed Khan: validate, deduplicate, and store event evidence.
    record = dict(record)
    if record.get("kind") not in ("login_failure", "file_access"):
        raise ValueError("Phase 2 accepts login_failure and file_access events only")
    audit = record.pop("_audit", None)
    boot_id = record.pop("_boot", None)
    existing = conn.execute(select(events.c.id).where(events.c.source_id == record["source_id"])).scalar()
    if existing:
        # An explicit replay may enrich older rows with source-backed OS metadata.
        # Never invent the missing policy for a historical alert.
        if audit and conn.execute(select(audit_details.c.event_id).where(
                audit_details.c.event_id == existing)).scalar() is None:
            conn.execute(audit_details.insert().values(event_id=existing, **audit))
        return False
    eid = conn.execute(events.insert().values(**record)).inserted_primary_key[0]
    if boot_id:
        conn.execute(event_context.insert().values(event_id=eid, boot_id=boot_id))
    if audit:
        conn.execute(audit_details.insert().values(event_id=eid, **audit))
    # END Mohd Ahmed Khan: event and audit-detail persistence.

    # START Ankit: apply failed-login and after-hours protected-file rules.
    if record["kind"] == "login_failure":
        # Evaluate windows ending at this event AND later stored events: late arrivals
        # must not hide a threshold crossing. Greedily group disjoint alert episodes.
        group = (events.c.kind == "login_failure", events.c.host == record["host"],
                 events.c.account == record["account"], events.c.origin == record["origin"])
        candidates = conn.execute(select(events).where(*group,
            events.c.timestamp >= record["timestamp"],
            events.c.timestamp <= record["timestamp"] + cfg["login_window_seconds"])
            .order_by(events.c.timestamp, events.c.id)).mappings().all()
        for end in candidates:
            window = conn.execute(select(events.c.id).where(*group,
                events.c.timestamp >= end["timestamp"] - cfg["login_window_seconds"],
                events.c.timestamp <= end["timestamp"])
                .order_by(events.c.timestamp, events.c.id)).scalars().all()
            used = set(conn.execute(select(alert_events.c.event_id).join(alerts).where(
                alerts.c.rule == "Repeated login failures",
                alert_events.c.event_id.in_(window))).scalars())
            fresh = [i for i in window if i not in used]
            if len(fresh) >= cfg["login_threshold"]:
                policy = save_policy(conn, "login_failures", dict(
                    threshold=cfg["login_threshold"], window_seconds=cfg["login_window_seconds"],
                    severity=60, evidence_grouping="disjoint episodes"))
                add_alert(conn, "Repeated login failures", end, fresh, 60,
                    f"{len(fresh)} failed authentications for {record['account']} within "
                    f"{cfg['login_window_seconds']} seconds on {record['host']}.",
                    "login:" + ":".join(map(str, fresh)), policy)
    if record["kind"] == "file_access" and record["outcome"] == "success":
        path = PurePosixPath(posixpath.normpath(record["resource"] or "/"))
        root = PurePosixPath(cfg["protected_path"])
        hour = datetime.fromtimestamp(record["timestamp"], ZoneInfo(cfg["timezone"])).hour
        start, end = cfg["allowed_start_hour"], cfg["allowed_end_hour"]
        allowed = start <= hour < end if start < end else hour >= start or hour < end
        if (path == root or root in path.parents) and not allowed:
            policy = save_policy(conn, "protected_access", dict(
                protected_path=str(root), timezone=cfg["timezone"],
                allowed_start_hour=start, allowed_end_hour=end, severity=70))
            add_alert(conn, "After-hours protected access", record, [eid], 70,
                f"Successful access to {path} outside {start:02}:00–{end:02}:00 "
                f"({cfg['timezone']}) on {record['host']}.", "file:" + record["source_id"], policy)
    # END Ankit: Phase 2 detection rules and their alert evidence.
    return True
