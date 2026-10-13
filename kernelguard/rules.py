"""Phase 2 detection rules, evaluated against stored event evidence."""

import posixpath
from collections import deque
from datetime import datetime
from pathlib import PurePosixPath
from zoneinfo import ZoneInfo

from sqlalchemy import select

from .core import add_alert, alert_events, alerts, events, save_policy


def evaluate_rules(conn, record, event_id, cfg):
    if record["kind"] == "login_failure":
        detect_login_episode(conn, record, cfg)
    elif record["kind"] == "file_access" and record["outcome"] == "success":
        detect_protected_access(conn, record, event_id, cfg)


# Ankit's Phase 2 policies: keep the existing alert names, scores and evidence rules.
def detect_login_episode(conn, incoming, cfg):
    """Reconsider later windows when an audit event arrives out of order.

    One ordered read supplies all candidate windows. A time bucket is added in full
    before it is evaluated, so records with the same timestamp behave as in SQL's
    inclusive timestamp window.
    """
    period = cfg["login_window_seconds"]
    earliest = incoming["timestamp"] - period
    latest = incoming["timestamp"] + period
    scope = (events.c.kind == "login_failure", events.c.host == incoming["host"],
             events.c.account == incoming["account"], events.c.origin == incoming["origin"])
    rows = conn.execute(select(events.c.id, events.c.timestamp).where(
        *scope, events.c.timestamp >= earliest, events.c.timestamp <= latest
    ).order_by(events.c.timestamp, events.c.id)).mappings().all()
    if not rows:
        return
    ids = [row["id"] for row in rows]
    assigned = set(conn.execute(select(alert_events.c.event_id).join(alerts).where(
        alerts.c.rule == "Repeated login failures", alert_events.c.event_id.in_(ids)
    )).scalars())

    window = deque()
    offset = 0
    while offset < len(rows):
        timestamp = rows[offset]["timestamp"]
        bucket = []
        while offset < len(rows) and rows[offset]["timestamp"] == timestamp:
            bucket.append(rows[offset])
            offset += 1
        window.extend(bucket)
        while window and window[0]["timestamp"] < timestamp - period:
            window.popleft()
        if timestamp < incoming["timestamp"]:
            continue
        for _ in bucket:
            evidence = [row["id"] for row in window if row["id"] not in assigned]
            if len(evidence) < cfg["login_threshold"]:
                continue
            policy = save_policy(conn, "login_failures", dict(
                threshold=cfg["login_threshold"], window_seconds=period,
                severity=60, evidence_grouping="disjoint episodes"))
            add_alert(conn, "Repeated login failures",
                {"timestamp": timestamp, "account": incoming["account"]}, evidence, 60,
                f"{len(evidence)} failed authentications for {incoming['account']} within "
                f"{period} seconds on {incoming['host']}.",
                "login:" + ":".join(map(str, evidence)), policy)
            assigned.update(evidence)


def detect_protected_access(conn, record, event_id, cfg):
    path = PurePosixPath(posixpath.normpath(record["resource"] or "/"))
    root = PurePosixPath(cfg["protected_path"])
    if path != root and root not in path.parents:
        return
    hour = datetime.fromtimestamp(record["timestamp"], ZoneInfo(cfg["timezone"])).hour
    start, end = cfg["allowed_start_hour"], cfg["allowed_end_hour"]
    allowed = start <= hour < end if start < end else hour >= start or hour < end
    if allowed:
        return
    policy = save_policy(conn, "protected_access", dict(
        protected_path=str(root), timezone=cfg["timezone"],
        allowed_start_hour=start, allowed_end_hour=end, severity=70))
    add_alert(conn, "After-hours protected access", record, [event_id], 70,
        f"Successful access to {path} outside {start:02}:00–{end:02}:00 "
        f"({cfg['timezone']}) on {record['host']}.", "file:" + record["source_id"], policy)
