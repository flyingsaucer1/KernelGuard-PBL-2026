"""Offline policy behavior checks using an isolated SQL database."""

from datetime import datetime, timezone

from sqlalchemy import create_engine, func, select

from kernelguard.core import alert_events, alerts, events, ingest, metadata
from kernelguard.config import settings


def store(records, cfg):
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    with engine.begin() as conn:
        for record in records:
            ingest(conn, record, cfg)
        found = conn.execute(select(alerts)).mappings().all()
        links = conn.scalar(select(func.count()).select_from(alert_events))
    engine.dispose()
    return found, links


def activity(source, timestamp, kind="login_failure", resource=None, outcome="failure"):
    return dict(source_id=source, host="lab", timestamp=timestamp, kind=kind,
        account="student", uid=None, effective_uid=None, session=None, pid=None,
        executable=None, resource=resource, outcome=outcome, origin="live")


def test_late_login_arrival_and_equal_timestamps_keep_complete_evidence():
    cfg = settings()
    cfg.update(login_threshold=3, login_window_seconds=5)
    found, links = store([activity("c", 103), activity("b", 100), activity("a", 100)], cfg)
    assert len(found) == 1
    assert found[0]["rule"] == "Repeated login failures"
    assert links == 3


def test_protected_path_boundary_and_allowed_hours():
    cfg = settings()
    cfg.update(protected_path="/data", timezone="UTC", allowed_start_hour=9,
               allowed_end_hour=18)
    night = int(datetime(2026, 10, 13, 20, tzinfo=timezone.utc).timestamp())
    day = int(datetime(2026, 10, 13, 10, tzinfo=timezone.utc).timestamp())
    found, links = store([
        activity("sibling", night, "file_access", "/data-other/report", "success"),
        activity("day", day, "file_access", "/data/report", "success"),
        activity("night", night, "file_access", "/data/report", "success"),
    ], cfg)
    assert [row["rule"] for row in found] == ["After-hours protected access"]
    assert links == 1
