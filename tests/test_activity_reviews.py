"""Activity rule boundaries, schema upgrade, administrator access and review integrity."""
import re
from pathlib import Path
from sqlalchemy import select, func
import pytest
from kernelguard.core import (database, metadata, settings, ingest, alerts, events,
    alert_events, administrators, alert_reviews, digest)
from kernelguard.parser import parse_audit
from kernelguard.demo import activity_audit
from kernelguard.auth import create_administrator
from kernelguard.web import create_app
from kernelguard.reviews import review_alert, ReviewConflict


@pytest.fixture
def engine():
    db = database("sqlite://")
    metadata.create_all(db)
    yield db
    db.dispose()


def demo_records():
    return list(parse_audit(Path("fixtures/demo.audit").read_text() + "\n" + activity_audit(), "lab", "demo"))


def count(conn, table):
    return conn.execute(select(func.count()).select_from(table)).scalar()


def seed(conn):
    for row in demo_records():
        ingest(conn, row, settings())


# START Ankit: check privileged-command and bulk-file detection rules.
def test_activity_end_to_end_replay_and_policy_links(engine):
    with engine.begin() as conn:
        seed(conn)
        assert count(conn, events) == 20
        assert count(conn, alerts) == 4
        assert count(conn, alert_events) == 17
        seed(conn)
        assert count(conn, events) == 20 and count(conn, alerts) == 4
        rules = conn.execute(select(alerts.c.rule)).scalars().all()
        assert "Sensitive privileged command" in rules
        assert "Bulk protected-file activity" in rules


@pytest.mark.parametrize("change", [
    {"effective_uid": "1001"}, {"outcome": "failure"}, {"uid": None},
    {"uid": "0"}, {"executable": "/usr/bin/cat"},
])
def test_privileged_rule_ignores_unmatched_activity(engine, change):
    row = list(parse_audit(activity_audit(), "lab", "demo"))[-1]
    row.update(change)
    with engine.begin() as conn:
        ingest(conn, row, settings())
        assert count(conn, alerts) == 0


def test_privileged_parser_excludes_arguments_and_unsupported_architecture():
    raw = activity_audit() + '\ntype=EXECVE msg=audit(1789014630.100:400): argc=2 a0="useradd" a1="SECRET"\n'
    parsed = list(parse_audit(raw, "lab", "demo"))
    assert "SECRET" not in str(parsed)
    assert parsed[-1]["kind"] == "privileged_exec"
    assert parsed[-1]["_audit"]["login_uid"] == "1001"
    assert parsed[-1]["_audit"]["effective_uid"] == "0"
    assert not any(r["kind"] == "privileged_exec" for r in
                   parse_audit(raw.replace("arch=c000003e", "arch=40000003"), "lab"))


@pytest.mark.parametrize("span,expected", [(60, 1), (61, 0)])
def test_bulk_inclusive_window_and_late_arrival(engine, span, expected):
    rows = list(parse_audit(activity_audit(), "lab", "demo"))[:3]
    rows[-1]["timestamp"] = rows[0]["timestamp"] + span
    cfg = settings()
    cfg["bulk_file_threshold"] = 3
    with engine.begin() as conn:
        for row in reversed(rows):
            ingest(conn, row, cfg)
        assert count(conn, alerts) == expected


@pytest.mark.parametrize("change", [
    {"host": "other"}, {"account": "uid:1002"}, {"origin": "live"}, {"session": "9"},
    {"resource": "/srv/kernelguard/protected-other/a"}, {"outcome": "failure"},
    {"session": None}, {"resource": "/srv/kernelguard/protected/report-0.txt"},
])
def test_bulk_requires_distinct_paths_and_same_scope(engine, change):
    rows = list(parse_audit(activity_audit(), "lab", "demo"))[:3]
    rows[-1].update(change)
    cfg = settings()
    cfg["bulk_file_threshold"] = 3
    with engine.begin() as conn:
        for row in rows:
            ingest(conn, row, cfg)
        assert count(conn, alerts) == 0
# END Ankit: activity-rule and evidence checks.


# START Mohd Shoaib: check authentication, CSRF, and review decisions.
def test_preview_cannot_write(engine):
    with engine.begin() as conn:
        seed(conn)
    client = create_app(engine, settings()).test_client()
    assert client.get("/").status_code == 200
    assert client.post("/alerts/1/review", data={"action": "acknowledge", "note": "test"}).status_code == 403
    with engine.connect() as conn:
        assert count(conn, alert_reviews) == 0


@pytest.fixture
def secured(engine):
    with engine.begin() as conn:
        create_administrator(conn, "reviewer", "a-test-password-123")
        seed(conn)
    app = create_app(engine, settings(), secret_key="test-only-secret-" * 4)
    app.config["TESTING"] = True
    return app.test_client()


def token(response):
    return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()


def sign_in(client):
    return client.post("/login", data={"csrf_token": token(client.get("/login")),
        "username": "reviewer", "password": "a-test-password-123"})


def test_authentication_csrf_review_reopen_and_logout(engine, secured):
    client = secured
    assert client.get("/").status_code == 302
    assert client.get("/alerts/1").status_code == 302
    assert client.post("/login", data={}).status_code == 400
    client.get("/login")
    assert client.post("/login", data={"csrf_token": "invalid-\u2603"}).status_code == 400
    assert sign_in(client).status_code == 302
    assert client.get("/").status_code == 200
    assert client.post("/alerts/1/review", data={}).status_code == 400
    body = {"csrf_token": token(client.get("/alerts/1")), "expected_id": "0",
            "action": "acknowledge", "note": "<script>Checked with owner</script>"}
    assert client.post("/alerts/1/review", data=body).status_code == 302
    assert client.post("/alerts/1/review", data=body).status_code == 409
    page = client.get("/alerts/1")
    assert b"Review status: Acknowledged" in page.data
    assert b"&lt;script&gt;" in page.data and b"<script>" not in page.data
    with engine.connect() as conn:
        review = conn.execute(select(alert_reviews)).mappings().one()
        assert review["administrator_id"] == 1
        assert count(conn, alerts) == 4 and count(conn, alert_events) == 17
    body.update(expected_id=str(review["id"]), action="reopen", note="Further investigation required")
    assert client.post("/alerts/1/review", data=body).status_code == 302
    assert b"Review status: Open" in client.get("/alerts/1").data
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", data={"csrf_token": body["csrf_token"]}).status_code == 302
    assert client.get("/").status_code == 302
    with engine.connect() as conn:
        assert count(conn, alert_reviews) == 2


def test_login_rejects_wrong_password_and_limits_attempts(secured):
    csrf = token(secured.get("/login"))
    body = dict(csrf_token=csrf, username="reviewer", password="wrong")
    for _ in range(5):
        assert secured.post("/login", data=body).status_code == 401
    assert secured.post("/login", data=body).status_code == 429
    assert secured.get("/").status_code == 302


def test_administrator_hash_and_fail_closed_without_secret(engine, monkeypatch):
    monkeypatch.delenv("KERNELGUARD_SECRET_KEY", raising=False)
    with engine.begin() as conn:
        create_administrator(conn, "reviewer", "a-test-password-123")
        stored = conn.execute(select(administrators.c.password_hash)).scalar_one()
        assert stored != "a-test-password-123" and stored.startswith("scrypt:")
        with pytest.raises(ValueError):
            create_administrator(conn, "reviewer", "a-test-password-123")
    with pytest.raises(ValueError, match="KERNELGUARD_SECRET_KEY"):
        create_app(engine, settings())


def test_review_transaction_rollback_and_invalid_transitions(engine):
    with engine.begin() as conn:
        create_administrator(conn, "reviewer", "a-test-password-123")
        seed(conn)
        with pytest.raises(ReviewConflict):
            review_alert(conn, 1, 1, "reopen", "Already open", 0)
        with pytest.raises(ValueError):
            review_alert(conn, 1, 1, "acknowledge", " ", 0)
    with pytest.raises(RuntimeError), engine.begin() as conn:
        review_alert(conn, 1, 1, "acknowledge", "Rollback test", 0)
        raise RuntimeError("simulated failure")
    with engine.connect() as conn:
        assert count(conn, alert_reviews) == 0
# END Mohd Shoaib: review workflow and access-control checks.


# START Mohd Ahmed Khan: check additive schema upgrade and retained evidence.
def test_additive_upgrade_keeps_existing_events(tmp_path):
    db = database("sqlite:///" + (tmp_path / "upgrade.db").as_posix())
    old_names = {"events", "alerts", "alert_events", "checkpoints", "audit_details",
                 "rule_policies", "alert_policies"}
    old_tables = [table for table in metadata.sorted_tables if table.name in old_names]
    metadata.create_all(db, tables=old_tables)
    with db.begin() as conn:
        old_record = dict(demo_records()[0])
        old_record.pop("_audit", None)
        conn.execute(events.insert().values(**old_record))
    metadata.create_all(db)
    metadata.create_all(db)
    with db.begin() as conn:
        seed(conn)
    with db.connect() as conn:
        assert count(conn, events) == 20 and count(conn, alerts) == 4
        assert count(conn, administrators) == count(conn, alert_reviews) == 0
    db.dispose()
# END Mohd Ahmed Khan: database upgrade check.
