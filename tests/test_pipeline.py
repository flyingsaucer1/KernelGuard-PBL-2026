from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from types import SimpleNamespace

import pytest
from sqlalchemy import select, func
from kernelguard.core import (database, metadata, settings, ingest, events, alerts,
                              alert_events, digest, checkpoint_get)
from kernelguard.parser import parse_audit
from kernelguard.web import create_app
from kernelguard.__main__ import collect_once


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr("kernelguard.__main__.current_boot", lambda: None)
    db = database("sqlite://")
    metadata.create_all(db)
    yield db
    db.dispose()


def record(i, stamp=1000, kind="login_failure", **extra):
    return dict(source_id=digest(str(i)), host="lab", timestamp=stamp, kind=kind,
                account="testuser", outcome="failure", origin="demo", **extra)


def count(conn, table):
    return conn.execute(select(func.count()).select_from(table)).scalar()


# START Ankit: check baseline evidence and the original detection rules.
def test_fixture_end_to_end_and_replay(engine):
    records = list(parse_audit(Path("fixtures/demo.audit").read_text(), "lab", "demo"))
    assert len(records) == 9
    with engine.begin() as conn:
        for r in records:
            ingest(conn, r, settings())
        assert count(conn, events) == 9
        assert count(conn, alerts) == 2
        assert count(conn, alert_events) == 6
        assert not any(ingest(conn, r, settings()) for r in records)
        assert count(conn, alerts) == 2


@pytest.mark.parametrize("timestamps,expected", [
    ([1000, 1010, 1020, 1030], 0),
    ([1000, 1010, 1020, 1030, 1300], 1),
    ([1000, 1010, 1020, 1030, 1301], 0),
    ([1000, 1060, 1120, 1180, 1240, 1250], 1),
    ([1240, 1180, 1120, 1060, 1000], 1),
])
def test_login_window(engine, timestamps, expected):
    with engine.begin() as conn:
        for i, t in enumerate(timestamps):
            ingest(conn, record(i, t), settings())
        assert count(conn, alerts) == expected


def test_accounts_hosts_and_demo_do_not_mix(engine):
    with engine.begin() as conn:
        for i in range(4):
            ingest(conn, record(i), settings())
        for i, key, value in [(4, "account", "other"), (5, "host", "other"), (6, "origin", "live")]:
            r = record(i)
            r[key] = value
            ingest(conn, r, settings())
        assert count(conn, alerts) == 0


@pytest.mark.parametrize("hour,path,outcome,expected", [
    (8, "/srv/kernelguard/protected/demo.txt", "success", 1),
    (9, "/srv/kernelguard/protected/demo.txt", "success", 0),
    (17, "/srv/kernelguard/protected/demo.txt", "success", 0),
    (18, "/srv/kernelguard/protected/demo.txt", "success", 1),
    (22, "/srv/kernelguard/protected-other/demo.txt", "success", 0),
    (22, "/srv/kernelguard/protected/demo.txt", "failure", 0),
])
def test_file_rule_boundaries(engine, hour, path, outcome, expected):
    stamp = int(datetime(2026, 9, 8, hour, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp())
    r = record(1, stamp, "file_access", resource=path)
    r["outcome"] = outcome
    with engine.begin() as conn:
        ingest(conn, r, settings())
        assert count(conn, alerts) == expected


def test_overnight_hours(engine):
    cfg = settings()
    cfg.update(allowed_start_hour=22, allowed_end_hour=6)
    with engine.begin() as conn:
        for hour in (23, 3, 6):
            stamp = int(datetime(2026, 9, 8, hour, tzinfo=ZoneInfo("Asia/Kolkata")).timestamp())
            r = record(hour, stamp, "file_access", resource=cfg["protected_path"] + "/a")
            r["outcome"] = "success"
            ingest(conn, r, cfg)
        assert count(conn, alerts) == 1
# END Ankit: login and protected-file policy checks.


# START Arshpreet Singh: check Linux Audit parsing and identity handling.
def test_multiline_relative_hex_and_identity():
    raw = '''type=SYSCALL msg=audit(1000.123:1): success=yes auid=1001 uid=0 euid=0 ses=3 pid=9 exe="/usr/bin/cat" key="kernelguard_protected"
type=CWD msg=audit(1000.123:1): cwd="/srv/kernelguard/protected"
type=PATH msg=audit(1000.123:1): name=6120622E747874 nametype=NORMAL
type=PATH msg=audit(1000.123:1): name=6120622E747874 nametype=NORMAL
type=PROCTITLE msg=audit(1000.123:1): proctitle=SECRET
type=PATH msg=audit(1000.123:1): name="6162" nametype=NORMAL
'''
    rows = list(parse_audit(raw, "lab"))
    assert len(rows) == 2
    assert rows[0]["resource"] == "/srv/kernelguard/protected/a b.txt"
    assert rows[1]["resource"].endswith("/6162")
    assert rows[0]["account"] == "uid:1001"
    assert rows[0]["effective_uid"] == "0"
    assert "SECRET" not in str(rows)


def test_only_login_authentication_is_counted():
    raw = '''type=USER_AUTH msg=audit(1000.123:1): pid=1 uid=0 msg='op=PAM:authentication acct="testuser" exe="/usr/sbin/sshd" res=failed'
type=USER_LOGIN msg=audit(1000.123:2): pid=1 uid=0 msg='acct="testuser" exe="/usr/sbin/sshd" res=failed'
type=USER_AUTH msg=audit(1000.123:3): pid=2 uid=0 msg='acct="testuser" exe="/usr/bin/sudo" res=failed'
malformed line
'''
    rows = list(parse_audit(raw, "lab"))
    assert len(rows) == 1
    assert rows[0]["account"] == "testuser"
# END Arshpreet Singh: audit-record parsing checks.


# START Mohd Ahmed Khan: verify transaction rollback preserves database state.
def test_transaction_rollback(engine):
    with pytest.raises(RuntimeError):
        with engine.begin() as conn:
            for i in range(5):
                ingest(conn, record(i), settings())
            raise RuntimeError("simulated database failure")
    with engine.connect() as conn:
        assert count(conn, events) == count(conn, alerts) == 0
# END Mohd Ahmed Khan: persistence rollback check.


# START Mohd Shoaib: check dashboard evidence, filters, and escaping.
def test_dashboard_evidence_filters_and_escaping(engine):
    with engine.begin() as conn:
        for i in range(5):
            r = record(i)
            r["account"] = '<script>alert(1)</script>'
            ingest(conn, r, settings())
    client = create_app(engine, settings()).test_client()
    home = client.get("/")
    assert home.status_code == 200
    assert b"Not live" in home.data
    assert b"<script>" not in home.data
    assert b"&lt;script&gt;" in home.data
    assert b"No matching events" in client.get("/?kind=file_access").data
    assert client.get("/alerts/1").status_code == 200
    assert client.get("/alerts/999").status_code == 404
# END Mohd Shoaib: dashboard response checks.


# START Arshpreet Singh: check collector checkpoints and audit failures.
def test_collector_checkpoint_commit_and_resume(engine, monkeypatch):
    calls = []
    def run(command, **kwargs):
        cursor = Path(command[command.index("--checkpoint") + 1])
        calls.append(cursor.read_text() if cursor.exists() else None)
        cursor.write_text("cursor-value")
        return SimpleNamespace(returncode=0, stdout=Path("fixtures/demo.audit").read_text(), stderr="")
    monkeypatch.setattr("kernelguard.__main__.subprocess.run", run)
    collect_once(engine, settings())
    collect_once(engine, settings())
    assert calls == [None, "cursor-value"]
    with engine.connect() as conn:
        assert count(conn, events) == 9
        assert checkpoint_get(conn, "collector_health")


def test_collector_error_does_not_advance(engine, monkeypatch):
    monkeypatch.setattr("kernelguard.__main__.subprocess.run", lambda *a, **kw:
        SimpleNamespace(returncode=1, stdout="", stderr="Error opening audit log: Permission denied"))
    with pytest.raises(RuntimeError):
        collect_once(engine, settings())
    with engine.connect() as conn:
        assert checkpoint_get(conn, "collector_health") is None
# END Arshpreet Singh: collector recovery checks.
