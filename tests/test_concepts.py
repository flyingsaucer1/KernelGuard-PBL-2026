"""Regression checks for the OS/DBMS review, beyond the original demo path."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from kernelguard.core import (metadata, database, settings, ingest, events, alerts,
    audit_details, alert_events, alert_policies, rule_policies, checkpoint_set, checkpoint_get)
from kernelguard.locking import writer_lock
from kernelguard.parser import parse_audit
from kernelguard.__main__ import collect_once
from tests.test_pipeline import record


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr("kernelguard.__main__.current_boot", lambda: None)
    db = database("sqlite://")
    metadata.create_all(db)
    yield db
    db.dispose()


def test_login_uid_is_distinct_from_real_and_effective_uid(engine):
    raw = '''type=SYSCALL msg=audit(1000.100:42): arch=c000003e syscall=257 success=yes auid=1001 uid=0 euid=0 ses=2 pid=19 key="kernelguard_protected"
type=PATH msg=audit(1000.100:42): name="/srv/kernelguard/protected/a" inode=27 dev=08:01 nametype=NORMAL'''
    r = next(parse_audit(raw, "lab"))
    with engine.begin() as conn:
        ingest(conn, r, settings())
        observed = conn.execute(select(audit_details)).mappings().one()
        assert observed["login_uid"] == "1001"
        assert observed["real_uid"] == observed["effective_uid"] == "0"
        assert observed["syscall"] == "257"
        assert observed["architecture"] == "c000003e"
        assert observed["inode"] == "27"


def test_authentication_does_not_invent_effective_uid():
    raw = '''type=USER_AUTH msg=audit(1000.1:1): uid=0 auid=4294967295 ses=4294967295 msg='acct="student" exe="/usr/sbin/sshd" res=failed' '''
    r = next(parse_audit(raw, "lab"))
    assert r["effective_uid"] is None
    assert r["_audit"]["login_uid"] is None
    assert r["_audit"]["session_id"] is None
    assert r["_audit"]["real_uid"] == "0"


def test_hex_path_with_newline_keeps_protected_prefix():
    name = "/srv/kernelguard/protected/a\nb.txt"
    raw = f'''type=SYSCALL msg=audit(1000.1:1): success=yes uid=1001 key="kernelguard_protected"
type=PATH msg=audit(1000.1:1): name={name.encode().hex()} nametype=NORMAL'''
    assert next(parse_audit(raw, "lab"))["resource"] == name


def test_policy_is_shared_and_immutable_across_configuration_changes(engine):
    cfg = settings()
    with engine.begin() as conn:
        for i in range(10):
            ingest(conn, record(i, 1000 + i), cfg)
        assert conn.execute(select(func.count()).select_from(rule_policies)).scalar() == 1
        cfg["login_threshold"] = 2
        for i in range(10, 12):
            ingest(conn, record(i, 2000 + i), cfg)
        snapshots = conn.execute(select(rule_policies.c.parameters_json)
            .join(alert_policies).order_by(alert_policies.c.alert_id)).scalars().all()
        assert [json.loads(p)["threshold"] for p in snapshots] == [5, 5, 2]
        assert conn.execute(select(func.count()).select_from(rule_policies)).scalar() == 2


@pytest.mark.parametrize("table,values", [
    (alert_events, {"alert_id": 999, "event_id": 999}),
    (alert_policies, {"alert_id": 999, "policy_id": "missing"}),
    (audit_details, {"event_id": 999, "audit_timestamp": "1", "audit_serial": "1", "record_type": "SYSCALL"}),
])
def test_database_rejects_orphaned_relationships(engine, table, values):
    with pytest.raises(IntegrityError), engine.begin() as conn:
        conn.execute(table.insert().values(**values))


def test_checkpoint_and_event_writes_roll_back_together(engine, monkeypatch):
    cfg = settings()
    with engine.begin() as conn:
        checkpoint_set(conn, "audit:" + cfg["host_id"], "old-cursor")

    def run(command, **kwargs):
        Path(command[command.index("--checkpoint") + 1]).write_text("new-cursor")
        return SimpleNamespace(returncode=0, stdout=Path("fixtures/demo.audit").read_text(), stderr="")

    def fail_after_insert(conn, r, cfg):
        ingest(conn, r, cfg)
        raise RuntimeError("simulated failure after an event write")

    monkeypatch.setattr("kernelguard.__main__.subprocess.run", run)
    monkeypatch.setattr("kernelguard.__main__.ingest", fail_after_insert)
    with pytest.raises(RuntimeError):
        collect_once(engine, cfg)
    with engine.connect() as conn:
        assert checkpoint_get(conn, "audit:" + cfg["host_id"]) == "old-cursor"
        assert conn.execute(select(func.count()).select_from(events)).scalar() == 0
        assert conn.execute(select(func.count()).select_from(audit_details)).scalar() == 0


def test_second_writer_rejected_and_lock_released_after_failure(tmp_path):
    db = database("sqlite:///" + (tmp_path / "lab.db").as_posix())
    with pytest.raises(ValueError):
        with writer_lock(db):
            with pytest.raises(RuntimeError):
                with writer_lock(db):
                    pytest.fail("Concurrent writer incorrectly admitted")
            raise ValueError("stop this writer")
    with writer_lock(db):
        pass
    db.dispose()


@pytest.mark.parametrize("override", [
    {"login_threshold": True}, {"login_threshold": 2.5}, {"login_window_seconds": "300"},
    {"allowed_start_hour": False}, {"host_id": ""}, {"typo_setting": 1},
    {"allowed_end_hour": 24}, {"login_window_seconds": 0}, {"protected_path": "relative/path"},
    {"timezone": "KernelGuard/Not_A_Zone"}, {"allowed_end_hour": 9},
])
def test_invalid_configuration_is_rejected(tmp_path, override):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(override))
    with pytest.raises(ValueError):
        settings(path)


def test_settings_normalize_path_and_preserve_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"protected_path": "/srv/kernelguard/unused/../protected/"}))
    cfg = settings(path)
    assert cfg["protected_path"] == "/srv/kernelguard/protected"
    assert cfg["login_threshold"] == 5


def test_lock_does_not_mislabel_application_errors(tmp_path):
    db = database("sqlite:///" + (tmp_path / "lab.db").as_posix())
    with pytest.raises(OSError, match="application failure"):
        with writer_lock(db):
            raise OSError("application failure")
    with writer_lock(db):
        pass
    db.dispose()


def test_replay_enriches_legacy_event_without_inventing_policy(engine):
    r = next(parse_audit(Path("fixtures/demo.audit").read_text(), "lab", "demo"))
    legacy = {k: v for k, v in r.items() if k != "_audit"}
    with engine.begin() as conn:
        conn.execute(events.insert().values(**legacy))
        assert not ingest(conn, r, settings())
        assert conn.execute(select(func.count()).select_from(audit_details)).scalar() == 1
        assert conn.execute(select(func.count()).select_from(alerts)).scalar() == 0


@pytest.mark.parametrize("returncode,stdout,stderr", [
    (2, "", ""), (1, "Permission denied", ""), (1, "", "Permission denied")])
def test_unexplained_collector_failure_preserves_checkpoint(engine, monkeypatch, returncode, stdout, stderr):
    cfg = settings()
    key = "audit:" + cfg["host_id"]
    with engine.begin() as conn:
        checkpoint_set(conn, key, "old-cursor")

    def run(command, **kwargs):
        Path(command[command.index("--checkpoint") + 1]).write_text("new-cursor")
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr("kernelguard.__main__.subprocess.run", run)
    with pytest.raises(RuntimeError, match="ausearch failed"):
        collect_once(engine, cfg)
    with engine.connect() as conn:
        assert checkpoint_get(conn, key) == "old-cursor"
        assert checkpoint_get(conn, "collector_health") is None


@pytest.mark.parametrize("stdout,stderr", [
    ("<no matches>\n", ""), ("", "<no matches>\n"), ("", "")])
def test_empty_successful_poll_records_health(engine, monkeypatch, stdout, stderr):
    monkeypatch.setattr("kernelguard.__main__.subprocess.run", lambda *a, **kw:
        SimpleNamespace(returncode=1, stdout=stdout, stderr=stderr))
    collect_once(engine, settings())
    with engine.connect() as conn:
        assert checkpoint_get(conn, "collector_health") is not None
        assert conn.execute(select(func.count()).select_from(events)).scalar() == 0
