"""Offline checks plus an optional disposable MySQL integration test."""

import os
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.dialects import mysql
from sqlalchemy.schema import CreateTable

from kernelguard.config import settings
from kernelguard.core import alert_events, alerts, database, events, ingest, metadata
from kernelguard.parser import parse_audit
from app import PHASE2_NAMES, check_schema, create_phase2_app, import_baseline


def test_phase2_schema_and_fixture():
    assert set(metadata.tables) == PHASE2_NAMES
    assert len(PHASE2_NAMES) == 8
    statements = [str(CreateTable(table).compile(dialect=mysql.dialect()))
                  for table in metadata.tables.values()]
    assert any("FOREIGN KEY(alert_id)" in statement for statement in statements)

    raw = Path("fixtures/demo.audit").read_text(encoding="utf-8")
    records = list(parse_audit(raw, "lab", "demo"))
    assert len(records) == 9
    assert {row["kind"] for row in records} == {"login_failure", "file_access"}


def test_only_mysql_is_accepted():
    with pytest.raises(ValueError, match="MySQL"):
        database("sqlite:///data/phase2.db")
    engine = database("mysql+pymysql://kg:password@localhost/kernelguard_phase2")
    try:
        assert engine.url.database == "kernelguard_phase2"
    finally:
        engine.dispose()


def test_user_process_and_file_audit_records():
    raw = '''type=SYSCALL msg=audit(1791813600.100:501): arch=c000003e syscall=59 success=yes pid=321 auid=1000 uid=1000 euid=1000 ses=3 exe="/usr/bin/cat" key="kernelguard_process_exec"
type=SYSCALL msg=audit(1791813601.100:502): arch=c000003e syscall=257 success=yes pid=321 auid=1000 uid=1000 euid=1000 ses=3 exe="/usr/bin/cat" key="kernelguard_file_access"
type=CWD msg=audit(1791813601.100:502): cwd="/home/kali"
type=PATH msg=audit(1791813601.100:502): item=0 name="notes.txt" inode=42 dev=08:01 nametype=NORMAL
'''
    records = list(parse_audit(raw, "lab", "live", boot_id="boot-1"))
    assert [(row["kind"], row["resource"]) for row in records] == [
        ("process_exec", "/usr/bin/cat"),
        ("file_access", "/home/kali/notes.txt"),
    ]
    assert all(row["origin"] == "live" for row in records)
    assert len({row["source_id"] for row in records}) == 2


def test_later_phase_events_are_rejected():
    record = {"kind": "privileged_exec"}
    with pytest.raises(ValueError, match="Phase 2 accepts"):
        ingest(None, record, settings())


def test_mysql_baseline_and_dashboard():
    url = os.environ.get("KERNELGUARD_PHASE2_TEST_DB_URL")
    if not url:
        pytest.skip("Set KERNELGUARD_PHASE2_TEST_DB_URL for a MySQL integration test")
    engine = database(url)
    if not engine.url.database.endswith("_test"):
        pytest.fail("Integration database name must end in _test")
    if inspect(engine).get_table_names():
        pytest.fail("Integration database must be empty before the test")

    try:
        check_schema(engine, create=True)
        assert set(inspect(engine).get_table_names()) == PHASE2_NAMES
        cfg = settings()
        import_baseline(engine, cfg)
        import_baseline(engine, cfg)
        with engine.connect() as conn:
            assert conn.scalar(select(func.count()).select_from(events)) == 9
            assert conn.scalar(select(func.count()).select_from(alerts)) == 2
            assert conn.scalar(select(func.count()).select_from(alert_events)) == 6
        client = create_phase2_app(engine, cfg).test_client()
        assert client.get("/").status_code == 200
        assert client.get("/alerts/1").status_code == 200
        assert client.get("/inventory").status_code == 404
    finally:
        metadata.drop_all(engine)
        engine.dispose()
