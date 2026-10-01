"""Opt-in: set KERNELGUARD_TEST_MYSQL_URL to a disposable MySQL database.

Creates missing schema tables; test data is rolled back. Never point at production.
"""
import os
import uuid
from pathlib import Path
import pytest
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from kernelguard.core import (database, metadata, ingest, settings, events, alerts,
    alert_events, digest, administrators, alert_reviews)
from kernelguard.auth import create_administrator
from kernelguard.reviews import review_alert
from kernelguard.locking import writer_lock
from kernelguard.inventory.models import Snapshot
from kernelguard.inventory.schema import devices, snapshots, device_events, device_decisions
from kernelguard.inventory.service import store_snapshot, device_id, decide_device


@pytest.mark.skipif(not os.environ.get("KERNELGUARD_TEST_MYSQL_URL"),
                    reason="No disposable MySQL test database configured")
def test_mysql_transaction_and_evidence():
    db = database(os.environ["KERNELGUARD_TEST_MYSQL_URL"])
    assert db.dialect.name == "mysql"
    metadata.create_all(db)
    with writer_lock(db):
        with pytest.raises(RuntimeError):
            with writer_lock(db):
                pytest.fail("MySQL admitted a concurrent writer")
    account = "test-" + uuid.uuid4().hex
    with db.connect() as conn:
        transaction = conn.begin()
        try:
            for i in range(5):
                r = dict(source_id=digest(f"{account}:{i}"), host="mysql-test", timestamp=1000+i,
                    kind="login_failure", account=account, outcome="failure", origin="demo")
                assert ingest(conn, r, settings())
                assert not ingest(conn, r, settings())
            aid = conn.execute(select(alerts.c.id).where(alerts.c.account == account)).scalar_one()
            assert conn.execute(select(func.count()).select_from(alert_events).where(
                alert_events.c.alert_id == aid)).scalar() == 5
            create_administrator(conn, account, uuid.uuid4().hex)
            admin_id = conn.execute(select(administrators.c.id).where(
                administrators.c.username == account)).scalar_one()
            review_alert(conn, aid, admin_id, "acknowledge", "MySQL transaction test", 0)
            assert conn.execute(select(func.count()).select_from(alert_reviews).where(
                alert_reviews.c.alert_id == aid)).scalar() == 1
            snapshot = Snapshot.model_validate_json(Path("fixtures/inventory.json").read_text())
            snapshot.host = account
            assert store_snapshot(conn, snapshot, settings())
            assert not store_snapshot(conn, snapshot, settings())
            did = device_id(snapshot, snapshot.devices[0])
            decide_device(conn, did, admin_id, True, "Disposable database test", 0)
            assert conn.execute(select(func.count()).select_from(devices).where(devices.c.host == account)).scalar() == 1
            def next_snapshot(offset, present):
                data = snapshot.model_dump()
                data["timestamp"] += offset
                if not present:
                    data["devices"] = []
                return Snapshot.model_validate(data)

            store_snapshot(conn, next_snapshot(10, False), settings())
            store_snapshot(conn, next_snapshot(20, True), settings())
            assert conn.execute(select(func.count()).select_from(alerts).where(
                alerts.c.rule == "Unapproved USB device")).scalar() == 1
            approval_id = conn.execute(select(func.max(device_decisions.c.id)).where(
                device_decisions.c.device_id == did)).scalar_one()
            decide_device(conn, did, admin_id, False, "Disposable revocation test", approval_id)
            store_snapshot(conn, next_snapshot(30, False), settings())
            store_snapshot(conn, next_snapshot(40, True), settings())
            assert conn.execute(select(func.count()).select_from(alerts).where(
                alerts.c.rule == "Unapproved USB device")).scalar() == 2
            assert conn.execute(select(func.count()).select_from(device_events).where(
                device_events.c.device_id == did)).scalar() == 5
            with pytest.raises(IntegrityError):
                conn.execute(alert_events.insert().values(alert_id=aid, event_id=2147483647))
        finally:
            transaction.rollback()
    with db.connect() as conn:
        assert conn.execute(select(func.count()).select_from(events).where(events.c.account == account)).scalar() == 0
        assert conn.execute(select(func.count()).select_from(administrators).where(
            administrators.c.username == account)).scalar() == 0
        assert conn.execute(select(func.count()).select_from(snapshots).where(snapshots.c.host == account)).scalar() == 0
    db.dispose()
