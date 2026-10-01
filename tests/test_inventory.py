import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from sqlalchemy import select, func
from kernelguard.core import database, metadata, settings, events, alerts, event_context
from kernelguard.inventory.models import Snapshot
from kernelguard.inventory.schema import users, sessions, processes, devices, snapshots, device_decisions
from kernelguard.inventory.service import store_snapshot, decide_device, device_id
from kernelguard.inventory.collector import collect_snapshot
from kernelguard.auth import create_administrator
from kernelguard.web import create_app
from kernelguard.reviews import ReviewConflict
from kernelguard.parser import parse_audit
from kernelguard.demo import activity_audit
from kernelguard.core import ingest
from tests.test_activity_reviews import token, sign_in


@pytest.fixture
def engine():
    db = database("sqlite://")
    metadata.create_all(db)
    yield db
    db.dispose()


def example(**changes):
    data = json.loads(Path("fixtures/inventory.json").read_text())
    data.update(changes)
    return Snapshot.model_validate(data)


def count(conn, table):
    return conn.execute(select(func.count()).select_from(table)).scalar()


def test_inventory_relations_device_alert_and_replay(engine):
    with engine.begin() as conn:
        assert store_snapshot(conn, example(), settings())
        assert not store_snapshot(conn, example(), settings())
        assert [count(conn, t) for t in (users, sessions, processes, devices, snapshots, events, alerts)] == [2, 1, 3, 1, 1, 1, 1]
        process = conn.execute(select(processes).where(processes.c.pid == 2900)).mappings().one()
        parent = conn.execute(select(processes).where(processes.c.id == process["parent_id"])).mappings().one()
        assert parent["pid"] == 2000 and process["session_id"]
        assert conn.execute(select(events.c.account)).scalar_one() == "unattributed"


def test_presence_changes_and_enrollment_only_affect_future_observations(engine):
    first = example()
    did = device_id(first, first.devices[0])
    with engine.begin() as conn:
        create_administrator(conn, "reviewer", "a-test-password-123")
        store_snapshot(conn, first, settings())
        decide_device(conn, did, 1, True, "Known lab hardware", 0)
        store_snapshot(conn, example(timestamp=first.timestamp+10), settings())
        assert count(conn, events) == 1
        store_snapshot(conn, example(timestamp=first.timestamp+20, devices=[]), settings())
        assert not conn.execute(select(devices.c.present)).scalar_one()
        store_snapshot(conn, example(timestamp=first.timestamp+30), settings())
        assert count(conn, events) == 3 and count(conn, alerts) == 1
        decision = conn.execute(select(device_decisions.c.id)).scalar_one()
        decide_device(conn, did, 1, False, "Retired hardware", decision)
        store_snapshot(conn, example(timestamp=first.timestamp+40, devices=[]), settings())
        store_snapshot(conn, example(timestamp=first.timestamp+50), settings())
        assert count(conn, alerts) == 2


def test_boot_pid_and_session_reuse_do_not_merge(engine):
    first = example()
    with engine.begin() as conn:
        store_snapshot(conn, first, settings())
        store_snapshot(conn, example(timestamp=first.timestamp+10, boot_id="new-boot"), settings())
        assert count(conn, sessions) == 2 and count(conn, processes) == 6
        newer = example(timestamp=first.timestamp+20, boot_id="new-boot")
        newer.processes[-1].started = "1789014710.000000"
        store_snapshot(conn, newer, settings())
        assert count(conn, processes) == 7
        assert conn.execute(select(func.count()).select_from(processes).where(processes.c.present)).scalar() == 3


def test_partial_process_poll_does_not_claim_process_exit(engine):
    first = example()
    with engine.begin() as conn:
        store_snapshot(conn, first, settings())
        store_snapshot(conn, example(timestamp=first.timestamp+10, processes=[], processes_complete=False), settings())
        assert conn.execute(select(func.count()).select_from(processes).where(processes.c.present)).scalar() == 3
        store_snapshot(conn, example(timestamp=first.timestamp+20, processes=[]), settings())
        assert conn.execute(select(func.count()).select_from(processes).where(processes.c.present)).scalar() == 0


def test_snapshot_failure_rolls_back_all_changes(engine):
    with pytest.raises(RuntimeError), engine.begin() as conn:
        store_snapshot(conn, example(), settings())
        raise RuntimeError("simulated database failure")
    with engine.connect() as conn:
        assert all(count(conn, t) == 0 for t in (users, sessions, processes, devices, snapshots, events, alerts))


def test_stale_snapshot_cannot_restore_old_presence(engine):
    with engine.begin() as conn:
        store_snapshot(conn, example(), settings())
        with pytest.raises(ValueError, match="newer"):
            store_snapshot(conn, example(timestamp=1789014699, devices=[]), settings())
        assert conn.execute(select(devices.c.present)).scalar_one()


def test_demo_and_live_inventories_and_enrollment_are_separate(engine):
    with engine.begin() as conn:
        store_snapshot(conn, example(), settings())
        store_snapshot(conn, example(origin="live"), settings())
        store_snapshot(conn, example(host="another-host"), settings())
        assert count(conn, devices) == 3 and count(conn, alerts) == 3


@pytest.mark.parametrize("invalid", [
    {"origin": "trusted"}, {"boot_id": ""}, {"timestamp": -1},
    {"users": [{"uid": "0", "username": "a"}, {"uid": "0", "username": "b"}]},
])
def test_invalid_inventory_rejected(invalid):
    with pytest.raises(ValueError):
        example(**invalid)


def test_duplicate_hardware_fingerprints_rejected():
    data = example().model_dump()
    duplicate = dict(data["devices"][0], port="another-port")
    data["devices"].append(duplicate)
    with pytest.raises(ValueError, match="Ambiguous"):
        Snapshot.model_validate(data)


def test_no_serial_identity_is_scoped_to_port():
    first = example()
    device = first.devices[0].model_copy(update={"serial": None})
    moved = device.model_copy(update={"port": "different-port"})
    assert device_id(first, device) != device_id(first, moved)


def test_inventory_web_enrollment_csrf_stale_forms_and_escaping(engine):
    snapshot = example()
    snapshot.devices[0].label = "<script>USB</script>"
    did = device_id(snapshot, snapshot.devices[0])
    with engine.begin() as conn:
        create_administrator(conn, "reviewer", "a-test-password-123")
        store_snapshot(conn, snapshot, settings())
    client = create_app(engine, settings(), secret_key="test-only-secret-"*4).test_client()
    assert client.get("/inventory").status_code == 302
    sign_in(client)
    for kind in ("users", "sessions", "processes", "devices"):
        assert client.get("/inventory?kind="+kind).status_code == 200
    page = client.get("/devices/"+did)
    assert b"&lt;script&gt;" in page.data and b"<script>" not in page.data
    route = f"/devices/{did}/enrollment"
    assert client.post(route, data={}).status_code == 400
    form = dict(csrf_token=token(page), expected_id="0", decision="approve", note="Lab device")
    assert client.post(route, data=form).status_code == 302
    assert client.post(route, data=form).status_code == 409
    assert b"Revoke approval" in client.get("/devices/"+did).data
    assert client.get("/devices/not-a-device").status_code == 404
    assert b"Inspect device enrollment" in client.get("/alerts/1").data


def test_windows_live_inventory_fails_explicitly(monkeypatch):
    monkeypatch.setattr("kernelguard.inventory.collector.sys.platform", "win32")
    with pytest.raises(RuntimeError, match="needs Linux"):
        collect_snapshot("lab")


def test_bulk_rule_separates_boot_contexts(engine):
    cfg = settings()
    cfg["bulk_file_threshold"] = 3
    rows = list(parse_audit(activity_audit(), "lab", "demo", "boot-a"))[:3]
    rows[-1]["_boot"] = "boot-b"
    with engine.begin() as conn:
        for row in rows:
            ingest(conn, row, cfg)
        assert count(conn, alerts) == 0 and count(conn, event_context) == 3


def test_linux_collector_adapter_with_mocked_operating_system(monkeypatch):
    import sys
    from kernelguard.inventory import collector
    monkeypatch.setattr(collector.sys, "platform", "linux")
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwall=lambda: [SimpleNamespace(pw_uid=1001, pw_name="student")]))
    class Attributes:
        def get(self, name):
            return {"idVendor": b"abcd", "idProduct": b"1234", "serial": b"LAB", "product": b"Test USB"}.get(name)
    usb = SimpleNamespace(sys_name="1-1", device_path="/devices/1-1", attributes=Attributes())
    monkeypatch.setitem(sys.modules, "pyudev", SimpleNamespace(Context=lambda:
        SimpleNamespace(list_devices=lambda **kw: [usb])))
    def process_iter():
        return []
    process_iter.cache_clear = lambda: None
    monkeypatch.setattr(collector.psutil, "process_iter", process_iter)
    monkeypatch.setattr(collector.Path, "read_text", lambda self: "test-boot")
    result = collect_snapshot("lab")
    assert result.origin == "live" and result.boot_id == "test-boot"
    assert result.devices[0].serial == "LAB" and result.users[0].uid == "1001"
