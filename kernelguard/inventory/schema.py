from sqlalchemy import Table, Column, String, Text, Integer, Boolean, ForeignKey, Index
from ..core import metadata

# START Mohd Ahmed Khan: relational tables for host inventory and device decisions.
snapshots = Table("inventory_snapshots", metadata,
    Column("id", String(64), primary_key=True),
    Column("host", String(128), nullable=False),
    Column("origin", String(16), nullable=False),
    Column("boot_id", String(64), nullable=False),
    Column("timestamp", Integer, nullable=False),
    Column("processes_complete", Boolean, nullable=False),
    Column("warnings_json", Text, nullable=False),
    Index("ix_snapshot_scope_time", "host", "origin", "timestamp"))
users = Table("host_users", metadata,
    Column("id", String(64), primary_key=True),
    Column("host", String(128), nullable=False), Column("origin", String(16), nullable=False),
    Column("uid", String(32), nullable=False), Column("username", String(128), nullable=False),
    Column("last_seen", Integer, nullable=False), Column("present", Boolean, nullable=False))
sessions = Table("host_sessions", metadata,
    Column("id", String(64), primary_key=True),
    Column("host", String(128), nullable=False), Column("origin", String(16), nullable=False),
    Column("boot_id", String(64), nullable=False), Column("audit_session", String(32), nullable=False),
    Column("user_id", ForeignKey("host_users.id")),
    Column("first_seen", Integer, nullable=False), Column("last_seen", Integer, nullable=False),
    Column("present", Boolean, nullable=False))
processes = Table("host_processes", metadata,
    Column("id", String(64), primary_key=True),
    Column("host", String(128), nullable=False), Column("origin", String(16), nullable=False),
    Column("boot_id", String(64), nullable=False), Column("pid", Integer, nullable=False),
    Column("started", String(32), nullable=False), Column("ppid", Integer, nullable=False),
    Column("parent_id", ForeignKey("host_processes.id")), Column("session_id", ForeignKey("host_sessions.id")),
    Column("user_id", ForeignKey("host_users.id")), Column("effective_uid", String(32)),
    Column("executable", Text), Column("last_seen", Integer, nullable=False),
    Column("present", Boolean, nullable=False),
    Index("ix_process_scope_pid", "host", "origin", "boot_id", "pid"))
devices = Table("usb_devices", metadata,
    Column("id", String(64), primary_key=True),
    Column("host", String(128), nullable=False), Column("origin", String(16), nullable=False),
    Column("vendor", String(4), nullable=False), Column("product", String(4), nullable=False),
    Column("serial", String(256)), Column("port", String(256), nullable=False),
    Column("label", String(256), nullable=False), Column("identity_basis", String(16), nullable=False),
    Column("boot_id", String(64), nullable=False),
    Column("first_seen", Integer, nullable=False), Column("last_seen", Integer, nullable=False),
    Column("present", Boolean, nullable=False))
device_events = Table("device_events", metadata,
    Column("event_id", ForeignKey("events.id"), primary_key=True),
    Column("device_id", ForeignKey("usb_devices.id"), nullable=False),
    Column("snapshot_id", ForeignKey("inventory_snapshots.id"), nullable=False))
device_decisions = Table("device_decisions", metadata,
    Column("id", Integer, primary_key=True),
    Column("device_id", ForeignKey("usb_devices.id"), nullable=False),
    Column("administrator_id", ForeignKey("administrators.id"), nullable=False),
    Column("approved", Boolean, nullable=False), Column("note", String(1000), nullable=False),
    Column("timestamp", Integer, nullable=False),
    Index("ix_device_decision", "device_id", "id"))
# END Mohd Ahmed Khan: inventory schema and foreign-key relationships.
