import argparse
import getpass
import json
import os
import subprocess
import tempfile
import time
import sys
from pathlib import Path

from .core import database, metadata, settings, ingest, checkpoint_get, checkpoint_set, digest
from .parser import parse_audit
from .locking import writer_lock, WriterBusy


def import_text(engine, cfg, text, origin):
    records = list(parse_audit(text, cfg["host_id"], origin))
    with writer_lock(engine), engine.begin() as conn:
        count = sum(ingest(conn, record, cfg) for record in records)
    print(f"Parsed {len(records)} events; inserted {count}; duplicates {len(records) - count}.")


def current_boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip() if sys.platform == "linux" else None


def collect_once(engine, cfg):
    """ausearch groups complete events; checkpoint advances only with DB commit."""
    boot = current_boot()
    key = "audit:" + (digest(cfg["host_id"] + ":" + boot) if boot else cfg["host_id"])
    with engine.connect() as conn:
        saved = checkpoint_get(conn, key)
    with tempfile.TemporaryDirectory(prefix="kernelguard-") as directory:
        cursor = Path(directory) / "audit.cursor"
        if saved:
            cursor.write_text(saved, encoding="utf-8")
        command = ["ausearch", "--input-logs", "--checkpoint", str(cursor), "--raw"]
        if not saved:
            command += ["--start", "boot"]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=45)
        # ausearch returns 1 when there are no matching events. Some versions
        # print "<no matches>"; this host's ausearch prints nothing.
        # Other failures must never be presented as a healthy collector.
        diagnostic = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode != 0 and not (
                proc.returncode == 1 and diagnostic in ("", "<no matches>")):
            raise RuntimeError(f"ausearch failed ({proc.returncode}): {diagnostic}")
        records = list(parse_audit(proc.stdout, cfg["host_id"], boot_id=boot))
        with engine.begin() as conn:
            count = sum(ingest(conn, record, cfg) for record in records)
            if cursor.exists():
                checkpoint_set(conn, key, cursor.read_text(encoding="utf-8"))
            checkpoint_set(conn, "collector_health", json.dumps({
                "last_poll": int(time.time()), "host": cfg["host_id"], "inserted": count}))
        print(f"Collector: inserted {count} events", flush=True)


def main():
    parser = argparse.ArgumentParser(description="KernelGuard activity monitor")
    parser.add_argument("--config", help="JSON rule settings")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    demo = sub.add_parser("demo", help="Import the complete synthetic activity and inventory demo")
    demo.add_argument("--baseline", action="store_true", help="Only import the original nine audit events")
    inventory = sub.add_parser("inventory", help="Poll Linux users, processes, sessions and USB devices")
    inventory.add_argument("--once", action="store_true")
    inventory.add_argument("--interval", type=int, default=10)
    inventory_import = sub.add_parser("import-inventory", help="Import a validated inventory JSON export")
    inventory_import.add_argument("path")
    admin = sub.add_parser("create-admin", help="Create an administrator; password is prompted privately")
    admin.add_argument("username")
    imp = sub.add_parser("import-audit", help="Import an exported raw audit log")
    imp.add_argument("path")
    imp.add_argument("--origin", choices=("live", "demo"), default="live")
    collector = sub.add_parser("collect", help="Linux only; needs audit log access")
    collector.add_argument("--once", action="store_true")
    collector.add_argument("--interval", type=int, default=5)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    cfg = settings(args.config)
    Path("data").mkdir(exist_ok=True)
    url = os.environ.get("KERNELGUARD_DB_URL", "sqlite:///data/kernelguard.db")
    engine = database(url)
    if args.command == "init-db":
        metadata.create_all(engine)
        print(f"Schema ready ({engine.dialect.name}).")
    elif args.command == "create-admin":
        from .auth import create_administrator
        password = getpass.getpass("New password (12–256 characters): ")
        if password != getpass.getpass("Confirm password: "):
            parser.error("Passwords do not match")
        metadata.create_all(engine)
        try:
            with writer_lock(engine), engine.begin() as conn:
                create_administrator(conn, args.username, password)
        except ValueError as exc:
            parser.error(str(exc))
        print("Administrator created. Set KERNELGUARD_SECRET_KEY and restart the dashboard.")
    elif args.command == "demo":
        metadata.create_all(engine)
        text = (Path(__file__).parent.parent / "fixtures/demo.audit").read_text()
        if not args.baseline:
            from .demo import activity_audit
            text += "\n" + activity_audit()
        import_text(engine, cfg, text, "demo")
        if not args.baseline:
            from .inventory.models import Snapshot
            from .inventory.service import store_snapshot
            snapshot = Snapshot.model_validate_json((Path(__file__).parent.parent / "fixtures/inventory.json").read_text())
            snapshot.host = cfg["host_id"]
            with writer_lock(engine), engine.begin() as conn:
                changed = store_snapshot(conn, snapshot, cfg)
            print(f"Synthetic inventory {'stored' if changed else 'already imported'}.")
    elif args.command in ("inventory", "import-inventory"):
        from .inventory.collector import collect_snapshot
        from .inventory.models import Snapshot
        from .inventory.service import store_snapshot
        metadata.create_all(engine)
        if args.command == "inventory" and args.interval < 1:
            parser.error("--interval must be positive")
        try:
            while True:
                try:
                    with writer_lock(engine):
                        snapshot = (Snapshot.model_validate_json(Path(args.path).read_text(encoding="utf-8"))
                            if args.command == "import-inventory" else collect_snapshot(cfg["host_id"]))
                        with engine.begin() as conn:
                            changed = store_snapshot(conn, snapshot, cfg)
                    print(f"Inventory {'stored' if changed else 'duplicate'}: {len(snapshot.users)} users, "
                        f"{len(snapshot.processes)} processes, {len(snapshot.devices)} USB devices. "
                        f"Warnings: {snapshot.warnings}", flush=True)
                except WriterBusy:
                    if args.command == "import-inventory" or args.once:
                        raise
                    print("Inventory waiting for database writer.", flush=True)
                if args.command == "import-inventory" or args.once:
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Inventory stopped.")
    elif args.command == "import-audit":
        import_text(engine, cfg, Path(args.path).read_text(encoding="utf-8"), args.origin)
    elif args.command == "collect":
        if sys.platform != "linux":
            parser.error("Live audit collection needs Linux; use demo on Windows")
        if args.interval < 1:
            parser.error("--interval must be positive")
        try:
            while True:
                try:
                    with writer_lock(engine):
                        collect_once(engine, cfg)
                except WriterBusy:
                    if args.once:
                        raise
                    print("Audit collector waiting for database writer.", flush=True)
                if args.once:
                    break
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("Collector stopped.")
    elif args.command == "serve":
        from .web import create_app
        from waitress import serve
        print(f"KernelGuard: http://127.0.0.1:{args.port}", flush=True)
        serve(create_app(engine, cfg), host="127.0.0.1", port=args.port, threads=4)


if __name__ == "__main__":
    main()
