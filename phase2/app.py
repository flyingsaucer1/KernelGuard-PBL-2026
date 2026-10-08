"""Run the Phase 2 audit/DBMS demonstration without Phase 3 features.

Examples:
    python app.py                 # initialize schema and serve
    python app.py demo            # import the nine-event baseline
    python app.py collect --once  # poll Linux Audit once
    python app.py serve           # serve an initialized Phase 2 database

Set KERNELGUARD_PHASE2_DB_URL to a dedicated MySQL URL before every command.
Never point this launcher at the completed project's database.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from flask import Flask, abort, render_template, request, url_for
from sqlalchemy import func, inspect, select
from waitress import serve

from kernelguard.core import (
    alert_events, alert_policies, alerts, checkpoint_get,
    checkpoint_set, checkpoints, database, digest, events,
    ingest, metadata, rule_policies, settings, utc_display,
)
from kernelguard.locking import writer_lock
from kernelguard.parser import parse_audit


ROOT = Path(__file__).resolve().parent
PHASE2_NAMES = set(metadata.tables)
PHASE2_KINDS = ("login_failure", "file_access")
PHASE2_RULES = ("Repeated login failures", "After-hours protected access")

def check_schema(engine, *, create=False):
    """Require a dedicated database containing only Phase 2 tables."""
    existing = set(inspect(engine).get_table_names())
    extra = existing - PHASE2_NAMES
    if extra:
        raise RuntimeError(
            "Phase 2 needs a dedicated database; unrelated tables found: "
            + ", ".join(sorted(extra))
        )
    if create:
        metadata.create_all(engine)
    elif PHASE2_NAMES - existing:
        raise RuntimeError("Phase 2 schema is missing; run: python app.py init-db")
    with engine.connect() as conn:
        other_kind = conn.execute(select(events.c.kind).where(
            events.c.kind.not_in(PHASE2_KINDS)).limit(1)).first()
        other_rule = conn.execute(select(alerts.c.rule).where(
            alerts.c.rule.not_in(PHASE2_RULES)).limit(1)).first()
    if other_kind or other_rule:
        raise RuntimeError("Database contains non-Phase-2 activity; choose a fresh database")


def import_baseline(engine, cfg):
    source = (ROOT / "fixtures" / "demo.audit").read_text(encoding="utf-8")
    records = list(parse_audit(source, cfg["host_id"], "demo"))
    if len(records) != 9 or any(row["kind"] not in PHASE2_KINDS for row in records):
        raise RuntimeError("The baseline fixture is not the expected nine Phase 2 events")
    with writer_lock(engine), engine.begin() as conn:
        inserted = sum(ingest(conn, row, cfg)
                       for row in records)
    print(f"Phase 2 baseline: {len(records)} events; inserted {inserted}.", flush=True)


# START Arshpreet Singh: collect Linux Audit events and commit the audit cursor.
def collect_once(engine, cfg):
    """Read only Phase 2 event kinds from Linux Audit, with a committed cursor."""
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    key = "phase2-audit:" + digest(cfg["host_id"] + ":" + boot)
    with writer_lock(engine):
        with engine.connect() as conn:
            saved = checkpoint_get(conn, key)
        with tempfile.TemporaryDirectory(prefix="kernelguard-phase2-") as directory:
            cursor = Path(directory) / "audit.cursor"
            if saved:
                cursor.write_text(saved, encoding="utf-8")
            command = ["ausearch", "--input-logs", "--checkpoint", str(cursor), "--raw"]
            if not saved:
                command += ["--start", "boot"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=45)
            diagnostic = (result.stdout + "\n" + result.stderr).strip()
            if result.returncode != 0 and not (
                    result.returncode == 1 and diagnostic in ("", "<no matches>")):
                raise RuntimeError(f"ausearch failed ({result.returncode}): {diagnostic}")
            records = [row for row in parse_audit(
                result.stdout, cfg["host_id"], "live", boot_id=boot)
                if row["kind"] in PHASE2_KINDS]
            with engine.begin() as conn:
                inserted = sum(ingest(conn, row, cfg)
                               for row in records)
                if cursor.exists():
                    checkpoint_set(conn, key, cursor.read_text(encoding="utf-8"))
                checkpoint_set(conn, "phase2_collector_health",
                               json.dumps({"last_poll": int(time.time()),
                                           "inserted": inserted}))
    print(f"Phase 2 collector: inserted {inserted} events.", flush=True)
# END Arshpreet Singh: Linux Audit collection and checkpoint handling.


# START Mohd Shoaib: serve the read-only dashboard, filters, and alert evidence.
def create_phase2_app(engine, cfg):
    app = Flask(__name__, template_folder=str(ROOT / "kernelguard" / "templates"),
                static_folder=str(ROOT / "kernelguard" / "static"))
    app.jinja_env.filters["utc"] = utc_display

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'none'")
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def overview():
        kind = request.args.get("kind", "")
        account = request.args.get("account", "").strip()[:128]
        query = select(events).order_by(
            events.c.timestamp.desc(), events.c.id.desc()).limit(100)
        if kind in PHASE2_KINDS:
            query = query.where(events.c.kind == kind)
        if account:
            query = query.where(events.c.account == account)
        with engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            alert_rows = conn.execute(select(alerts).order_by(
                alerts.c.timestamp.desc()).limit(30)).mappings().all()
            total = conn.execute(select(func.count()).select_from(events)).scalar()
            alert_count = conn.execute(select(func.count()).select_from(alerts)).scalar()
            demo_count = conn.execute(select(func.count()).select_from(events).where(
                events.c.origin == "demo")).scalar()
            health = conn.execute(select(checkpoints.c.value).where(
                checkpoints.c.name == "phase2_collector_health")).scalar()
        last_poll = json.loads(health).get("last_poll", 0) if health else 0
        healthy = 0 <= time.time() - last_poll < 30
        return render_template(
            "overview.html", rows=rows, alert_rows=alert_rows, total=total,
            alert_count=alert_count, demo_count=demo_count, healthy=healthy,
            backend=engine.dialect.name, cfg=cfg, kind=kind, account=account)

    @app.get("/alerts/<int:alert_id>")
    def detail(alert_id):
        with engine.connect() as conn:
            alert = conn.execute(select(alerts).where(
                alerts.c.id == alert_id)).mappings().first()
            if alert is None:
                abort(404)
            rows = conn.execute(select(events).join(
                alert_events, events.c.id == alert_events.c.event_id).where(
                alert_events.c.alert_id == alert_id).order_by(
                events.c.timestamp)).mappings().all()
            policy = conn.execute(select(rule_policies).join(
                alert_policies, rule_policies.c.id == alert_policies.c.policy_id
            ).where(alert_policies.c.alert_id == alert_id)).mappings().first()
        return render_template("alert.html", alert=alert, rows=rows, policy=policy)

    return app
# END Mohd Shoaib: dashboard and alert evidence routes.


def main():
    parser = argparse.ArgumentParser(description="KernelGuard Phase 2 only")
    parser.add_argument("command", nargs="?", default="run",
                        choices=("run", "init-db", "demo", "serve", "collect"))
    parser.add_argument("--config", help="Optional JSON policy settings")
    parser.add_argument("--port", type=int, default=5002)
    parser.add_argument("--once", action="store_true", help="One Linux Audit poll")
    parser.add_argument("--interval", type=int, default=5)
    args = parser.parse_args()
    if args.port < 1 or args.port > 65535 or args.interval < 1:
        parser.error("port and interval must be positive and the port at most 65535")
    if args.command == "collect" and sys.platform != "linux":
        parser.error("Live audit collection requires Linux")

    cfg = settings(args.config)
    url = os.environ.get("KERNELGUARD_PHASE2_DB_URL")
    if not url:
        parser.error("Set KERNELGUARD_PHASE2_DB_URL to the dedicated MySQL database")
    try:
        engine = database(url)
    except ValueError as exc:
        parser.error(str(exc))
    if engine.url.database == "kernelguard_live":
        parser.error("Choose a dedicated Phase 2 database, not kernelguard_live")
    try:
        check_schema(engine, create=args.command in ("run", "init-db", "demo"))
        if args.command == "init-db":
            print(f"Phase 2 schema ready ({engine.dialect.name}).")
            return
        if args.command == "demo":
            import_baseline(engine, cfg)
            return
        if args.command == "collect":
            try:
                while True:
                    collect_once(engine, cfg)
                    if args.once:
                        return
                    time.sleep(args.interval)
            except KeyboardInterrupt:
                print("Phase 2 collector stopped.")
            return
        print(f"Phase 2 dashboard: http://127.0.0.1:{args.port}", flush=True)
        serve(create_phase2_app(engine, cfg), host="127.0.0.1",
              port=args.port, threads=4)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
