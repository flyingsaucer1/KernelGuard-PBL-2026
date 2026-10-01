"""Reproducible synthetic policy evaluation and a bounded SQLite throughput sample."""
import argparse
import json
import platform
import tempfile
import time
from pathlib import Path
from sqlalchemy import select, func
from kernelguard.core import database, metadata, settings, ingest, events, alerts, digest
from kernelguard.demo import activity_audit
from kernelguard.parser import parse_audit
from kernelguard.inventory.models import Snapshot
from kernelguard.inventory.service import store_snapshot

ROOT = Path(__file__).resolve().parent.parent


def evaluate(batches=25):
    baseline = list(parse_audit((ROOT / "fixtures/demo.audit").read_text(), "evaluation", "demo"))
    extra = list(parse_audit(activity_audit(), "evaluation", "demo"))
    authentications = [r for r in baseline if r["kind"] == "login_failure"]
    cases = [
        ("Five failed logins", authentications, "Repeated login failures", True),
        ("Four failed logins", authentications[:4], "Repeated login failures", False),
        ("Distinct-path burst", extra[:10], "Bulk protected-file activity", True),
        ("Nine distinct paths", extra[:9], "Bulk protected-file activity", False),
        ("Selected root-effective command", extra[-1:], "Sensitive privileged command", True),
        ("Unselected executable", [dict(extra[-1], executable="/usr/bin/id")], "Sensitive privileged command", False),
        ("Repeated read of one path", [dict(r, resource="/srv/kernelguard/protected/same") for r in extra[:10]], "Bulk protected-file activity", False),
        ("Failed privileged execution", [dict(extra[-1], outcome="failure")], "Sensitive privileged command", False),
        ("Allowed-hours read", extra[:1], "After-hours protected access", False),
        ("Outside-hours successful read", [r for r in baseline if r["kind"] == "file_access" and r["outcome"] == "success"], "After-hours protected access", True),
    ]
    outcomes = []
    for label, records, rule, expected in cases:
        db = database("sqlite://")
        metadata.create_all(db)
        with db.begin() as conn:
            for record in records:
                ingest(conn, record, settings())
            predicted = bool(conn.execute(select(alerts.c.id).where(alerts.c.rule == rule)).first())
        db.dispose()
        outcomes.append(dict(scenario=label, expected_policy_match=expected, observed=predicted, passed=expected == predicted))
    db = database("sqlite://")
    metadata.create_all(db)
    with db.begin() as conn:
        store_snapshot(conn, Snapshot.model_validate_json((ROOT / "fixtures/inventory.json").read_text()), settings())
        predicted = bool(conn.execute(select(alerts.c.id).where(alerts.c.rule == "Unapproved USB device")).first())
    db.dispose()
    outcomes.append(dict(scenario="Unenrolled USB observation", expected_policy_match=True, observed=predicted, passed=predicted))
    records = []
    for batch in range(batches):
        for index, original in enumerate(baseline + extra):
            records.append(dict(original, host=f"benchmark-{batch}", source_id=digest(f"benchmark:{batch}:{index}")))
    with tempfile.TemporaryDirectory(prefix="kernelguard-evaluation-") as directory:
        db = database("sqlite:///" + (Path(directory) / "benchmark.db").as_posix())
        metadata.create_all(db)
        started = time.perf_counter()
        with db.begin() as conn:
            for record in records:
                ingest(conn, record, settings())
        elapsed = time.perf_counter() - started
        with db.connect() as conn:
            event_count = conn.execute(select(func.count()).select_from(events)).scalar()
            alert_count = conn.execute(select(func.count()).select_from(alerts)).scalar()
        db.dispose()
    return dict(environment=dict(os=platform.system(), python=platform.python_version(), backend="SQLite"),
        policy_cases=outcomes, passed=sum(c["passed"] for c in outcomes), total=len(outcomes),
        benchmark=dict(events=event_count, alerts=alert_count, seconds=round(elapsed, 4),
            events_per_second=round(event_count / elapsed, 1), batches=batches,
            scope="Synthetic disk-backed ingestion; one transaction; excludes collection, inventory, browser and setup"),
        false_positive_analysis=[
            dict(scenario="Authorized backup reads ten distinct protected files", legitimate=True,
                rule="Bulk protected-file activity", alerts=outcomes[2]["observed"]),
            dict(scenario="Authorized administrator runs selected command", legitimate=True,
                rule="Sensitive privileged command", alerts=outcomes[4]["observed"]),
        ],
        limitations="Hand-authored policy cases are not a real-world labelled security dataset. "
            "The two legitimate scenarios deliberately satisfy policy and need human review. "
            "No field precision/recall or production throughput is claimed.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batches", type=int, default=25)
    parser.add_argument("--output", default="docs/evaluation.json")
    args = parser.parse_args()
    if not 1 <= args.batches <= 500:
        parser.error("--batches must be between 1 and 500")
    result = evaluate(args.batches)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"policy_cases": f"{result['passed']}/{result['total']}", "benchmark": result["benchmark"]}, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] else 1)


if __name__ == "__main__":
    main()
