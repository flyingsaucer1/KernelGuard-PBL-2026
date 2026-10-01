import json
import time
from flask import Flask, render_template, request, abort, g, redirect, url_for
from sqlalchemy import select, func
from .core import (events, alerts, alert_events, checkpoints, utc_display,
                   audit_details, rule_policies, alert_policies, alert_reviews, administrators)
from .auth import configure_auth
from .locking import writer_lock
from .reviews import review_alert, ReviewConflict


def event_view():
    return select(events, audit_details.c.login_uid, audit_details.c.real_uid,
        audit_details.c.effective_uid.label("observed_effective_uid"),
        audit_details.c.audit_serial, audit_details.c.syscall,
        audit_details.c.architecture, audit_details.c.inode, audit_details.c.device
        ).outerjoin(audit_details, events.c.id == audit_details.c.event_id)


def create_app(engine, cfg, secret_key=None):
    app = Flask(__name__)
    configure_auth(app, engine, secret_key)
    from .inventory.routes import register_inventory
    register_inventory(app, engine)
    app.jinja_env.filters["utc"] = utc_display

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def dashboard():
        kind = request.args.get("kind", "")
        account = request.args.get("account", "").strip()[:128]
        query = event_view().order_by(events.c.timestamp.desc(), events.c.id.desc()).limit(100)
        if kind:
            query = query.where(events.c.kind == kind)
        if account:
            query = query.where(events.c.account == account)
        with engine.connect() as conn:
            rows = conn.execute(query).mappings().all()
            latest_alerts = conn.execute(select(alerts).order_by(alerts.c.timestamp.desc()).limit(30)).mappings().all()
            total = conn.execute(select(func.count()).select_from(events)).scalar()
            alert_count = conn.execute(select(func.count()).select_from(alerts)).scalar()
            demo_count = conn.execute(select(func.count()).select_from(events).where(events.c.origin == "demo")).scalar()
            health_value = conn.execute(select(checkpoints.c.value).where(checkpoints.c.name == "collector_health")).scalar()
            latest_review = select(alert_reviews.c.alert_id, func.max(alert_reviews.c.id).label("latest_id")).group_by(
                alert_reviews.c.alert_id).subquery()
            reviews = dict(conn.execute(select(alert_reviews.c.alert_id, alert_reviews.c.action).join(
                latest_review, alert_reviews.c.id == latest_review.c.latest_id)).all())
        health = json.loads(health_value) if health_value else None
        healthy = health is not None and 0 <= time.time() - health["last_poll"] < 30
        return render_template("dashboard.html", rows=rows, alerts=latest_alerts,
            total=total, alert_count=alert_count, demo_count=demo_count, health=health,
            healthy=healthy, backend=engine.dialect.name, cfg=cfg, kind=kind, account=account,
            reviews=reviews)

    @app.get("/alerts/<int:alert_id>")
    def detail(alert_id):
        with engine.connect() as conn:
            alert = conn.execute(select(alerts).where(alerts.c.id == alert_id)).mappings().first()
            if alert is None:
                abort(404)
            evidence = conn.execute(event_view().join(alert_events, events.c.id == alert_events.c.event_id).where(
                alert_events.c.alert_id == alert_id).order_by(events.c.timestamp)).mappings().all()
            policy = conn.execute(select(rule_policies).join(alert_policies).where(
                alert_policies.c.alert_id == alert_id)).mappings().first()
            history = conn.execute(select(alert_reviews, administrators.c.username).join(administrators)
                .where(alert_reviews.c.alert_id == alert_id).order_by(alert_reviews.c.id.desc())).mappings().all()
            from .inventory.schema import devices, device_events
            device_evidence = conn.execute(select(devices.c.id, devices.c.label).join(device_events)
                .join(alert_events, alert_events.c.event_id == device_events.c.event_id)
                .where(alert_events.c.alert_id == alert_id)).mappings().all()
        return render_template("alert.html", alert=alert, rows=evidence,
            policy=policy, parameters=json.loads(policy["parameters_json"]) if policy else {}, history=history,
            device_evidence=device_evidence)

    @app.post("/alerts/<int:alert_id>/review")
    def review(alert_id):
        if not g.administrator:
            abort(403)
        try:
            expected = int(request.form.get("expected_id", ""))
            with writer_lock(engine), engine.begin() as conn:
                review_alert(conn, alert_id, g.administrator["id"], request.form.get("action"),
                    request.form.get("note", ""), expected)
        except LookupError:
            abort(404)
        except (ReviewConflict, RuntimeError) as exc:
            abort(409, str(exc))
        except ValueError as exc:
            abort(400, str(exc))
        return redirect(url_for("detail", alert_id=alert_id))

    return app
