import time
import json
from flask import Blueprint, render_template, request, abort, g, redirect, url_for
from sqlalchemy import select, func
from ..core import administrators, events
from ..locking import writer_lock
from ..reviews import ReviewConflict
from .schema import users, sessions, processes, devices, snapshots, device_decisions, device_events
from .service import decide_device


# START Mohd Shoaib: inventory pages and USB enrollment routes.
def register_inventory(app, engine):
    blueprint = Blueprint("inventory", __name__)

    @blueprint.get("/inventory")
    def index():
        # START Mohd Ahmed Khan: query related inventory tables for the UI.
        kind = request.args.get("kind", "devices")
        tables = dict(devices=devices, users=users, sessions=sessions, processes=processes)
        if kind not in tables:
            abort(400)
        table = tables[kind]
        query = select(table)
        if kind == "processes":
            parent = processes.alias("observed_parent")
            query = select(processes, users.c.username.label("user_name"), users.c.uid.label("real_uid"),
                sessions.c.audit_session.label("session_number"), parent.c.pid.label("parent_pid"))
            query = query.select_from(processes.outerjoin(users, processes.c.user_id == users.c.id)
                .outerjoin(sessions, processes.c.session_id == sessions.c.id)
                .outerjoin(parent, processes.c.parent_id == parent.c.id))
        elif kind == "sessions":
            query = select(sessions, users.c.username.label("user_name"), users.c.uid.label("login_uid"))
            query = query.select_from(sessions.outerjoin(users, sessions.c.user_id == users.c.id))
        page = max(1, min(request.args.get("page", 1, type=int), 100000))
        host, origin = request.args.get("host", "")[:128], request.args.get("origin", "")
        filters = []
        if host:
            filters.append(table.c.host == host)
        if origin:
            filters.append(table.c.origin == origin)
        with engine.connect() as conn:
            rows = conn.execute(query.where(*filters).order_by(table.c.last_seen.desc(), table.c.id)
                .limit(50).offset((page - 1) * 50)).mappings().all()
            total = conn.execute(select(func.count()).select_from(table).where(*filters)).scalar()
            runs = conn.execute(select(snapshots).order_by(snapshots.c.timestamp.desc()).limit(5)).mappings().all()
            runs = [dict(row, warnings=json.loads(row["warnings_json"])) for row in runs]
        # END Mohd Ahmed Khan: inventory relationship and pagination queries.
        return render_template("inventory.html", kind=kind, rows=rows, total=total, page=page,
            host=host, origin=origin, runs=runs, now=int(time.time()))

    @blueprint.get("/devices/<identity>")
    def detail(identity):
        with engine.connect() as conn:
            device = conn.execute(select(devices).where(devices.c.id == identity)).mappings().first()
            if not device:
                abort(404)
            history = conn.execute(select(device_decisions, administrators.c.username).join(administrators)
                .where(device_decisions.c.device_id == identity).order_by(device_decisions.c.id.desc())).mappings().all()
            observations = conn.execute(select(events).join(device_events).where(
                device_events.c.device_id == identity).order_by(events.c.timestamp.desc()).limit(50)).mappings().all()
        return render_template("device.html", device=device, history=history, observations=observations)

    @blueprint.post("/devices/<identity>/enrollment")
    def enrollment(identity):
        if not g.administrator:
            abort(403)
        try:
            if request.form.get("decision") not in ("approve", "revoke"):
                raise ValueError("Choose approve or revoke")
            expected = int(request.form.get("expected_id", ""))
            with writer_lock(engine), engine.begin() as conn:
                decide_device(conn, identity, g.administrator["id"], request.form["decision"] == "approve",
                    request.form.get("note", ""), expected)
        except LookupError:
            abort(404)
        except (ReviewConflict, RuntimeError) as exc:
            abort(409, str(exc))
        except ValueError as exc:
            abort(400, str(exc))
        return redirect(url_for("inventory.detail", identity=identity))

    app.register_blueprint(blueprint)
# END Mohd Shoaib: inventory display and administrator device actions.
