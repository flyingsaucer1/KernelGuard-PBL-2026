"""Append-only review history, serialized with other cooperating database writers."""
import time
from sqlalchemy import select
from .core import alerts, alert_reviews


class ReviewConflict(ValueError):
    pass


def review_alert(conn, alert_id, administrator_id, action, note, expected_id):
    if action not in ("acknowledge", "reopen") or not 1 <= len(note.strip()) <= 1000:
        raise ValueError("Choose acknowledge/reopen and enter a note of 1–1000 characters")
    if conn.execute(select(alerts.c.id).where(alerts.c.id == alert_id)).scalar() is None:
        raise LookupError("Alert not found")
    latest = conn.execute(select(alert_reviews).where(alert_reviews.c.alert_id == alert_id)
        .order_by(alert_reviews.c.id.desc()).limit(1)).mappings().first()
    if (latest["id"] if latest else 0) != expected_id:
        raise ReviewConflict("Another review was saved. Reload before submitting again")
    previous = latest["action"] if latest else "reopen"
    if action == previous:
        raise ReviewConflict("The alert already has that review status")
    conn.execute(alert_reviews.insert().values(alert_id=alert_id,
        administrator_id=administrator_id, action=action, note=note.strip(), timestamp=int(time.time())))
