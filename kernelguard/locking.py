"""Enforce the single ingestion writer promised by this lab prototype.

Portalocker handles SQLite's OS file lock; MySQL uses a connection-owned advisory lock.
Neither mechanism locks out an administrator or an unrelated program that ignores it.
"""
from contextlib import contextmanager
from pathlib import Path
import portalocker
from sqlalchemy import text
from .core import digest


class WriterBusy(RuntimeError):
    """A cooperating writer owns the lock; a periodic collector may retry later."""


@contextmanager
def writer_lock(engine):
    if engine.dialect.name == "mysql":
        name = "kg:" + digest(engine.url.database or "")[:60]
        with engine.connect() as conn:
            acquired = conn.execute(text("SELECT GET_LOCK(:name, 0)"), {"name": name}).scalar()
            if acquired != 1:
                raise WriterBusy("Another KernelGuard writer is active for this database")
            try:
                yield
            finally:
                conn.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
        return
    database_path = engine.url.database
    if not database_path or database_path == ":memory:":
        yield  # Isolated unit-test databases do not share disk storage.
        return
    lock_path = Path(str(Path(database_path).resolve()) + ".writer.lock")
    lock = portalocker.Lock(lock_path, mode="a", timeout=0)
    try:
        lock.acquire()
    except portalocker.exceptions.LockException as exc:
        raise WriterBusy("Another KernelGuard writer is active") from exc
    except OSError as exc:
        raise RuntimeError("The OS writer lock is unavailable") from exc
    try:
        yield
    finally:
        lock.release()
