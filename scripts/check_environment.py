"""Readiness report; reports missing lab requirements without modifying the host."""
import importlib.util
import json
import os
import platform
import shutil
from sqlalchemy import text
from kernelguard.core import database


def main():
    checks = dict(linux=platform.system() == "Linux", ausearch=bool(shutil.which("ausearch")),
        pyudev=importlib.util.find_spec("pyudev") is not None,
        mysql_test_configured=bool(os.environ.get("KERNELGUARD_TEST_MYSQL_URL")))
    url = os.environ.get("KERNELGUARD_DB_URL")
    checks["mysql_connected"] = False
    if url:
        engine = database(url)
        try:
            with engine.connect() as conn:
                checks["mysql_connected"] = engine.dialect.name == "mysql" and conn.execute(text("SELECT 1")).scalar() == 1
        except Exception:
            checks["database_error"] = "Connection failed; inspect configuration locally (credentials omitted)"
        finally:
            engine.dispose()
    print(json.dumps({"checks": checks, "ready_for_lab_acceptance": all(checks.values()),
        "note": "Readiness only; successful checks do not prove audit capture or USB detection. See docs/ACCEPTANCE.md."}, indent=2))
    raise SystemExit(0 if all(checks.values()) else 2)


if __name__ == "__main__":
    main()
