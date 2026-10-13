# Phase 2 file guide

| Path | What it does |
| --- | --- |
| `README.md` | Setup, demo, DBMS model, and assessment instructions. |
| `requirements.txt` | Python dependencies, including the MySQL client driver. |
| `.gitignore` | Excludes virtual environments, local data, caches, and secrets from Git. |
| `.env.mysql.example` | Safe template for the Kali MySQL container settings; copy it to ignored `.env.mysql`. |
| `config.example.json` | Example host, watched path, timezone, time window, and login threshold. |
| `app.py` | CLI, fixture import, Linux `ausearch` polling, schema check, and read-only Flask dashboard. |
| `kernelguard/__init__.py` | Marks the Python package. |
| `kernelguard/config.py` | Validates Phase 2 policy settings. |
| `kernelguard/core.py` | Defines eight relational tables and writes event evidence. |
| `kernelguard/rules.py` | Evaluates the two Phase 2 policies against stored evidence. |
| `kernelguard/parser.py` | Groups raw Linux Audit lines and extracts authentication, file-open, and process-launch metadata. |
| `kernelguard/locking.py` | Uses a MySQL advisory lock to coordinate one ingestion writer. |
| `kernelguard/templates/base.html` | Shared page frame and navigation. |
| `kernelguard/templates/overview.html` | Event list, filters, counts, and alert cards. |
| `kernelguard/templates/alert.html` | One alert's evidence and saved rule settings. |
| `kernelguard/static/style.css` | Dashboard layout and responsive styles. |
| `fixtures/demo.audit` | Nine synthetic raw audit events for a repeatable demo. |
| `linux/kernelguard.rules` | Linux Audit rules for protected access, file opens in home or mounted storage, and user-session process launches. |
| `sql/schema.mysql.sql` | Generated MySQL schema for review. |
| `sql/analysis.sql` | SELECT queries for grouping, evidence joins, audit details, policy history, and an EXPLAIN example. |
| `scripts/export_schema.py` | Regenerates the SQL schema from the eight Python table definitions. |
| `tests/test_app.py` | Checks parser and schema offline; optionally checks replay and dashboard against a disposable MySQL database. |
| `tests/test_rules.py` | Checks late arrivals, timestamp ties, and protected-path boundaries offline. |
| `docs/TEAM.md` | Suggested teammate speaking areas and source files. |
| `docs/CODE_PROVENANCE.md` | Records the relationship to the completed project and limits of similarity claims. |
| `docs/KALI_SETUP.md` | Runs one MySQL database in a container on Kali. |

`.venv/`, `__pycache__/`, and `.pytest_cache/` are generated locally and ignored by Git. The `data/` folder contains ignored artifacts from the earlier preview and local tests; this MySQL-only version does not use it. There are no runtime imports from the completed project.
