# Mohd Ahmed Khan

Role: **Database, persistence and integration developer**

## Primary files

| File | Assigned responsibility |
| --- | --- |
| `kernelguard/core.py` | Define the main relational schema, transactions, event deduplication and evidence relationships. |
| `kernelguard/inventory/schema.py` | Define normalized user, session, process, USB and decision tables. |
| `kernelguard/inventory/service.py` | Store snapshots atomically and maintain device/presence history. |
| `kernelguard/__main__.py` | Integrate database initialization, imports, collectors, demo and web commands. |
| `sql/schema.mysql.sql` | Provide the generated MySQL/InnoDB schema. |
| `sql/analysis.sql` | Provide relational queries for project analysis. |
| `scripts/export_schema.py` | Generate the MySQL schema from application metadata. |
| `tests/test_mysql.py` | Verify the opt-in MySQL transaction and schema behavior. |
| `tests/test_concepts.py` | Verify database constraints, deduplication and OS/DBMS concepts. |

## Shared files

| File | Ahmed's section |
| --- | --- |
| `kernelguard/locking.py` | Database writer-lock integration. Primary collector owner: Arshpreet. |
| `kernelguard/inventory/models.py` | Snapshot contract consumed by persistence. Primary validation owner: Arshpreet. |
| `kernelguard/inventory/routes.py` | Queries that supply inventory screens. Primary UI owner: Shoaib. |
| `kernelguard/activity_rules.py` | Transactional creation of alert/evidence relationships. Primary rule owner: Ankit. |
| `tests/test_inventory.py` | Snapshot rollback, relationships and stored device history. Shared with Arshpreet and Shoaib. |
| `config.example.json` | Database-independent configuration integration. Shared with Arshpreet and Ankit. |
| `docs/ARCHITECTURE.md` | DBMS relationships, keys, transactions and normalization. Team-level file. |
| `docs/ACCEPTANCE.md` | MySQL acceptance and rollback evidence. Team-level file. |

## What Ahmed should explain

- Primary keys, foreign keys, indexes and join tables.
- Atomic transactions and rollback.
- Event and snapshot deduplication.
- SQLite versus MySQL use in the project.
- Inventory persistence, device history and full-module integration.
