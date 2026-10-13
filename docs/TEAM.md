# Phase 2 team presentation map

This map adapts the responsibility areas recorded in the completed project's contribution documents. Several files were integrated or rewritten later. Use your team's actual work history for personal authorship claims.

| Teammate | Area to demonstrate | Files in this standalone copy |
| --- | --- | --- |
| Arshpreet Singh | Linux Audit rule, metadata parsing, collector checkpoint and writer coordination | `linux/kernelguard.rules`, `kernelguard/parser.py`, `kernelguard/locking.py`, collector section of `app.py` |
| Mohd Ahmed Khan | Relational schema, transactions, event identity, foreign keys and SQL analysis | `kernelguard/core.py`, `sql/schema.mysql.sql`, `sql/analysis.sql`, `scripts/export_schema.py` |
| Ankit | Failed-login and after-hours policies, synthetic evidence and repeatable checks | `kernelguard/rules.py`, `fixtures/demo.audit`, `tests/test_app.py`, `tests/test_rules.py` |
| Mohd Shoaib | Read-only alert dashboard, filters and evidence pages | Dashboard section of `app.py`, `kernelguard/templates/base.html`, `kernelguard/templates/overview.html`, `kernelguard/templates/alert.html`, `kernelguard/static/style.css` |

`app.py`, the project README, configuration, and packaging are shared integration material for the presentation copy. One physical file can support more than one teammate's explanation.
