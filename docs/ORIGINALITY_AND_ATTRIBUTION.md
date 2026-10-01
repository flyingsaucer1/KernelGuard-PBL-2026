# Originality and attribution record

## What can be established

The application was generated and revised in this workspace with AI assistance for
the KernelGuard proposal. No third-party project repository was imported during
these sessions. Official documentation was consulted for Linux Audit fields,
checkpoint behavior, Flask, SQLAlchemy, and MySQL. The fixture and project-specific
rules were created here.

This is a provenance statement about the visible development session, **not a
plagiarism certificate**. No institutional similarity checker, private assignment
corpus, or comprehensive public-code comparison was run. No similarity percentage
is claimed. Common Python, SQL, Flask and HTML patterns can resemble other programs
without establishing copied authorship.

The review prioritizes understandable project-specific behavior, documented design
decisions, references, and tests. Renaming variables or disguising standard algorithms
would not establish independent authorship. Do not claim that every line was written
unaided by the students. Follow the college's actual policy on disclosing AI assistance.

## Project contribution versus reused technology

| Area | KernelGuard's contribution | Reused foundation |
|---|---|---|
| Collection | Scoped rule, polling and atomic checkpoint workflow | Linux kernel auditing, auditd, ausearch |
| Parsing | Selected event format, identity handling and metadata filtering | Documented Linux Audit record format |
| Detection | Configurable thresholds, distinct evidence episodes, after-hours policy | Standard comparisons and SQL queries |
| Database | Event/evidence schema, policy snapshots and storage integration | SQLAlchemy, SQLite/MySQL engines, PyMySQL |
| Dashboard | Project views, filters and evidence presentation | Flask/Jinja, HTML and CSS |
| Verification | Synthetic scenarios and project regression tests | pytest and Python standard library |
| Configuration | Project fields, allowed ranges and cross-field rules | Pydantic strict validation |
| Writer locking | Database-specific lock selection and failure handling | Portalocker OS locks and MySQL named locks |
| Host inventory | Boot/process identities, snapshot transitions, USB enrollment | psutil, pyudev, pwd and procfs |
| Administrator workflows | Review/enrollment contracts and history | Flask sessions, Werkzeug password hashes |
| Serving | Local runtime configuration | Waitress |

The project does not implement SQL transactions, a relational engine, a kernel audit
subsystem, or a web framework from scratch. It combines those facilities to make a
small monitoring workflow that can be explained and tested.

## References

- [Red Hat: understanding audit log files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files): meaning of SYSCALL, PATH, auid, uid and euid.
- [Linux Audit: ausearch manual](https://man7.org/linux/man-pages/man8/ausearch.8.html): complete events, checkpoints and failure statuses.
- [SQLAlchemy: engines and connections](https://docs.sqlalchemy.org/en/20/core/connections.html): connection and transaction APIs.
- [SQLAlchemy: MySQL dialect](https://docs.sqlalchemy.org/en/20/dialects/mysql.html): MySQL/PyMySQL integration and table options.
- [MySQL: foreign keys](https://dev.mysql.com/doc/refman/8.4/en/create-table-foreign-keys.html): referential integrity behavior.
- [MySQL: locking functions](https://dev.mysql.com/doc/refman/8.4/en/locking-functions.html): connection-owned advisory locks.
- [Flask documentation](https://flask.palletsprojects.com/en/stable/): routing, templates and application runtime.
- [Pydantic strict validation](https://docs.pydantic.dev/latest/concepts/strict_mode/): reject wrong types and validate declared fields.
- [Portalocker API](https://portalocker.readthedocs.io/en/latest/api/portalocker.html): portable exclusive file locking and release.

These are technical references, not claims that the application's text or algorithms
are novel research. Keep installed dependency license notices intact. Dependency source
is external code: exclude `.venv`, generated caches, and database files from the student
source submission unless the examiner specifically asks for them. Submit `requirements.txt`
so the dependencies can be installed separately.

## Suggested acknowledgement

“KernelGuard was developed with AI assistance for initial implementation and review.
The system uses Linux Audit, Flask, SQLAlchemy and MySQL. The team is responsible for
understanding, adapting and validating the submitted system. Technical references are
listed in the documentation.”

Adapt this statement only to describe work that your team actually performs. Keep
your own lab results, commits, design notes and explanations as the project develops.
