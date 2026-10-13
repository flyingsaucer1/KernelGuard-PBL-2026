# Code provenance and similarity

This folder is a Phase 2 presentation copy reconstructed from the team's completed
KernelGuard project. It shares the same problem, audit event format, relational
schema, rule names, and fixtures. Those similarities are intentional and should be
disclosed when submitting or presenting the work. This folder is not a historical
snapshot of an earlier submission.

The `docs/TEAM.md` map gives areas for teammates to explain. It is not evidence
that a specific person wrote every line in a listed file. Preserve the team's
actual contribution history and credit any external code, examples, or guidance
used during development. Library calls and MySQL/Linux Audit syntax should be
explained through their documentation rather than claimed as original inventions.

The rule evaluator in `kernelguard/rules.py` uses one ordered evidence query for
each incoming login event and evaluates timestamp buckets in memory. This replaced
the repeated per-window database queries previously embedded in `core.py`. The
change improves separation of storage and policy logic and handles timestamp ties
explicitly. `tests/test_rules.py` checks late arrivals and protected-path limits.
The audit parser now builds a shared event envelope and separates authentication,
syscall, and path handling. Its output was compared with the earlier presentation
copy on the nine-event fixture and remained identical.

Refactoring does not certify a similarity percentage or remove the need to cite
borrowed material. If a checker identifies a particular external match, review that
source and the corresponding lines before making any further changes.
