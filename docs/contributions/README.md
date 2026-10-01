# Team file ownership

This directory groups KernelGuard files by the member currently assigned to explain,
test and maintain them. It is an **allocation record**, not proof of authorship or a
replacement for Git history.

The working source files stay in their functional directories (`kernelguard/`,
`tests/`, `linux/`, and so on). Moving them into member-named folders would break
Python imports, templates, service paths and tests.

## Members

| Member | Main responsibility | File list |
| --- | --- | --- |
| Arshpreet Singh | Linux audit and host-data collection | [ARSHPREET.md](ARSHPREET.md) |
| Mohd Ahmed Khan | Database, persistence and integration | [AHMED.md](AHMED.md) |
| Ankit | Detection rules and evaluation | [ANKIT.md](ANKIT.md) |
| Mohd Shoaib | Dashboard, authentication and review workflow | [SHOAIB.md](SHOAIB.md) |

## Shared-file rule

Some files connect several modules. Their primary maintainer is listed first, followed
by the members who must understand the relevant section. A shared file should appear
in only one member's **primary files** list, but it may appear in other members'
**shared files** list.

The following files are team-level integration material:

- `README.md`
- `requirements.txt`
- `.gitignore`
- `kernelguard/__init__.py`
- `docs/ARCHITECTURE.md`
- `docs/ACCEPTANCE.md`
- `docs/ORIGINALITY_AND_ATTRIBUTION.md`

Each member should commit only work they actually completed and should be able to
explain every file listed under their name.
