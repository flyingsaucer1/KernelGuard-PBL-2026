# Ankit

Role: **Detection-rule and evaluation developer**

## Primary files

| File | Assigned responsibility |
| --- | --- |
| `kernelguard/activity_rules.py` | Detect bulk distinct-path activity and selected privileged commands. |
| `kernelguard/demo.py` | Generate additional deterministic synthetic activity scenarios. |
| `fixtures/demo.audit` | Provide baseline audit evidence for repeatable tests and demonstrations. |
| `linux/privileged-execution.rules` | Capture selected root-effective executions without storing command arguments in the app. |
| `scripts/evaluate.py` | Evaluate positive/negative policy cases and bounded ingestion performance. |
| `scripts/make_fixture.py` | Support construction of controlled synthetic fixture data. |
| `tests/test_pipeline.py` | Test failed-login, after-hours, parsing, replay and evidence behavior. |
| `docs/EVALUATION.md` | Explain policy results, limits and false-positive examples. |
| `docs/evaluation.json` | Store the reproducible evaluation output. |

## Shared files

| File | Ankit's section |
| --- | --- |
| `kernelguard/core.py` | Failed-login and after-hours detection functions. Primary schema owner: Ahmed. |
| `kernelguard/inventory/service.py` | Unknown/unapproved USB alert decision. Primary persistence owner: Ahmed. |
| `config.example.json` | Thresholds, allowed hours, windows and selected executables. Shared with Arshpreet and Ahmed. |
| `tests/test_activity_reviews.py` | Activity-rule assertions; review workflow is owned by Shoaib. |
| `tests/test_inventory.py` | USB alert scenarios; collection/storage sections are shared with Arshpreet and Ahmed. |
| `docs/ACCEPTANCE.md` | Safe rule-trigger demonstrations and expected evidence. Team-level file. |

## What Ankit should explain

- The five detection rules and their thresholds.
- Distinct-path counting versus repeated access to one path.
- Login identity versus effective root privilege.
- Why alerts indicate policy matches rather than confirmed attacks.
- False positives, negative cases and the limits of synthetic evaluation.
