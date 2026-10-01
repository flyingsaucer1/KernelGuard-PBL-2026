# Evaluation

Run `python -m scripts.evaluate` to regenerate [evaluation.json](evaluation.json).
The script creates a temporary database, evaluates hand-authored positive/negative
policy scenarios and times synthetic audit ingestion. It does not alter the demo database.

The current run matched **11/11 expected policy outcomes**. Its 500-event disk-backed
SQLite sample created 100 alerts in approximately **0.480 seconds** (about **1,043
events/second**). This uses one transaction and independent synthetic host groups;
it excludes source collection, process/USB enumeration, web rendering and setup.
Timings vary by computer, cache and workload. They are not production capacity claims.

Coverage includes threshold negatives, repeated-path negatives, allowed-hours reads,
privilege negatives and unenrolled USB observations. Regression tests additionally
cover boot/PID reuse, replay, partial inventories, relationship integrity, rollbacks,
source isolation, CSRF and stale administrator decisions.

## False-positive analysis

Two legitimate scenarios intentionally match existing policy: an authorized backup
reading ten distinct protected files, and authorized use of a selected privileged
command. The report ties these observations to the corresponding measured policy cases.
Acknowledgement and saved policy explanations support review of these cases.

The sample is too small and artificial to estimate operational false-positive rates,
precision or recall. No field security accuracy is claimed. A defensible field
evaluation needs independently labelled activity from the authorized Linux lab,
including ordinary work and simulated violations, with the configuration fixed
before scoring. Keep that real-lab evidence alongside the acceptance report.
