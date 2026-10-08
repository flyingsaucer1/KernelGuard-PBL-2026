-- Event counts by account and type (MySQL).
SELECT host, origin, account, kind, COUNT(*) AS event_count
FROM events GROUP BY host, origin, account, kind ORDER BY event_count DESC;

-- Explain the oldest available alert using its original event metadata.
SELECT a.id, a.rule, a.score, a.reason, e.timestamp, e.account,
       e.resource, e.executable, e.outcome, e.source_id
FROM alerts a
JOIN alert_events ae ON ae.alert_id = a.id
JOIN events e ON e.id = ae.event_id
WHERE a.id = (SELECT id FROM alerts ORDER BY id LIMIT 1)
ORDER BY e.timestamp;

-- Events and alerts are inserted atomically by the Python transaction.
-- Failed authentication summaries (timestamp is UTC Unix seconds).
SELECT host, origin, account, COUNT(*) AS failures, MIN(timestamp) AS first_seen,
       MAX(timestamp) AS last_seen
FROM events WHERE kind = 'login_failure'
GROUP BY host, origin, account;

-- Canonical OS evidence: do not confuse the login identity with current privilege.
SELECT e.id, e.account, d.login_uid, d.real_uid, d.effective_uid,
       d.session_id, d.syscall, d.architecture, d.inode, d.device
FROM events e JOIN audit_details d ON d.event_id = e.id
ORDER BY e.timestamp;

-- Historical policy settings; old alerts without snapshots remain visible via LEFT JOIN.
SELECT a.id, a.rule, p.rule_code, p.version, p.parameters_json
FROM alerts a
LEFT JOIN alert_policies ap ON ap.alert_id = a.id
LEFT JOIN rule_policies p ON p.id = ap.policy_id
ORDER BY a.id;

-- MySQL EXPLAIN example. Inspect the chosen key and estimated rows on your lab data.
-- Small fixture tables may legitimately use a full scan; do not claim an index was used
-- without examining actual EXPLAIN output.
EXPLAIN SELECT id, timestamp FROM events
WHERE host = 'kernelguard-lab' AND account = 'testuser'
  AND kind = 'login_failure' AND origin = 'live'
  AND timestamp BETWEEN 1788868800 AND 1788869100;
