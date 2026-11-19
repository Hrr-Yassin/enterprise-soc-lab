# Future testing and acceptance

All results are pending implementation. The following criteria are proposed for a controlled educational environment.

Use five controlled scenarios built from labeled benign activity and fixture logs: S1 approved support-account sign-in sequence, S2 monitored service/job change, S3 synthetic DNS and connection burst, S4 test policy-file change, and S5 simulated telemetry interruption. Record negative controls from normal admin/backup operations. Future target: at least 95% event coverage (indexed expected records / emitted expected records), p95 event-to-alert latency ≤60 seconds at a documented ingest rate, and ≤2% false-positive test windows (alerted benign windows / all benign windows). Score each investigation 0–2 for timeline, provenance, competing explanation, scope and response rationale. Target ≥8/10 per scenario. Record clock skew and report sample counts and dropped data alongside metrics.

## Control checks

| Control objective | Check and expected behavior |
| --- | --- |
| Collector spoofing | Reject an unknown agent and preserve enrollment audit evidence |
| Log loss or clock drift | Drop a benign fixture and verify coverage degrades visibly |
| Analyst exposure | A restricted analyst cannot access original PCAP |
| Alert floods | Repeated fixture produces one linked case and a volume signal |

## Evidence and disposition

Use the [structured evidence template](../templates/detection-review.md). Record fixture or revision, operator, expected and observed outcomes, timestamps, and supporting evidence. Use pass, fail, blocked or unexecuted and preserve the first result on retest.
