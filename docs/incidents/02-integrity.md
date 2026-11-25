# SOC-02 · Monitored file and service changes

## Executive summary

Simulation 0cee9232 produced an indexed alert for editing the monitored inventory file. The same exercise generated a transient service start and a policy-file write. Both reached the manager archive, and the initial run missed their expected alerts.

## Timeline and relevant alerts

All times are UTC on 2026-11-25. Guest and manager clocks differed by approximately 0.58 seconds during the run.

- 17:21:39.986 guest time. The harness edited the inventory file. At 17:21:40.826 manager time, rule 100104, level 9, indexed document `7z26E6IBlfn5GjgETGr_`.
- 17:21:40 guest syslog time. Systemd reported that the run-specific sandbox service started and deactivated successfully.
- 17:21:40.036 guest audit time. Audit serial 370 reported a successful `openat` under watch key `soc_policy_change` with the monitored service policy in its PATH record.

## Correlation and root cause

The FIM diff contains the run marker. The file changed from 9 to 29 bytes and the SHA-256 digest changed from prefix `4b654bd14370` to `06b1ac25327a`. The service unit and Auditd process arguments carry the same run marker. Auditd attributes the policy operation to a Python process in the exercise, while FIM describes the inventory file contents. The harness wrote a policy comment and retained the disabled export setting. The inventory fixture edit, separate policy write and no-op service were controlled exercise actions.

## Severity and ATT&CK

Moderate if unexplained. An unauthorized policy change granting access or a durable privileged service would increase severity. T1543.002 Systemd Service describes the modeled technique. This unit was transient, and the record shows successful deactivation. The generic FIM change alone is insufficient to assign an ATT&CK technique.

## Containment and remediation

In production, preserve service configuration, Auditd records and the affected files before altering them. Disable a confirmed unauthorized service and restore affected configuration from a reviewed baseline. Verify ownership, hashes, effective settings and service state after restoration. Tune and retest the missed service and audit detections against real telemetry.

## False positives and lessons

Deployment tools, scheduled jobs and approved permissions maintenance can generate these signals. The notes-file change and the inventory job were observed controls without their target alerts. The original D09 read was source-only evidence. Combine FIM with syscall and service context before inferring persistence.

Evidence references are in run 0cee9232. The FIM alert was stored in `wazuh-alerts-4.x-2026.11.25`. Systemd and Auditd records are retained in the private manager archive.

## Retest on 2026-11-25

Run `9007ca4b` passed all ten acceptance scenarios. Timestamps are UTC.

- 18:08:35.453. D04 FIM change, rule 100104, indexed document `ST3lE6IBlfn5GjgEMWu9`.
- 18:08:35.744. D05 systemd service start, rule 100105, document `Tj3lE6IBlfn5GjgEMWu9`.
- 18:08:35.977. D09 Auditd policy write, rule 100109, document `XD3lE6IBlfn5GjgENWsS`.

The archive recorded the notes-file change, approved job start and separately watched control-file write. None matched its target rule in the manager archive or index. [Sanitized retest evidence](../evidence/run-9007ca4b.json)
