# SOC-01 · Identity escalation signals

## Executive summary

In simulation 0cee9232, Wazuh indexed a repeated SSH failure alert and a local Administrators membership alert from labeled fixtures. A live sudo attempt by the dedicated probe user was denied and reached the manager archive. The evidence shows distinct identity signals exercised by the same run. There was no observed successful elevation or native Windows activity.

## Timeline and relevant alerts

All times are UTC on 2026-11-25. Alert times are manager timestamps.

- 17:21:39.965 guest time. The harness generated eight synthetic SSH failure records for a single account and TEST-NET source.
- 17:21:41.187. Rule 5763, level 10, indexed document `_T26E6IBlfn5GjgETWoA`.
- 17:21:41.192. Rule 100102, level 11, indexed document `_j26E6IBlfn5GjgETWoA`. The Windows Security 4732 fixture targeted SID S-1-5-32-544.
- 17:21:41.295. Auditd serial 364 recorded a failed sudo USER_CMD for a no-op command. The run recorded exit status 1 and no indexed D03 alert.

## Correlation and root cause

The run ID links the synthetic SSH account and Windows fixture, while the harness ledger and agent 001 link the live sudo denial to the same exercise. The seven-record SSH control was archived without producing rule 5763. The Windows control targeted the built-in Users group and produced no target alert. The originating cause was the exercise harness. In production, repeated failures and a membership change would warrant checking host identity, account identity and successful logons before inferring a shared actor.

## Severity and ATT&CK

Moderate triage priority under the simulated threat model. A confirmed, unauthorized administrator membership change would raise priority. The modeled behaviors are T1110.001 Password Guessing, T1098.007 Additional Local or Domain Groups, and T1548.003 Sudo and Sudo Caching. The observed sudo action failed.

## Containment and remediation

In a real incident, review the related account and source history, preserve sign-in and group-change records, and verify change approval. If an unauthorized change is confirmed, remove the added membership and revoke active sessions. Review delegation and collect native Security and Sysmon events before extending conclusions to Windows.

## False positives and lessons

Common explanations include a mistyped saved password, scheduled administrative provisioning, and missing sudo delegation. Compare against successful logons and approved changes. A decoded event can still miss its expected rule, as D03 did. Keep fixture collection and native endpoint coverage visible as separate claims.

Evidence references are in run 0cee9232. Indexed alerts were stored in `wazuh-alerts-4.x-2026.11.25`. The private archive retains the sudo and control records.

## Retest on 2026-11-25

Run `9007ca4b` passed all ten acceptance scenarios. Timestamps are UTC.

- 18:08:35.810. D01 SSH fixture, rule 5763, indexed document `Vz3lE6IBlfn5GjgEMWu-`.
- 18:08:35.819. D02 Windows Security 4732 fixture, rule 100102, document `WD3lE6IBlfn5GjgEMWu-`.
- 18:08:35.943. D03 live Auditd sudo denial, rule 100103, document `Wz3lE6IBlfn5GjgENWsS`.

The manager received seven SSH control records, one Windows group control and one successful sudo control. None matched its target rule in the manager archive or index. [Sanitized retest evidence](../evidence/run-9007ca4b.json)
