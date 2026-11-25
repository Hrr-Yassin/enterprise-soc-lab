# SOC-03 · Network policy and denied application export

## Executive summary

In simulation 0cee9232, Suricata identified a DNS query outside the lab allowlist and traffic to a restricted UDP port. Separately, the inventory service returned HTTP 403 to an export request by a service identity. The exercise ran on the endpoint loopback interface, with no evidence of an external transfer.

## Timeline and relevant alerts

All times are UTC on 2026-11-25. Alert times are manager timestamps.

- 17:21:41.202. Inventory export denial, rule 100100, level 8, indexed document `AD26E6IBlfn5GjgETWsA`. The application and harness agree on the denial.
- 17:21:42.988. DNS allowlist alert, rule 100107, level 7, indexed document `AT26E6IBlfn5GjgETWsA`. Suricata signature 9900101 reports the run-specific unapproved query.
- 17:21:42.998. Restricted UDP alert, rule 100108, level 8, indexed document `Aj26E6IBlfn5GjgETWsA`. Signature 9900102 reports a 127.0.0.1 flow to UDP 15941.

## Correlation and root cause

The DNS name and application record carry the run ID. The restricted UDP source and destination ports agree with the guest ledger. The harness observed a local NXDOMAIN response and a 29-byte UDP payload received by the test listener. The application denied the export. The shared endpoint and run establish exercise provenance. The evidence does not link the export to either network flow as part of a single transaction.

## Severity and ATT&CK

Low in the observed lab context. Raise priority for sensitive data access, repeated attempts or a validated external destination. DNS telemetry could support triage for T1071.004 DNS in an independent investigation with command-and-control evidence. The lab query alone does not establish that technique.

## Containment and remediation

In production, identify the process and actor, check resolver and network records, and preserve the service request context. Restrict confirmed unauthorized destinations and revoke credentials if misuse is confirmed. Review service-identity permissions and check whether any successful exports predate the denial.

## False positives and lessons

A renamed internal domain, a developer test listener or an outdated integration can explain these alerts. The approved DNS namespace, neighboring UDP port and application health request were archived controls without their target alerts. Suricata observed the traffic in passive mode. The application supplied the enforcement evidence for its own request.

Evidence references are in run 0cee9232. All three alerts were stored in `wazuh-alerts-4.x-2026.11.25`.

## Retest on 2026-11-25

Run `9007ca4b` passed all ten acceptance scenarios. Timestamps are UTC.

- 18:08:35.830. D10 export denial, rule 100100, indexed document `Wj3lE6IBlfn5GjgEMWu-`.
- 18:08:37.598. D07 DNS namespace alert, rule 100107, document `Xj3lE6IBlfn5GjgEOWsE`.
- 18:08:37.629. D08 restricted UDP alert, rule 100108, document `Xz3lE6IBlfn5GjgEOWsE`.

Two DNS control records, one UDP control and one application control reached the manager archive. None matched its target rule in the manager archive or index. [Sanitized retest evidence](../evidence/run-9007ca4b.json)
