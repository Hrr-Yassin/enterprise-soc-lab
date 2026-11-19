# Technical design

**Phase 0 specification**

Sign off a field mapping before rule deployment. Keep event time, receive time, source host, source record ID, user, event class and a raw-record pointer. Deduplicate on source identity and record ID, with a bounded time window if IDs reset. Quarantine unsupported schemas. Keep raw events restricted and project redacted fields for routine triage. Correlate host/account/time across sources with a late-event tolerance of two minutes. Separate alert severity from case priority by evaluating confidence, scope and asset criticality. For every case, preserve an evidence timeline, competing explanations, disposition, owner and escalation reason. Use dashboards for ingestion health, rule noise, and open cases. Respond with tabletop containment and recovery approvals; never automatically isolate a host.

## Detection catalogue for future validation

| ID | Signal | Scenario | Negative control |
| --- | --- | --- | --- |
| D01 | Repeated Windows sign-in failures, Security 4625 | S1 | One mistyped password |
| D02 | Windows success after failures for same account, 4624 after 4625 | S1 | Success for different account |
| D03 | Security-enabled group membership change, Security 4728 or 4732 | S1 | Routine login without change |
| D04 | Windows service installation event, System 7045 | S2 | Existing service restart |
| D05 | Unusual lab parent/child process pairing, Sysmon 1 | S2 | Documented baseline pair |
| D06 | Scheduled task creation, Security 4698 when audit enabled | S2 | Read of task status |
| D07 | DNS burst per client from Suricata EVE | S3 | Steady resolver baseline |
| D08 | Unexpected internal connection fan-out from EVE flows | S3 | Approved health check |
| D09 | Auditd write to monitored lab policy file | S4 | Read-only policy review |
| D10 | Source heartbeat absent after two intervals | S5 | Arrival within jitter budget |

Calibrate with ground-truth fixture labels and annotate applicable ATT&CK techniques only where behavior supports the mapping. Log source coverage gaps separately from detector false negatives.

## Technology rationale

Wazuh integrates agent enrollment, a manager, indexer and dashboard for a compact SOC. Suricata contributes EVE JSON network metadata. Sysmon and Windows Security channels capture complementary process and identity events; Linux Auditd supplies syscall-derived records. Sigma expresses detection intent portable across backends, but mappings and rule semantics must be tested in Wazuh. Wireshark is reserved for manual packet review and Python for fixture normalization and metrics. KVM/QEMU provides isolated, reproducible endpoints.

See [acceptance criteria](testing-strategy.md) and [authoritative references](references.md).

## Operations and evidence contracts

| Contract | Fields and behavior |
| --- | --- |
| Source registration | Asset ID, source type, expected cadence, enabled channels, clock health and approved ingest route. Test heartbeat after enrollment. |
| Alert | Rule ID and version, grouped event IDs, time window, confidence, reason, asset priority, eligibility for triage. Preserve the events even when the alert is suppressed. |
| Hunt | Hypothesis, data sources, date range, query version, exclusions, results and limits. Convert a repeatable validated observation into a rule candidate. |
| Incident | Owner, affected systems, canonical UTC timeline, decision log and action approvals. Record recovery verification and handover. |

### Playbooks

For a suspected identity incident, confirm asset/account ownership, compare ordinary login context, preserve related endpoint and network observations, escalate on corroborated spread, and obtain authorization for containment. For telemetry silence, verify heartbeat, clock and queue state before classifying severity. Restore ingestion and reconcile the missing time range against the source records. Record false-positive rationale and rule follow-up in both playbooks.
