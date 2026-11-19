# Threat model

## Scope and assumptions

Collect telemetry from enrolled training machines only. Keep raw captures and account identifiers in the lab and publish aggregate, approved measurements.

Use the proposed [component graph](architecture.md) as the system boundary. Assumptions and control efficacy are subject to laboratory verification.

| Threat | Trust boundary | Proposed control | Future verification |
| --- | --- | --- | --- |
| Collector spoofing | Endpoint to manager | Allowlisted agent enrollment, per-source identity, restricted ingress | Reject an unknown agent and preserve enrollment audit evidence |
| Log loss or clock drift | Sensor and indexer | Time health, sequence gaps, queue alarms | Drop a benign fixture and verify coverage degrades visibly |
| Analyst exposure | Index to dashboard | Scoped read role, redacted fields, retention controls | A restricted analyst cannot access original PCAP |
| Alert floods | Rules to case queue | Deduplication and noise thresholds | Repeated fixture produces one linked case and a volume signal |

## Residual risk and review triggers

A single Wazuh node keeps the lab affordable and creates a known single point of failure; measure backlog recovery before considering a separate indexer. Suricata gives protocol and signature context while endpoint events carry identity and process provenance. Keep Sigma translation reviewable and write native correlation only where the translation loses intent.

Revisit the model whenever the topology, identities, dataset, or deployment context changes.
