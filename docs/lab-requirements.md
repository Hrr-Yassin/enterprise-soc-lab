# Laboratory requirements

Starting estimate: 8 logical cores, 24 GB RAM and 160 GB SSD. Budget 8 GB for central Wazuh, 6 GB for Windows, 2 GB each for Linux and sensor, with remaining headroom for host and analyst. Set ingestion quotas and a seven-day fixture retention ceiling. Acquire legitimate OS images, KVM snapshots and a private virtual switch.

## Setup decisions before implementation

Run two KVM networks: an endpoint segment for Windows and Linux, and a restricted management segment for the Wazuh manager/indexer/dashboard and analyst workstation. Mirror the endpoint segment to Suricata through a receive-only capture path. Agents and the sensor can reach only the collector ingress. Restrict the dashboard and indexer to management access. Use private time synchronization and an explicitly bounded update window. Document that intra-host traffic invisible to the mirror is an expected coverage gap.

## Release boundaries

Collect telemetry from enrolled training machines only. Keep raw captures and account identifiers in the lab and publish aggregate, approved measurements.

Check available CPU, memory, storage, version compatibility and approval before provisioning. Record actual allocations in the first validated run.
