# Technical interview preparation

## Architecture and operations

### 1. What runs in Podman, and what runs in the guest?

Rootless Podman runs Wazuh Manager with Filebeat, one Wazuh Indexer, and Wazuh Dashboard. The dedicated Debian 12 QEMU/KVM guest runs the Wazuh agent, Auditd, rsyslog, the passive Suricata sensor, and the lab application. The manager decodes and evaluates events, Filebeat ships alerts to the indexer, and the dashboard reads those alerts and queries the manager API for agent status. [Architecture and data flow](architecture.md)

### 2. How does the lab limit network exposure?

The management containers share an internal Podman network. Fedora publishes dashboard HTTPS, the agent relay, and SSH to the dedicated guest on loopback. The indexer and manager API stay inside the project network. Normal guest operation uses restricted QEMU networking. Provisioning uses a temporary allowlisted HTTPS package relay. [Architecture and listeners](architecture.md)

### 3. How are TLS trust and agent enrollment handled?

Initialization creates a private CA and service certificates. Service connections verify the intended name against that CA. The Debian agent uses an individually issued enrollment key, and the health check verifies that the remote enrollment listener is absent. Generated credentials, private keys, and raw evidence stay in ignored local directories. [Security boundaries](../SECURITY.md) · [Deployment guide](deployment.md) · [Health checks](../scripts/health.py)

### 4. Why use a single indexer, and what did yellow health mean?

One indexer kept the memory and storage footprint within the Fedora host's budget. The verified deployment had 12 started primary shards and three unassigned replica shards. Primaries served queries, and loss of the one host would still interrupt the whole lab. Resource measurements qualify the result as a single-host exercise. [Architecture decision](adr-001-deployment.md) · [Resource measurements](resources.md)

### 5. How would you reproduce the deployment on another compatible host?

Run the documented Fedora preflight, initialize the private PKI and credentials, and start the digest-pinned Podman services. Prepare the checksum-verified Debian image, provision it in bootstrap mode, start it in isolated mode, and enroll the agent. Run the health, acceptance, native replay, and dashboard checks in that order. The retained evidence comes from the original Fedora host. [Deployment and reproduction](deployment.md) · [Pinned images](../config/central-images.env)

### 6. How can a ruleset update fail safely?

The lifecycle script stages a candidate and tests it with Wazuh analysisd before publishing the same bytes. If the manager restart fails, the script restores the previous rules and attempts a recovery restart. The operator then checks service health and agent readiness. The automated suite exercises a rejected candidate, a changed source file, and a failed restart. [Reload implementation](../scripts/soc.sh) · [Lifecycle tests](../tests/test_soc_lifecycle.py)

## Detection and validation

### 7. What makes a scenario pass the acceptance runner?

The runner requires an indexed positive from the expected agent and rule, attributable to the intended action. It also requires receipt of the defined control records in the manager archive and a settled index check. A matching target in the controls or an unattributed indexed target fails the scenario. Run `9007ca4b` verified 10 of 10 scenarios, with ten indexed positives and zero target matches from controls. [Validation strategy](testing-strategy.md) · [Accepted evidence](evidence/run-9007ca4b.json)

### 8. How do you verify a negative control when indexing is delayed?

An absent indexed alert is only interpretable after the manager archive confirms that the control arrived. The runner checks receipt and target matches in the archive and checks the index across both phases. It also rejects partial, timed-out, or failed-shard searches. A late indexed target or a manager target that is missing from the index still fails the check. [Acceptance runner](../scripts/run_scenarios.py) · [Acceptance tests](../tests/test_run_scenarios.py)

### 9. What does native Logtest establish alongside the acceptance run?

The six Wazuh Logtest cases use the archived positive and control record for each of D03, D05, and D09. All six verified the expected decoder and target outcome. The end-to-end run provides separate evidence for actual collection, manager receipt, Filebeat delivery, and index search. [Native replay evidence](evidence/logtest-9007ca4b.json) · [Accepted evidence](evidence/run-9007ca4b.json)

### 10. Why did D01 use seven and eight SSH failures?

The exercise used labeled syslog fixtures to test stock rule 5763. Eight failures from one source reached the target correlation threshold, while the seven-record control used a separate source. Both streams reached the manager. Shared NAT can group unrelated users, and distributed attempts can evade a per-source threshold. Production triage would check the source, affected accounts, and any subsequent successful logons. [D01 coverage and threshold](detection-coverage.md) · [Identity investigation](incidents/01-identity.md)

### 11. What do the Windows fixtures prove, and what is still open?

D02 sent a labeled Windows Security 4732-shaped event and tested the local Administrators group SID. D06 sent a labeled Sysmon ProcessCreate-shaped event and tested a program path directly under the Public profile. The records traveled through the Debian agent and produced the expected fixture alerts. Native Windows EventChannel collection, actual Sysmon event generation, enrollment, and candidate native rules still need acceptance on a dedicated licensed Windows guest. [Windows onboarding](../endpoints/windows/README.md) · [Detection coverage](detection-coverage.md)

### 12. How did you validate D03, the sudo denial?

Rule 100103 matches a failed Auditd `USER_CMD` for the sudo executable. The exercise produced a benign denied command and an authorized no-op control. The native replay decoded both as Auditd. The denial matched 100103, and the authorized command reached the generic Auditd rule without the target alert. [Rule definition](../detections/rules.xml) · [Native replay](evidence/logtest-9007ca4b.json)

### 13. How do FIM and Auditd complement each other?

D04's FIM alert describes a change to the monitored inventory file, including hashes and a diff. D09 uses a successful audited syscall, a watch key and a path to attribute a policy-file change to a process. These are separate files in the exercise. I use FIM to establish what changed, then seek audit evidence and an approved baseline to determine how the operation occurred and whether it was expected. [Integrity investigation](incidents/02-integrity.md)

### 14. What boundary does D05 detect?

Rule 100105 detects a lab-scoped transient systemd service start outside the approved inventory naming convention. The negative control starts an approved inventory job. The accepted positive was a no-op transient service that deactivated successfully. A production investigation would verify the unit contents, initiator, authorization, and ability to recur before inferring persistence. [Rule definition](../detections/rules.xml) · [Integrity investigation](incidents/02-integrity.md)

### 15. What caused the original D09 rule miss?

The first native replay decoded the policy-file write but selected stock rule 92600 for a Python process. Rule 100109 now inherits from both 80700 and 92600 and still requires a successful syscall, the exact audit watch key, and the exact policy path. The retest indexed the intended rule. A separately watched control write proved reception through Auditd and produced no target match. [Rule definition](../detections/rules.xml) · [Native replay](evidence/logtest-9007ca4b.json)

### 16. How does a Suricata event travel from packet to investigation?

For D07, a lab DNS query on the guest loopback interface matched Suricata signature 9900101. The Wazuh agent forwarded the EVE JSON, rule 100107 matched the signature ID, and Filebeat shipped the alert to the indexer. I used its indexed document and timestamp to build the case timeline. The sensor's scope is the guest loopback interface, with passive visibility over the test traffic there. [Sensor rules](../endpoints/linux/sensor.rules) · [Network and application investigation](incidents/03-network-policy.md)

### 17. What evidence shows that the application denied access?

In D10, the test application logged a denied inventory export for a service identity. Rule 100100 requires the inventory service, export action, service actor type, and deny decision. The same identity's health request was the control. Suricata supplied network observations in the same run. The application decision record supplies the enforcement evidence for the export request. [Rule definition](../detections/rules.xml) · [Network and application investigation](incidents/03-network-policy.md)

## Investigation and evidence

### 18. How would you prioritize the identity investigation?

I would begin at moderate triage priority in the simulated scope. The SSH burst and group change came from fixtures, and the live sudo attempt failed. The timeline connects them to one exercise. In production, a verified unauthorized administrator membership change or successful escalation would raise priority. I would preserve the account and group-change records and check approved changes and successful logons. [Identity investigation](incidents/01-identity.md)

### 19. What can you infer from the network case?

Suricata observed the disallowed DNS namespace and restricted UDP destination in the lab. The listener received the test datagram, and the application separately denied an export. The run markers and guest ledger assign those records to the exercise. A claim of exfiltration, command and control, or one transaction spanning those events would require additional supporting evidence. [Network and application investigation](incidents/03-network-policy.md)

### 20. What can the test count and measured latency support?

The 25 automated tests cover local configuration, lifecycle, and acceptance safeguards. The Fedora run, native replay, and dashboard captures verify the running lab. Its recorded p95 was about three seconds from guest action to manager alert time after clock adjustment. The index check verified later retrieval. One run provides no sustained capacity or production false-positive estimate. [CI workflow](../.github/workflows/validate.yml) · [Accepted evidence](evidence/run-9007ca4b.json) · [Validation limits](testing-strategy.md)
