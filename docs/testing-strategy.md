# Validation strategy

The exercise uses explicit positives and negative controls on one dedicated Linux guest. Windows-shaped records are labeled and travel through the Linux agent's replay file. The native Windows EventChannel and Sysmon installation need their own acceptance run on a dedicated Windows endpoint.

~~~mermaid
flowchart LR
  A["Action or labeled fixture"] --> B["Guest record"]
  B --> C["Wazuh manager archive"]
  C --> D["Rule match"]
  D --> E["Filebeat and index"]
  E --> F["Dashboard and investigation"]
  B --> G["Independent control ledger"]
  C --> H["No matching control alert"]
  G --> H
~~~

| Gate | Evidence |
| --- | --- |
| Static config | Parse tracked XML, check rule IDs and sensor references, and syntax check scripts. |
| Certificate and initialization | Verify strict X.509 chains, certificate names, credential modes, and reinitialization behavior. |
| Backend and agent | Wazuh analysisd config test, authenticated green/yellow single-node cluster health, dashboard HTTPS and active Linux agent. |
| Alerts | Require a complete index search and exact rule and agent IDs. Tie each alert to a positive action using decoded fields, source ports, a unit name or a run marker. Retain the indexed document and manager record IDs. |
| Negative controls | Confirm source outcomes and manager archive records for all ten scenarios. Check the manager archive and index across both phases so a late control match still fails the scenario. An unattributed indexed target alert also prevents a pass. D09 reads the service policy and writes a separate watched control file. |
| Analyst evidence | Trace raw entries to alert references, distinguish observed events from explanation, and capture the actual dashboard. |

The exercise measures ten scenarios over one bounded run. The runner allows up to 35 seconds after each control action for receipt at the manager and requires an additional 10 seconds before the final index query. The run report includes the receipt counts and query time. The private output also preserves phase ledgers, manager archives and indexed target records. A partially completed phase may have a ledger even when the final report is absent.

The runner measures per-scenario action-to-manager delay and the guest/collector clock offset. The final index check is an upper bound for all observed indexed alerts. A representative production false-positive rate or sustained ingestion capacity requires a larger corpus and independent traffic. The original design's 95% event coverage, 60-second p95 latency and 2% false-positive-window thresholds remain targets for broader load testing.

Allow two minutes between runs for D01's stock SSH correlation window to expire. Rule 5763 also suppresses repeats for 60 seconds after firing. [Wazuh 4.14.10 SSH rules](https://github.com/wazuh/wazuh/blob/v4.14.10/ruleset/rules/0095-sshd_rules.xml#L432-L439)

## Wazuh rule replay

The supported host procedure runs the D03, D05 and D09 pairs through a Wazuh Logtest session. Positives must decode and produce the exact target alert. Controls must also decode and exclude the target rule. Any failed fixture produces a nonzero replay exit status. The initial run supplies five archived inputs. Its D09 read had no archived record, so the helper constructs a separate-watch control from the positive and labels its provenance. The end-to-end run requires the new D09 control to be received from the real guest. [Wazuh Logtest documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
