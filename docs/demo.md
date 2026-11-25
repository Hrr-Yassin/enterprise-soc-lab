# Five-minute demonstration

Have the stack running and the accepted `9007ca4b` exercise report ready before the interview. Open the local Operations dashboard and keep the private evidence available in a terminal.

| Time | Show | Explain |
| --- | --- | --- |
| 0:00–0:45 | Architecture diagram and health output | Explain the trust boundary between the monitored guest and the Wazuh network. Describe why management is on loopback and why Suricata sees guest loopback only. |
| 0:45–1:30 | Wazuh agent status and the coverage panel | Show the active Linux agent. Point out which records came from live guest services and which came from Windows-shaped fixtures. |
| 1:30–2:25 | Authentication alerts | Open D01 and show the eighth failed record to the correlation alert. Show the seven-event control and explain why stock per-source correlation was retained. |
| 2:25–3:20 | FIM and policy alerts | Compare D04's before and after hashes. Show D09's native Logtest verdict, indexed rule 100109 and the separately watched control record. Explain why stock rule 92600 took precedence in the first replay. |
| 3:20–4:15 | A network case | Compare the allowed and disallowed destinations. Identify what Suricata observed and what remains unknown about intent. |
| 4:15–5:00 | Validation report and case decision | Summarize the observed alert and control counts, the sample-size limitation, and a practical next change before wider deployment. |

For a live rerun, start the exercise before the demo. The runner has distinct control and positive windows and waits for index refresh. Keep the completed run available for a five-minute presentation. [Accepted run](evidence/run-9007ca4b.json) · [Native Logtest](evidence/logtest-9007ca4b.json) · [Operations capture](evidence/screenshots/operations-9007ca4b.png) · [Agents capture](evidence/screenshots/agents-9007ca4b.png)
