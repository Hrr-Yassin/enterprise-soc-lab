# Engineering progress

## Baseline and investigation

On 25 November 2026 the first run passed seven of ten scenarios. Three positives reached the manager archive without producing the expected indexed alerts. The investigations record the original evidence and the subsequent retest. [Baseline](docs/evidence/run-0cee9232.json) · [Investigations](docs/incidents/)

## Native acceptance

Archived events guided corrections to D03 (sudo), D05 (systemd) and D09 (Auditd policy write). A separately watched control file established receipt of the D09 control. Native replay identified the stock rule that took precedence for D09. Run `9007ca4b` then passed 10/10 with ten indexed positives, 17 manager records across ten negative controls and zero control or unattributed target matches. Six archived records passed native Logtest. [Acceptance](docs/evidence/run-9007ca4b.json) · [Replay](docs/evidence/logtest-9007ca4b.json)

Visible Chromium verified dashboard authentication, Operations panels and the active Debian agent. Seven snapshots bracketed the acceptance workload. [Dashboard captures](docs/evidence/screenshots/) · [Measurements](docs/resources.md)

## Portfolio release candidate

The release includes deployment and troubleshooting instructions, an architecture diagram, a five-minute demonstration, three investigations in Markdown and PDF, 20 interview questions, English and French CV bullets, and a LinkedIn description. The local static checks and all 25 automated tests passed against the release tree. Windows and Sysmon validation uses labeled fixtures. A clean-room deployment remains open. [Handoff](HANDOFF.md)
