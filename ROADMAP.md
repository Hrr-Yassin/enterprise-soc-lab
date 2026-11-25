# Implementation roadmap

The current lab uses the single-host deployment in [ADR 001](docs/adr-001-deployment.md). The original design is retained in the Phase 0 commit `7f82d20`.

| Milestone | Evidence to date | Remaining acceptance |
| --- | --- | --- |
| Wazuh and Linux deployment | Verified host TLS, running project services and the isolated active guest. Routine startup reused the running stack. Resource samples cover run 9007ca4b. | A clean-room installation and full-stack shutdown drill remain future exercises. |
| Detection engineering | Run 9007ca4b verified ten indexed positives and received controls with zero target matches. All six native Logtest records passed. | Expand the control and false-positive corpus for broader workloads. |
| Windows and Sysmon | Two Windows-shaped fixtures passed through the Linux agent and were indexed. The native collection and Sysmon policy files are in the repository. | Obtain a dedicated authorized Windows VM and validate native events and controls. |
| Incident response | Three simulated investigations preserve the baseline and cite manager and index evidence from the accepted run. Markdown and PDF versions are available. | Extend investigations when native Windows evidence is available. |
| Analyst dashboard | Visible Chromium rendered the live dashboards and an active Linux endpoint. Reviewed screenshots of Operations and the Agents table are retained with the project. | Repeat dashboard verification after major source or dependency changes. |
| Portfolio | Deployment instructions, curated runtime evidence, resource measurements, reports and demonstration material are ready for review. | Publish to the remote repository after approval. |

See the [handoff](HANDOFF.md) for the current blockers and next actions.
