# Release handoff

The local candidate on `release/soc-portfolio` uses public baseline `7f82d20` as its parent. Publication to GitHub requires owner approval. The implementation and the raw evidence remain available in the original development workspace.

| Review area | Retained evidence |
| --- | --- |
| Detection and controls | [Run 9007ca4b](docs/evidence/run-9007ca4b.json), seven live guest scenarios and three fixtures. |
| Native replay | [Six Logtest verdicts](docs/evidence/logtest-9007ca4b.json), one positive and one control each for D03, D05 and D09. |
| Operations | [Visible dashboard captures](docs/evidence/screenshots/) and [resource measurements](docs/resources.md). |
| Release validation | Static checks and 25 automated tests passed. Public projections were compared with retained private evidence. Three single-page PDFs and two reviewed PNGs accompany the release. |
| Privacy | Runtime credentials, PKI, guest disks, raw logs and original captures stay in ignored directories. The snapshot carries the public GitHub no-reply identity. |

The lab uses a single indexer and a loopback Suricata sensor. The accepted run demonstrates the recorded workload. Native Windows EventChannel and Sysmon collection still require a dedicated licensed guest. A clean-room installation remains unverified. Weighted readiness remains 9.0/10 under the original rubric.

Use the [deployment guide](docs/deployment.md) to resume the existing lab or provision a dedicated host. The [demo guide](docs/demo.md) can be presented using the retained run and captures.
