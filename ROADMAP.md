# Implementation roadmap

Phase 0 design documentation is complete. Laboratory preparation and all implementation, validation and evidence tasks remain pending.

## Phase 0 — Requirements, architecture and laboratory preparation

- [x] Complete Phase 0 design documentation.
- [ ] Inventory sources, negotiate schema and controls.

| Objective | Dependencies | Expected outputs | Acceptance | Difficulty | Skills | Known risk |
| --- | --- | --- | --- | --- | --- | --- |
| Define telemetry contracts and lab boundaries | Host capacity and source docs | Topology and source map | Each signal and trust boundary has an owner | Medium | Telemetry planning | Host memory pressure |

## Phase 1 — Minimum viable educational prototype

- [ ] Collect two endpoint sources.
- [ ] Bring up isolated Windows and Linux telemetry.

| Objective | Dependencies | Expected outputs | Acceptance | Difficulty | Skills | Known risk |
| --- | --- | --- | --- | --- | --- | --- |
| Collect two endpoint sources | Snapshots and time sync | Collector health notes | A benign event from each host is traceable | Medium | Agent onboarding | Clock skew |

## Phase 2 — Core functionality

- [ ] Add network and correlate.
- [ ] Mirror traffic, normalize EVE, review ten rule specs.

| Objective | Dependencies | Expected outputs | Acceptance | Difficulty | Skills | Known risk |
| --- | --- | --- | --- | --- | --- | --- |
| Add network and correlate | Working endpoint flow | Rules and analyst views | Every rule has a field map and negative control | High | Detection engineering | Sigma translation gaps |

## Phase 3 — Security validation and controlled laboratory verification

- [ ] Replay and tune.
- [ ] Run five controlled scenarios and containment tabletop.

| Objective | Dependencies | Expected outputs | Acceptance | Difficulty | Skills | Known risk |
| --- | --- | --- | --- | --- | --- | --- |
| Replay and tune | Labeled fixtures and baseline | Measured results and case notes | All metrics have denominators and failures are traced | High | Quality measurement | Sparse baseline |

## Phase 4 — Documentation, performance evaluation and professional presentation

- [ ] Publish evidence.
- [ ] Redact packets and compare rates across replays.

| Objective | Dependencies | Expected outputs | Acceptance | Difficulty | Skills | Known risk |
| --- | --- | --- | --- | --- | --- | --- |
| Publish evidence | Approved summary artifacts | Playbook and evaluation report | Reader reproduces metrics from approved manifest | Medium | SOC reporting | Sensitive telemetry |
