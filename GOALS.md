# Goals

Build an isolated, reproducible SOC with Wazuh, endpoint and network telemetry, verified detections, evidence-backed investigations, and a professional portfolio. Do not expose management services publicly or modify existing lab resources.

Completion requires running components, collected telemetry, tested rules, and real evidence.

## Current evidence

Native acceptance run `9007ca4b` met the ten-scenario target with a received control for each scenario and zero control target matches. The six archived D03, D05 and D09 records passed native Logtest. The Fedora runtime, resource sample and visible Operations and Agents captures are verified. Native Windows monitoring remains scoped to a future dedicated guest.

Every acceptance pass requires the expected indexed alert, matched controls in the manager archive and a complete, settled index query across both phases. Any failed Wazuh replay fixture stops the deployment verification sequence.
