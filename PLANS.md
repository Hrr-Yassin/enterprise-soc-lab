# Plan

1. Inventory the existing project and host.
2. Select an isolated resource-bounded architecture and establish deployment prerequisites.
3. Deploy central services and dedicated telemetry sources; validate secure communications.
4. Implement and test detections with positive and negative controls.
5. Collect real evidence, complete investigations and dashboards, and validate reproducibility.

Windows and Sysmon depend on a dedicated authorized Windows VM. Do not report unobserved results as complete.

## Current execution order

1. Use the verified Fedora stack and retain the evidence from acceptance run `9007ca4b` and the six native replay cases.
2. Keep the verified visible Chromium captures for Operations and Agents with the accepted run.
3. Use the curated evidence, incident reports and measurements for the portfolio and repeat verification after deployment changes.
4. Onboard Windows on a dedicated guest when the guest, license and approved administrative access are available.
