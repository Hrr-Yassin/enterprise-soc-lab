# Security and ethical scope

Collect telemetry from enrolled training machines only. Keep raw captures and account identifiers in the lab and publish aggregate, approved measurements.

For documentation defects, use a GitHub issue and describe impact without uploading sensitive material. Use GitHub’s private vulnerability reporting only if the feature is available for this repository. Keep sensitive evidence within the authorized lab and contact the repository owner through an agreed private channel if needed.

## Deployment limitations

- Single-host deployment shares one failure domain. Monitor disk headroom and retain reviewed evidence outside that failure domain when needed.
- The dashboard uses a local administrator account. Define operator roles and audit access before adding other users.
- The capture client verifies the dashboard against the project CA and loopback IP before opening Chromium. The certificate exception is scoped to the issued dashboard public key. Login and import use the dashboard origin and disallow redirects. Use the project CA in the browser trust store for routine analyst sessions. [Chromium certificate option](https://github.com/chromium/chromium/blob/main/services/network/public/cpp/network_switches.cc)
- The Suricata sensor observes the dedicated guest loopback and provides passive visibility. The current deployment has no evidence of cross-host inspection.
- Keep the cloud-init ISO, guest disk, Wazuh enrollment state, PKI, credentials and raw archives private. Exclude those files from Git and inspect any screenshots before sharing.
