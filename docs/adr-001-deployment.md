# ADR 001 · Independent single-host deployment

**Status** Accepted for the Fedora lab.

The original design proposed separate KVM networks and a mirror port. The test host had eight logical CPUs and 31 GiB RAM. A dedicated single-node deployment provides endpoint-to-dashboard evidence with a bounded resource allocation and independent guest networking.

Use official digest-pinned Wazuh images with native rootless Podman, SELinux labels, named volumes, and memory and CPU caps. Publish Dashboard and agent data only on loopback. Give the Linux sensor and agent a 1.5 GiB cloud guest with its own disk, SSH identities, and constrained QEMU forwarding. Keep the Wazuh indexer the only search backend. Issue each agent a key administratively and disable automatic enrollment. Generate a private CA and use it for internal HTTPS and dashboard validation.

A rootful bridge and external sensors would offer broader traffic visibility but require changes at the host networking boundary. A multi-node indexer would consume more memory and still share the same physical failure domain. Native Podman also prevents the evaluated Compose provider from expanding service credentials into process arguments. The trade-offs are a single search node, a loopback capture boundary, and project administration using the local dashboard administrator account. [Wazuh deployment reference](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)

A separately licensed, dedicated Windows guest can use the same key issuance model. Existing guests are treated as outside the project unless their owner approves a change.

The native initializer reads three configuration templates from the Wazuh Docker single-node reference at commit `76ddb88b9c8b618a254a287f2684f93d3c5ac2f4`. The vendored files retain their [upstream license](../vendor/wazuh/LICENSE).
