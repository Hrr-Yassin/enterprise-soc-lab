# Architecture

The lab uses rootless Podman for Wazuh and a separate QEMU/KVM guest for monitored activity. Both are named and scoped to this repository. The Linux guest is an independent cloud disk overlay. This layout uses no libvirt bridge, storage pool, or existing VM.

~~~mermaid
flowchart LR
  Analyst["Analyst browser<br/>127.0.0.1:8443"]
  subgraph Central["Rootless Podman internal network"]
    Dashboard["Wazuh Dashboard"]
    Manager["Wazuh Manager and Filebeat"]
    Index["Wazuh Indexer"]
    Archive["Private manager archive"]
    Dashboard -->|"HTTPS"| Index
    Dashboard -->|"Wazuh HTTPS API"| Manager
    Manager -->|"Filebeat with certificate validation"| Index
    Manager --> Archive
  end
  subgraph Guest["Dedicated soc-linux QEMU guest"]
    Audit["Auditd and system logs"]
    FIM["FIM and test application"]
    Sensor["Suricata on guest loopback"]
    Agent["Wazuh agent"]
    Audit --> Agent
    FIM --> Agent
    Sensor -->|"EVE JSON"| Agent
  end
  Analyst -->|"HTTPS using project CA"| Dashboard
  Agent -->|"Authenticated AES channel via loopback relay"| Manager
~~~

| Host listener | Purpose |
| --- | --- |
| 127.0.0.1:8443/TCP | Dashboard HTTPS |
| 127.0.0.1:15140/TCP | Wazuh agent data relay |
| 127.0.0.1:22223/TCP | Key-only SSH to the dedicated Linux guest |

The indexer and manager API are reachable only inside the project network. Enrollment uses a per-agent key created through the manager's authenticated private API and installed over the guest's pinned, key-only SSH connection. During package setup, QEMU forwards the guest update connection to a private Unix socket. The relay allows HTTPS CONNECT to Debian and Wazuh package repositories and ends when provisioning exits. The normal guest launch forwards agent data and listens on the loopback SSH port.

Suricata observes the exercise's traffic on the Linux guest's loopback interface. Its alerts document what that sensor could see. A separate routing or mirroring design would be necessary for traffic between real endpoints. The collector and indexer run on one host, so a crash or disk loss there affects the whole lab.

See the [deployment procedure](deployment.md), [decision record](adr-001-deployment.md), and [threat model](threat-model.md).
