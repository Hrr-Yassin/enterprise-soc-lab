# Portfolio copy

## CV bullets in English

- Built an isolated Wazuh 4.14.10 SOC lab with digest-pinned rootless Podman services, private TLS, loopback management access, and a dedicated Debian KVM endpoint. [Architecture evidence](architecture.md)
- Validated 10 of 10 detection scenarios, covering seven live Linux lab scenarios and three labeled fixtures. Confirmed all controls reached the manager with zero target matches and passed six native Wazuh Logtest cases. [Acceptance evidence](evidence/run-9007ca4b.json) · [Native replay](evidence/logtest-9007ca4b.json)
- Produced three simulated incident investigation reports with timelines, alert references, and containment and remediation decisions by correlating Wazuh, Auditd, file integrity, systemd, and Suricata evidence. [Identity](incidents/01-identity.md) · [Integrity](incidents/02-integrity.md) · [Network and application](incidents/03-network-policy.md)

## Points de CV en français

- Déployé un laboratoire SOC isolé avec Wazuh 4.14.10, des conteneurs Podman sans privilèges, des images référencées par empreinte SHA-256, une PKI privée, un accès de gestion en boucle locale et une VM Debian dédiée sous KVM. [Architecture](architecture.md)
- Validé 10 scénarios de détection sur 10, dont sept avec de la télémétrie réelle sous Linux et trois avec des événements de test étiquetés. Confirmé la réception de chaque contrôle négatif sans déclenchement de la règle cible et validé six cas de rejeu natif avec Wazuh Logtest. [Rapport de validation](evidence/run-9007ca4b.json) · [Rejeu natif](evidence/logtest-9007ca4b.json)
- Rédigé trois rapports d’investigation d’incidents simulés avec chronologies, références d’alertes et décisions de confinement et de remédiation, à partir de données corrélées provenant de Wazuh, d’Auditd, du contrôle d’intégrité des fichiers, de systemd et de Suricata. [Identité](incidents/01-identity.md) · [Intégrité](incidents/02-integrity.md) · [Réseau et application](incidents/03-network-policy.md)

## LinkedIn project description

I built an isolated SOC lab on Fedora with Wazuh, OpenSearch, rootless Podman, a dedicated Debian KVM endpoint, and Suricata. I traced endpoint and network signals from collection to indexed alerts and verified 10 of 10 controlled detection scenarios. The accepted run included seven live Linux lab scenarios, three labeled fixtures, and zero target matches from the negative controls. I also validated six archived records with native Wazuh Logtest and documented three simulated investigations. Windows Security and Sysmon coverage is currently fixture-based. The repository includes deployment instructions, reviewed dashboard captures, and evidence for the accepted run.
