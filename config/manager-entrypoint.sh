#!/usr/bin/env bash
set -euo pipefail
FROM=/wazuh-config-mount
TO=/var/ossec
# Wazuh's image-level sync can exit before copying config on a reused volume.
# Apply the project files in the documented manager hook before services start.
install -o root -g wazuh -m 0640 "$FROM/etc/ossec.conf" "$TO/etc/ossec.conf"
install -o root -g wazuh -m 0640 "$FROM/etc/rules/enterprise_soc.xml" "$TO/etc/rules/enterprise_soc.xml"
install -o root -g wazuh -m 0640 "$FROM/api/configuration/ssl/server.crt" "$TO/api/configuration/ssl/server.crt"
install -o root -g wazuh -m 0640 "$FROM/api/configuration/ssl/server.key" "$TO/api/configuration/ssl/server.key"
