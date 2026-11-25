#!/usr/bin/env bash
# Run as root only inside the project-owned Debian cloud guest.
set -euo pipefail
umask 027
[[ $EUID == 0 && $(hostname) == soc-linux && -e /var/lib/cloud/instance/boot-finished ]] ||
  { echo 'This installer is only for the dedicated soc-linux cloud guest' >&2; exit 1; }
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export DEBIAN_FRONTEND=noninteractive
export https_proxy="http://10.0.2.101:3142"
# Use HTTPS even though APT independently verifies signed package metadata.
cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: https://deb.debian.org/debian
Suites: bookworm bookworm-updates bookworm-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://deb.debian.org/debian-security
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
apt-get -o Acquire::Retries=2 -o Acquire::Languages=none update -q
apt-get -q -y --no-install-recommends install ca-certificates curl gnupg auditd rsyslog
apt-get -q -y --no-install-recommends -t bookworm-backports install suricata=1:7.0.10-1~bpo12+1
systemctl disable --now suricata.service
key=$(mktemp)
trap 'rm -f -- "$key"' EXIT
curl --fail --silent --show-error --location --connect-timeout 15 \
  https://packages.wazuh.com/key/GPG-KEY-WAZUH --output "$key"
fingerprint=$(gpg --batch --show-keys --with-colons "$key" | awk -F: '$1=="fpr" && !found {print $10; found=1}')
[[ $fingerprint == 0DCFCA5547B19D2A6099506096B3EE5F29111145 ]] || { echo 'Wazuh signing key changed' >&2; exit 1; }
gpg --batch --yes --dearmor --output /usr/share/keyrings/enterprise-soc-wazuh.gpg "$key"
chmod 0644 /usr/share/keyrings/enterprise-soc-wazuh.gpg
printf 'deb [signed-by=/usr/share/keyrings/enterprise-soc-wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n' \
  > /etc/apt/sources.list.d/enterprise-soc-wazuh.list
apt-get -o Acquire::Retries=2 -o Acquire::Languages=none update -q
apt-get -q -y --no-install-recommends install wazuh-agent=4.14.10-1
systemctl stop wazuh-agent
install -o root -g wazuh -m 0640 agent.xml /var/ossec/etc/ossec.conf
install -d -m 0750 /etc/soc-lab /var/log/soc-lab /var/log/soc-lab/suricata \
  /var/lib/soc-lab /var/lib/soc-lab/files /var/lib/soc-lab/policy
install -m 0640 sensor.rules /etc/soc-lab/sensor.rules
python3 -I tune_suricata.py
for filename in system.log auth-fixture.log windows-fixture.jsonl app.jsonl suricata/eve.json; do
  touch "/var/log/soc-lab/$filename"
done
if [[ ! -f /var/lib/soc-lab/policy/service.conf ]]; then
  printf 'export_enabled=false\n' > /var/lib/soc-lab/policy/service.conf
fi
if [[ ! -f /var/lib/soc-lab/policy/control.conf ]]; then
  install -m 0640 /dev/null /var/lib/soc-lab/policy/control.conf
fi
for file in inventory notes; do
  if [[ ! -f /var/lib/soc-lab/files/$file.txt ]]; then
    printf 'baseline\n' > "/var/lib/soc-lab/files/$file.txt"
  fi
done
if ! id soc-probe >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin soc-probe
fi

install -o root -g root -m 0640 policy-audit.rules /etc/audit/rules.d/60-enterprise-soc.rules

cat > /etc/rsyslog.d/25-enterprise-soc.conf <<'EOF'
if ($programname == 'sudo' or $programname == 'systemd' or $programname == 'sshd') then {
  action(type="omfile" file="/var/log/soc-lab/system.log" template="RSYSLOG_TraditionalFileFormat")
}
EOF

cat > /etc/systemd/system/soc-suricata.service <<'EOF'
[Unit]
Description=Enterprise SOC Suricata loopback sensor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/suricata -c /etc/soc-lab/suricata.yaml -S /etc/soc-lab/sensor.rules --pcap=lo -l /var/log/soc-lab/suricata --runmode single
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

rsyslogd -N1
suricata -T -c /etc/soc-lab/suricata.yaml -S /etc/soc-lab/sensor.rules -l /var/log/soc-lab/suricata
systemctl daemon-reload
systemctl enable --now auditd rsyslog soc-suricata
systemctl restart rsyslog
augenrules --load
auditctl -l
dpkg-query -W wazuh-agent auditd rsyslog suricata
printf '%s\n' 'Guest configured. Shut down bootstrap mode, then start the VM in restricted mode and enroll the agent.'
