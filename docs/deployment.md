# Deploy and operate the lab

The accepted run used Fedora, rootless Podman and a dedicated Debian 12 KVM guest. Use this procedure from the repository root on an authorized Fedora x86-64 host. The release evidence covers the existing lab's native acceptance, rule reload and repeated start. A separate clean-room installation remains a future verification milestone. [Runtime evidence](evidence/run-9007ca4b.json) · [Resource report](resources.md)

## Host prerequisites

Use Python 3.12 or newer and OpenSSL 3. The project's command validation workflow uses Python 3.12. Install any missing Fedora packages from the following set. [Fedora QEMU](https://packages.fedoraproject.org/pkgs/qemu/qemu-system-x86/) · [QEMU disk tools](https://packages.fedoraproject.org/pkgs/qemu/qemu-img/) · [Fedora Ncat](https://packages.fedoraproject.org/pkgs/nmap/nmap-ncat/) · [genisoimage](https://packages.fedoraproject.org/pkgs/cdrkit/genisoimage/)

~~~sh
sudo dnf install podman qemu-system-x86 qemu-img openssh-clients \
  openssl genisoimage nmap-ncat python3 python3-pip curl iproute util-linux procps-ng
~~~

Review the probe results and check the three host listeners before a fresh start. The Podman runtime probe should report `true`, `/dev/kvm` must be accessible to the current user, and `vm.max_map_count` must be at least 262144. The QEMU relay uses `/usr/bin/nc`. The libvirt probe is inventory only. Keep the inventory output private because it can contain other VM names. [Podman rootless requirements](https://docs.podman.io/en/latest/markdown/podman.1.html#rootless-mode) · [Wazuh host requirements](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)

~~~sh
python3 -B scripts/preflight.py
test -x /usr/bin/nc
ss -H -ltn '( sport = :8443 or sport = :15140 or sport = :22223 )'
~~~

The ports must be free for a fresh setup. A running lab should already own these loopback listeners. Budget for up to 6 GiB of central container memory and 1.5 GiB guest RAM, plus host overhead. Allow storage for three OCI images, index data, manager archives and a growable 12 GiB guest overlay. Fresh provisioning needs access to the pinned public image and software sources. [Architecture and listeners](architecture.md) · [Measured resource use](resources.md)

## Local checks

~~~sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export SOC_PYTHON="$VIRTUAL_ENV/bin/python"

python -B scripts/validate.py
python -B -m unittest discover -s tests -v
~~~

Keep this environment active for subsequent commands. If Podman is installed at a different path, set `SOC_PODMAN` to its executable path.

## Fresh deployment

Run the one-time setup as the rootless Podman user. The scripts pin Wazuh 4.14.10 OCI image digests and create local certificates and credentials under the ignored `restricted/wazuh/native/` directory. Use its `credentials.txt` privately for sign-in. Trust the public CA in `pki/ca.pem` in the browser profile used for this lab. [Image digest pins](../config/central-images.env)

~~~sh
./scripts/soc.sh init &&
  ./scripts/soc.sh certs &&
  ./scripts/soc.sh start &&
  ./scripts/soc.sh health --wait 180
~~~

Bootstrap the dedicated guest only after the stack is healthy. The download checks the SHA-512 of Debian build `20261117-2665`. During provisioning, QEMU forwards updates to a temporary allowlisted HTTPS relay. The guest verifies Debian APT metadata and the Wazuh signing key, and selects Wazuh Agent `4.14.10-1` and Suricata `1:7.0.10-1~bpo12+1`. Artifact and package availability are prerequisites for a fresh install. [Debian cloud images](https://www.debian.org/distrib/) · [Debian Suricata package](https://packages.debian.org/bookworm-backports/suricata)

~~~sh
./scripts/linux_vm.sh download &&
  ./scripts/linux_vm.sh prepare &&
  ./scripts/linux_vm.sh start --bootstrap
~~~

Wait for SSH to become available. Provisioning waits for cloud-init once SSH connects. After provisioning succeeds, power down the bootstrap guest and start it in normal isolated mode. This mode keeps SSH on host loopback and forwards agent events to the manager's loopback listener. [QEMU user networking](https://www.qemu.org/docs/master/system/qemu-manpage.html)

~~~sh
./scripts/linux_vm.sh provision &&
  ./scripts/linux_vm.sh stop &&
  ./scripts/linux_vm.sh start
~~~

Once SSH is available again, check each guest service and enroll the agent. The enrollment script retrieves or creates the dedicated agent's key using the private API and installs it through host-key-pinned SSH.

~~~sh
./scripts/linux_vm.sh ssh 'for service in auditd rsyslog soc-suricata; do systemctl is-active --quiet "$service" || exit 1; done' &&
  python -B scripts/enroll_linux.py &&
  ./scripts/soc.sh health --wait 120 --require-agent soc-linux
~~~

The optional `python -B scripts/retention.py` command applies a seven-day deletion policy to lab alert indices. Export needed evidence before policy expiry. Manage private manager archives and local results separately.

## Resume an existing lab

Reuse the existing containers, volumes, credentials, guest disk and SSH keys. The one-time `init` and `certs` steps refuse existing state. The regular start commands reuse running resources. After SSH is available, verify the enrollment; use the enrollment script when recovering a disconnected agent. [Troubleshooting](troubleshooting.md)

~~~sh
./scripts/soc.sh start &&
  ./scripts/linux_vm.sh start &&
  ./scripts/linux_vm.sh status &&
  ./scripts/soc.sh health --wait 120 --require-agent soc-linux
~~~

## Reproduce the validated run

From the Fedora host, launch the runner below. It sends the exercise actions to the isolated `soc-linux` guest over SSH. Health checks verify authenticated manager and indexer connections, dashboard HTTPS and an active Linux agent. For each scenario, acceptance requires an indexed positive, manager receipt of the expected control records and an absence of target matches on controls in either the manager archive or the index. A complete index search is required. Allow at least two minutes between runs for the stock SSH correlation window. [Validation strategy](testing-strategy.md)

~~~sh
python -B scripts/run_scenarios.py
~~~

A passing run prints ten `PASS` lines and exits zero. It writes `run.json`, `manager-archives.jsonl`, `indexed-targets.jsonl` and phase ledgers under `local-results/<run-id>/`. Set `run_id` below to the eight-character ID printed by the exercise. A fresh clone generates its own private archives before replay. The public JSON files contain reviewed results and provide a reference for comparison. [Accepted run](evidence/run-9007ca4b.json) · [Six native replay verdicts](evidence/logtest-9007ca4b.json)

~~~sh
run_id=YOUR_RUN_ID
run_report="local-results/$run_id/run.json"
python -B scripts/replay_rules.py "$run_report"
python -B scripts/summarize_run.py "$run_report" > "local-results/$run_id/public-summary.json"
./scripts/measure.sh
~~~

The replay selects six archived records, runs them through Wazuh Logtest and saves the decoder and rule verdicts beside the report. The optional `--prepare-only` checks record selection locally. Spend time reviewing the summary before sharing it. Keep the raw ledgers, archives and credential files private. [Wazuh Logtest documentation](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)

## Reproduce the dashboard captures

Install the pinned browser dependency and its matching Chromium build. Use a graphical host session for `--headed`. Fedora users can supply a compatible installed Chromium path with `--chromium`. [Playwright browser setup](https://playwright.dev/python/docs/browsers) · [Fedora Chromium](https://packages.fedoraproject.org/pkgs/chromium/chromium/)

~~~sh
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python -B scripts/dashboard.py "$run_report" --headed
~~~

Each invocation checks local HTTPS, signs in with the generated credentials and imports the lab saved objects. It writes the Operations, Suricata and live Agents captures to a new private `dashboard-*` directory beside the report. The Agents capture masks the lab IP and other endpoint rows. Review the screenshots before sharing them. [Accepted Operations capture](evidence/screenshots/operations-9007ca4b.png) · [Accepted Agents capture](evidence/screenshots/agents-9007ca4b.png)

## Update an older provisioned guest

Use this procedure for an older `soc-linux` guest that predates the D09 control watch. Run it in normal isolated mode. The control file is created only when absent, and the watched policy file is outside the update.

~~~sh
./scripts/linux_vm.sh put endpoints/linux/policy-audit.rules &&
  ./scripts/linux_vm.sh ssh 'sudo sh -ec "test -e /var/lib/soc-lab/policy/control.conf || install -m 0640 /dev/null /var/lib/soc-lab/policy/control.conf" && sudo install -o root -g root -m 0640 /home/soc/policy-audit.rules /etc/audit/rules.d/60-enterprise-soc.rules && sudo augenrules --load && sudo auditctl -l' &&
  ./scripts/soc.sh reload-rules &&
  ./scripts/soc.sh health --wait 120 --require-agent soc-linux
~~~

Normal startup reuses deployed rules. Use `reload-rules` when updating a rule on an existing stack. It validates the exact candidate snapshot before restarting the manager. If Podman reports a restart error, the script restores the prior snapshot, attempts a recovery restart and reports failure. Recheck health before running an exercise. With an earlier private report available, use it for a preliminary replay. Validate the updated guest with a fresh exercise and replay using that run's archived control.

## Routine shutdown and cleanup

~~~sh
./scripts/linux_vm.sh stop &&
  ./scripts/soc.sh stop
~~~

Use the [resume steps](#resume-an-existing-lab) for the next start. For decommissioning, `soc.sh cleanup` removes project containers and the internal network. Named volumes remain available after this command. The separate `--purge-data` flag deletes those volumes and should follow evidence export. The guest disk, PKI and raw results live in `restricted/` and `local-results/` and need deliberate private archival or removal.
