# Troubleshooting

| Symptom | Diagnostic and recovery |
| --- | --- |
| Rootless Podman or KVM is inaccessible | From the authorized host account, run `python3 -B scripts/preflight.py`. Check the Podman runtime probe, writable user runtime directory and `/dev/kvm` access. A sandbox can hide the guest PID or prevent access to the runtime directory. Preserve the existing state and verify it from the host. |
| A host port is already in use | Check host ports 8443, 15140 and 22223 with `ss` before starting a fresh lab. Identify the listener owner before changing state. For a running lab, compare the listeners with the loopback addresses in the architecture diagram. |
| Indexer fails before initialization | Verify `vm.max_map_count` is at least 262144 and allow up to 3 GiB of memory for the indexer. Inspect `podman logs enterprise-soc-indexer` privately and check disk headroom and shard allocation. |
| Dashboard HTTP 503 during startup | Run `./scripts/soc.sh health --wait 180`. Check the manager, indexer and Dashboard startup logs privately for backend or certificate errors. |
| Indexer reports yellow | Check shard allocation. The accepted single-node run had 12 started primaries and three unassigned replicas. Investigate any unassigned primary before running acceptance. |
| HTTPS fails | Use the generated project CA and connect to `127.0.0.1` so the dashboard's IP SAN can be verified. Check validity, issuing CA and SAN before retrying. |
| SSH waits at the banner | Inspect `restricted/linux/serial.log` privately for the NoCloud datasource. The guest reads its seed through the second VirtIO disk. Preserve pinned SSH host-key checks and allow cloud-init to complete. |
| Provisioning cannot locate a pinned package | Check the dedicated guest is in bootstrap mode and that the temporary relay reaches the allowed sources. Verify the exact version in `endpoints/linux/provision.sh` is still available, including Bookworm backports and its dependencies for Suricata. Record any version change and reverify its rules and telemetry. |
| Agent stays disconnected | Confirm `./scripts/linux_vm.sh status` reports isolated mode and the host listens on `127.0.0.1:15140`. Check `/var/ossec/logs/ossec.log` inside the guest privately. Rerun `python -B scripts/enroll_linux.py` after the manager is healthy. |
| Endpoint event arrives but the index lacks the alert | Check the guest source and manager archive, then the manager alert file. Use native Logtest to see which decoder and rule matched. Investigate Filebeat and index connectivity after confirming the manager emitted the expected alert. |
| A rule update reports failure | Read the validation error, then check deployed rule state and run `./scripts/soc.sh health --wait 180 --require-agent soc-linux`. If the rollback itself fails, the script reports the path to the previous snapshot. Preserve it for recovery. |
| First integrity exercise yields no change event | Wait for the agent's initial file integrity scan. Confirm the baseline file exists and the configured directory is monitored before running the exercise. |
| Exercise reports an unobserved control | Use the run's private action ledger and `manager-archives.jsonl`. Check source services, the guest clock, log collector format and required decoder fields. For D09, confirm the separately watched control file is present and its Auditd rule is loaded. Retain the failed run and rerun after correcting the evidence path. |
| Native replay has missing fixtures | Supply the private `run.json` with its sibling `manager-archives.jsonl`. For a fresh lab, first run the ten-scenario exercise. The replay can check fixture selection locally with `--prepare-only`. |
| Visible browser capture fails to launch | Use a graphical host session with a compatible installed Chromium executable and pass its path in `--chromium`. Check local HTTPS and authentication before troubleshooting the dashboard locator or query. |

Check the served certificate with the local public CA without showing credentials. The curl test should return HTTP 200 for the dashboard login page.

~~~sh
openssl verify -x509_strict -verify_ip 127.0.0.1 \
  -CAfile restricted/wazuh/native/pki/ca.pem \
  restricted/wazuh/native/pki/wazuh.dashboard.pem
curl --noproxy 127.0.0.1 --cacert restricted/wazuh/native/pki/ca.pem \
  --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' \
  https://127.0.0.1:8443/app/login
~~~

Record UTC times, run IDs and rule IDs before attempting recovery. Keep raw logs, process arguments containing credential paths and unrelated host inventory private. Use the archive to confirm receipt and the index to trace alert delivery. [Deployment and verification](deployment.md) · [Validation strategy](testing-strategy.md)
