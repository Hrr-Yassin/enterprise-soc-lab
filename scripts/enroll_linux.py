#!/usr/bin/env python3
"""Provision one Wazuh agent key through the authenticated private API and pinned SSH."""

import argparse
import base64
import fcntl
import re
import subprocess
import sys

import health

NAME = "soc-linux"
VM = str(health.ROOT / "scripts/linux_vm.sh")


def enroll():
    mode = subprocess.run([VM, "status"], check=True, text=True, capture_output=True)
    if "restrict=on (isolated)" not in mode.stdout:
        raise RuntimeError("The Linux guest must be running in restricted mode")
    with (health.STATE / "agent-enrollment.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = health.api(f"/agents?name={NAME}&select=id,name")["data"]
        agents = [item for item in data["affected_items"] if item["name"] == NAME]
        if len(agents) > 1:
            raise RuntimeError("Duplicate endpoint identity")
        if agents:
            agent_id = agents[0]["id"]
            data = health.api(f"/agents/{agent_id}/key")["data"]
            key = data["affected_items"][0]["key"]
        else:
            data = health.api("/agents", method="POST", payload={"name": NAME, "ip": "any"})["data"]
            agent_id, key = data["id"], data["key"]
        record = base64.b64decode(key, validate=True).decode().strip()
    fields = record.split()
    if len(fields) != 4 or fields[:3] != [agent_id, NAME, "any"] or not re.fullmatch(r"[a-fA-F0-9]{32,128}", fields[3]):
        raise RuntimeError("Manager returned an unexpected key format")
    command = """sudo sh -ec '
      test "$(hostname)" = soc-linux
      umask 077
      tempfile=$(mktemp /var/ossec/etc/.soc-key.XXXXXX)
      trap "rm -f -- $tempfile" EXIT
      cat > "$tempfile"
      chown root:wazuh "$tempfile"
      chmod 0640 "$tempfile"
      mv -f -- "$tempfile" /var/ossec/etc/client.keys
      systemctl enable --now wazuh-agent
      systemctl restart wazuh-agent
    '"""
    # The key is excluded from both command-line arguments and logs.
    result = subprocess.run([VM, "ssh", command], input=record + "\n", text=True,
                            capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError(f"Guest enrollment failed (exit {result.returncode})")
    print(f"Installed the Wazuh key for {NAME} (agent {agent_id})")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        enroll()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
