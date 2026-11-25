#!/usr/bin/env python3
"""Limit guest loopback EVE output to the events the SOC uses."""
import os
from pathlib import Path
import socket

import yaml


def main():
    if os.geteuid() != 0 or socket.gethostname() != "soc-linux":
        raise SystemExit("This sensor is configured only in the dedicated SOC guest")
    config = yaml.safe_load(Path("/etc/suricata/suricata.yaml").read_text())
    config["outputs"] = [{"eve-log": {"enabled": True, "filetype": "regular",
                                     "filename": "eve.json", "types": ["alert", "dns"]}}]
    config["app-layer"]["protocols"]["dns"]["udp"]["detection-ports"]["dp"] = 15353
    config["stats"]["enabled"] = False
    output = Path("/etc/soc-lab/suricata.yaml")
    output.write_text(yaml.safe_dump(config, version=(1, 1), explicit_start=True, sort_keys=False))
    output.chmod(0o640)


if __name__ == "__main__":
    main()
