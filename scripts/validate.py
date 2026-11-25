#!/usr/bin/env python3
"""Validate tracked rules and deployment configuration without running the lab."""
import ast
from pathlib import Path
import re
import subprocess
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent


def validate():
    paths = ("detections/rules.xml", "endpoints/linux/agent.xml", "endpoints/windows/agent-localfiles.xml",
             "endpoints/windows/sysmon.xml")
    for path in paths:
        ElementTree.parse(ROOT / path)
    rules = ElementTree.parse(ROOT / paths[0]).findall("rule")
    ids = [int(rule.get("id")) for rule in rules]
    if len(set(ids)) != len(ids) or not (set(range(100100, 100110)) - {100101}) <= set(ids):
        raise ValueError("Detection rule IDs must be unique and cover the nine custom scenarios")
    signatures = re.findall(r"\bsid:(\d+);", (ROOT / "endpoints/linux/sensor.rules").read_text())
    if len(set(signatures)) != len(signatures):
        raise ValueError("Suricata signatures must have unique SIDs")
    for identifier in ("100107", "100108"):
        sid = next(rule for rule in rules if rule.get("id") == identifier).findtext("field").strip("^$")
        if sid not in signatures:
            raise ValueError(f"Wazuh rule {identifier} refers to a nonexistent Suricata signature")
    pinned = (ROOT / "config/central-images.env").read_text()
    for service in ("manager", "indexer", "dashboard"):
        if not re.search(fr"^SOC_{service.upper()}_IMAGE=docker.io/wazuh/wazuh-{service}@sha256:[0-9a-f]{{64}}$",
                         pinned, re.MULTILINE):
            raise ValueError(f"Image for {service} is not digest-pinned")
    for directory in ("scripts", "endpoints", "tests", "config"):
        for path in (ROOT / directory).rglob("*.py"):
            ast.parse(path.read_text(), filename=str(path))
        for path in (ROOT / directory).rglob("*.sh"):
            subprocess.run(["bash", "-n", path], check=True)


if __name__ == "__main__":
    validate()
    print("Rule, endpoint, digest, and script validation passed")
