#!/usr/bin/env python3
"""Configure seven-day retention for the isolated lab's Wazuh alerts."""
import argparse
import sys

import health

NAME = "enterprise-soc-alerts-7d"
PATTERN = "wazuh-alerts-4.x-*"
POLICY = {
    "policy": {
        "description": "Delete lab alert indices seven days after creation",
        "default_state": "collect",
        "states": [
            {"name": "collect", "actions": [],
             "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "7d"}}]},
            {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
        ],
        "ism_template": [{"index_patterns": [PATTERN], "priority": 100}],
    },
}


def install():
    existing = health.indexer("/_plugins/_ism/policies?size=100")["policies"]
    match = next((row for row in existing if row["_id"] == NAME), None)
    if match:
        old = match["policy"]
        if any(old.get(key) != value for key, value in POLICY["policy"].items()
               if key not in {"states", "ism_template"}):
            raise RuntimeError(f"The existing policy {NAME} differs from the project policy")
    else:
        health.indexer(f"/_plugins/_ism/policies/{NAME}", method="PUT", payload=POLICY)
    indices = health.indexer(f"/_cat/indices/{PATTERN}?format=json&h=index")
    if indices:
        for entry in indices:
            index = entry["index"]
            explanation = health.indexer(f"/_plugins/_ism/explain/{index}")[index]
            current = explanation.get("policy_id")
            if current and current != NAME:
                raise RuntimeError(f"{index} already has a different retention policy")
            if not current:
                result = health.indexer(f"/_plugins/_ism/add/{index}", method="POST", payload={"policy_id": NAME})
                if result.get("failures"):
                    raise RuntimeError(f"Could not attach retention to {index}")
    print(f"Installed/verified {NAME} for {PATTERN}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        install()
    except (OSError, KeyError, RuntimeError, ValueError) as exc:
        sys.exit(str(exc))
