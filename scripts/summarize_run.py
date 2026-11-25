#!/usr/bin/env python3
"""Project a lab run into shareable metrics without including raw event data."""

import argparse
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path


def timestamp(value):
    return datetime.fromisoformat(value)


def project(run, archive):
    rows = []
    latency = []
    endpoint_offset = run["clock_offset_seconds"]
    for scenario in run["scenarios"]:
        alerts = scenario["observed_alerts"]
        started = timestamp(scenario["positive"]["started"])
        if alerts:
            elapsed = round((timestamp(alerts[0]["timestamp"]) - started).total_seconds() + endpoint_offset, 3)
            latency.append(elapsed)
        else:
            elapsed = None
        rows.append({
            "scenario": scenario["scenario"], "telemetry": scenario["source"], "rule": scenario["expected_rule"],
            "pass": scenario["passed"], "control_records_at_manager": scenario["control_evidence"]["manager_records"],
            "control_target_alerts": len(scenario["control_alert_ids"]), "source_to_manager_seconds": elapsed,
            "alerts": [{"record_id": alert["id"], "indexed_document_id": alert["document_id"],
                        "index": alert["index"], "received_at": alert["timestamp"], "level": alert["rule"]["level"],
                        "description": alert["rule"]["description"]} for alert in alerts],
        })
        if "unexpected_target_alert_ids" in scenario:
            rows[-1]["unattributed_target_alerts"] = len(scenario["unexpected_target_alert_ids"])
            rows[-1]["control_index_settled"] = scenario["control_index_settled"]
        if "manager_target_record_ids" in scenario["control_evidence"]:
            rows[-1]["control_targets_at_manager"] = len(scenario["control_evidence"]["manager_target_record_ids"])
    latency.sort()
    summary = {
        "run": run["run"], "scope": "Authorized synthetic and live benign events in the dedicated SOC guest",
        "control_window_started_at": run["control_start"], "positive_window_started_at": run["positive_start"],
        "index_checked_at": run["checked_at"], "endpoint_clock_offset_seconds": endpoint_offset,
        "latency_method": "Manager alert timestamp minus guest action start, adjusted by guest-minus-collector clock offset",
        "agent": run["agent"]["name"], "agent_version": run["agent"]["version"],
        "scenario_count": len(rows), "passed_scenarios": sum(item["pass"] for item in rows),
        "false_target_alerts": sum(item["control_target_alerts"] for item in rows),
        "positives_with_indexed_alert": sum(bool(item["alerts"]) for item in rows),
        "p95_source_to_manager_seconds": latency[math.ceil(len(latency) * 0.95) - 1] if latency else None,
        "private_archive_sha256": hashlib.file_digest(archive, "sha256").hexdigest(),
        "scenarios": rows,
    }
    if "index_snapshot_at" in run:
        summary["index_query_started_at"] = run["index_snapshot_at"]
        summary["unattributed_target_alerts"] = sum(item["unattributed_target_alerts"] for item in rows)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    with (args.report.parent / "manager-archives.jsonl").open("rb") as archive:
        print(json.dumps(project(json.loads(args.report.read_text()), archive), indent=2))
