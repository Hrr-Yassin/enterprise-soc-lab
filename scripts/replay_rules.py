#!/usr/bin/env python3
"""Replay D03, D05 and D09 through the project's private Wazuh Logtest API."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import health
from run_scenarios import SCENARIOS, event_matches

CASES = {"D03": ("auditd", "audit"), "D05": ("systemd", "syslog"), "D09": ("auditd", "audit")}


def prepare(report, events):
    for row in report["scenarios"]:
        case = row["scenario"]
        if case not in CASES:
            continue
        decoder, log_format = CASES[case]
        fixtures = {}
        for phase in ("positive", "control"):
            action = row[phase]
            record = next((entry for entry in events if event_matches(entry, action, report["run"])), None)
            if record:
                log, location, origin = record["full_log"], record["location"], "manager archive"
            elif case == "D09" and phase == "control" and "audited_control_path" not in action:
                # The original run only read the service policy. Derive a fixture for the revised watch.
                positive, _ = fixtures["positive"]
                location = positive["location"]
                log = positive["event"]
                for old, new in (
                    ('key="soc_policy_change"', 'key="soc_policy_control"'),
                    ('name="/var/lib/soc-lab/policy/service.conf"', 'name="/var/lib/soc-lab/policy/control.conf"'),
                ):
                    if log.count(old) != 1:
                        raise ValueError("Cannot derive D09 control from the archived Auditd write")
                    log = log.replace(old, new)
                origin = "constructed control from archived positive"
            else:
                raise ValueError(f"Archived log for {case} {phase} is missing")
            payload = {"event": log, "location": location, "log_format": log_format}
            metadata = {"scenario": case, "phase": phase, "origin": origin, "expected_decoder": decoder,
                        "target_rule": SCENARIOS[case][0], "fixture_sha256": hashlib.sha256(log.encode()).hexdigest()}
            fixtures[phase] = payload, metadata
            yield payload, metadata


def evaluate(response, metadata):
    data = response.get("data") or {}
    output = data.get("output")
    if response.get("error") != 0 or not isinstance(output, dict):
        raise RuntimeError(f"Wazuh Logtest rejected {metadata['scenario']} {metadata['phase']}")
    decoder_info = output.get("decoder")
    rule = output.get("rule")
    decoder = decoder_info.get("name") if isinstance(decoder_info, dict) else None
    rule_id = str(rule.get("id", "")) if isinstance(rule, dict) else ""
    target = rule_id == metadata["target_rule"]
    alert = data.get("alert")
    expected_match = target and alert is True if metadata["phase"] == "positive" else not target
    return {**metadata, "observed_decoder": decoder, "observed_rule": rule_id or None,
            "alert": alert, "passed": decoder == metadata["expected_decoder"] and expected_match}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="private local-results run.json")
    parser.add_argument("--prepare-only", action="store_true", help="check sample selection without contacting Wazuh")
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    with (args.report.parent / "manager-archives.jsonl").open() as archive:
        inputs = list(prepare(report, [json.loads(line) for line in archive]))
    if {(sample["scenario"], sample["phase"]) for _, sample in inputs} != {
        (case, phase) for case in CASES for phase in ("positive", "control")
    } or len(inputs) != 6:
        raise ValueError("Replay requires one positive and one control for each corrected rule")
    if args.prepare_only:
        print(json.dumps([sample for _, sample in inputs], indent=2))
        return 0

    results = []
    token = None
    os.umask(0o077)
    path = args.report.parent / f"wazuh-logtest-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}.jsonl"
    with path.open("x", buffering=1) as evidence:
        for payload, metadata in inputs:
            if token:
                payload["token"] = token
            response = health.api("/logtest", method="PUT", payload=payload)
            result = evaluate(response, metadata)
            results.append(result)
            token = response["data"].get("token")
            evidence.write(json.dumps(result) + "\n")
            print(f"{result['scenario']} {result['phase']} {'PASS' if result['passed'] else 'FAIL'}")
    print(f"Wazuh Logtest evidence retained in {path}")
    return int(not all(result["passed"] for result in results))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
