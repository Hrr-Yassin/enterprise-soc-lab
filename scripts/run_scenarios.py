#!/usr/bin/env python3
"""Exercise lab detections and verify exact Wazuh alerts in OpenSearch."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

import health

ROOT = health.ROOT
VM = str(ROOT / "scripts/linux_vm.sh")
EXERCISE = ROOT / "endpoints/linux/exercise.py"
INDEX_SETTLE = timedelta(seconds=10)
MAX_CONTROL_INGEST = timedelta(seconds=35)
SCENARIOS = {
    "D01": ("5763", "fixture: OpenSSH"),
    "D02": ("100102", "fixture: Windows Security 4732"),
    "D03": ("100103", "live: Linux sudo"),
    "D04": ("100104", "live: Wazuh FIM"),
    "D05": ("100105", "live: Linux systemd"),
    "D06": ("100106", "fixture: Sysmon 1"),
    "D07": ("100107", "live: Suricata DNS"),
    "D08": ("100108", "live: Suricata UDP"),
    "D09": ("100109", "live: Linux Auditd"),
    "D10": ("100100", "live: lab HTTP application"),
}


def utc():
    return datetime.now(timezone.utc)


def guest(*args, timeout=65):
    return subprocess.run([VM, *args], check=True, timeout=timeout, capture_output=True, text=True).stdout


def records(run, phase, output):
    command = f"sudo /usr/bin/python3 /home/soc/exercise.py {run} {phase}"
    ledger = output / f"{phase}-actions.jsonl"
    with ledger.open("x") as stream:
        # Preserve completed actions even if the guest command exits partway through the phase.
        subprocess.run([VM, "ssh", command], check=True, timeout=65, stdout=stream, stderr=subprocess.PIPE)
    result = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
    if ([item["scenario"] for item in result] != list(SCENARIOS)
            or any(item["phase"] != phase for item in result)):
        raise RuntimeError(f"Guest did not complete all {phase} scenarios")
    return result


def alerts(agent_id, start):
    query = {"size": 200, "track_total_hits": True, "sort": [{"timestamp": "asc"}],
             "query": {"bool": {"filter": [
                 {"term": {"agent.id": agent_id}},
                 {"range": {"timestamp": {"gte": start.isoformat(timespec="milliseconds")}}},
                 {"terms": {"rule.id": [values[0] for values in SCENARIOS.values()]}},
             ]}}}
    result = health.indexer("/wazuh-alerts-4.x-*/_search?allow_no_indices=true&allow_partial_search_results=false",
                            method="POST", payload=query)
    shards = result["_shards"]
    if result["timed_out"] or shards["failed"] or shards["successful"] != shards["total"]:
        raise RuntimeError("Incomplete indexer search cannot verify scenario alerts")
    if result["hits"]["total"]["value"] > query["size"]:
        raise RuntimeError("Unexpectedly high scenario alert count")
    return result["hits"]["hits"]


def archives(agent_id, start):
    completed = subprocess.run([health.PODMAN, "exec", health.MANAGER, "tail", "-n", "2500",
                                "/var/ossec/logs/archives/archives.json"], check=True,
                               text=True, capture_output=True, timeout=12)
    events = []
    for line in completed.stdout.splitlines():
        try:
            event = json.loads(line)
            moment = datetime.fromisoformat(event["timestamp"])
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
        if moment >= start and event.get("agent", {}).get("id") == agent_id:
            events.append(event)
    return events


def alert_record(item):
    source = item["_source"]
    return {"document_id": item["_id"], "index": item["_index"], **{
        name: source[name] for name in ("timestamp", "id", "agent", "rule", "location", "data", "syscheck", "full_log")
        if name in source
    }}


def event_matches(record, action, run):
    """Tie a decoded record to one action, independent of its assigned rule."""
    case = action["scenario"]
    phase = action["phase"]
    positive = phase == "positive"
    data = record.get("data", {})
    log = record.get("full_log", "")
    if case == "D01":
        return (data.get("srcip") == action["source_ip"] and data.get("dstuser") == f"lab-{run}"
                and data.get("srcport") in {str(port) for port in range(25000, 25000 + action["records"])})
    if case in {"D02", "D06"}:
        return (data.get("soc_run"), data.get("soc_phase"), data.get("soc_case")) == (run, phase, case)
    if case == "D03":
        audit = data.get("audit", {})
        command = action["command"]
        audit_command = re.search(r'\bcmd=(?:"([^"]*)"|([0-9a-fA-F]+))(?= )', log)
        command_value = audit_command and (audit_command[1] if audit_command[2] is None else audit_command[2].upper())
        return ((audit.get("type"), audit.get("exe"), audit.get("res")) ==
                ("USER_CMD", '"/usr/bin/sudo"', "failed" if positive else "success")
                and command_value in {command, command.encode().hex().upper()}
                and f'UID="{action["user"]}"' in log.split())
    if case == "D04":
        fim = record.get("syscheck", {})
        return fim.get("path") == action["path"] and f"lab change {run}" in fim.get("diff", "")
    if case == "D05":
        return f'Started {action["unit"]} - SOC lab job ' in log
    if case == "D07":
        dns = data.get("dns", {})
        return any(item.get("rrname") == action["query"] and str(item.get("id")) == str(action["transaction_id"])
                   for item in [dns, *dns.get("query", [])])
    if case == "D08":
        return (str(data.get("src_port")) == str(action["source_port"])
                and str(data.get("dest_port")) == str(action["destination_port"]))
    if case == "D09":
        audit = data.get("audit", {})
        key = "soc_policy_change" if positive else "soc_policy_control"
        path = action["path"] if positive else action.get("audited_control_path")
        proctitle = re.search(r'\bproctitle=([0-9a-fA-F]+)', log)
        run_suffix = f"\0{run}\0{phase}".encode().hex()
        return (path and
                (audit.get("type"), audit.get("key"), audit.get("success"), audit.get("file", {}).get("name"))
                == ("SYSCALL", key, "yes", path) and proctitle
                and proctitle[1].lower().removesuffix("00").endswith(run_suffix))
    app = data.get("app", {})
    return ((data.get("soc_run"), data.get("soc_phase")) == (run, phase)
            and app.get("decision") == ("deny" if positive else "allow"))


def control_evidence(control, events, run):
    start = datetime.fromisoformat(control["started"]) - timedelta(seconds=2)
    end = datetime.fromisoformat(control["finished"]) + MAX_CONTROL_INGEST
    rule_id = SCENARIOS[control["scenario"]][0]
    matched = {}
    target_records = set()
    for event in events:
        timestamp = datetime.fromisoformat(event["timestamp"])
        if timestamp < start or not event_matches(event, control, run):
            continue
        if str((event.get("rule") or {}).get("id")) == rule_id:
            target_records.add(event["id"])
        if timestamp <= end:
            # A replayed copy of an SSH fixture cannot stand in for a missing attempt.
            key = event["data"]["srcport"] if control["scenario"] == "D01" else (event["id"], event["full_log"])
            matched[key] = event
    last = max((event["timestamp"] for event in matched.values()), default=None)
    return {"checked_at_source": True, "manager_records": len(matched),
            "expected_records": control.get("records", 1),
            "manager_record_ids": [event["id"] for event in matched.values()], "last_manager_record_at": last,
            "manager_target_record_ids": sorted(target_records)}


def evaluate_scenario(control, positive, indexed, events, run, positive_start, snapshot_at):
    case = positive["scenario"]
    rule_id, source = SCENARIOS[case]
    positive_alerts, control_ids, unexpected_ids = [], [], []
    for record in indexed:
        if record["rule"]["id"] != rule_id:
            continue
        if event_matches(record, control, run):
            control_ids.append(record["document_id"])
        elif datetime.fromisoformat(record["timestamp"]) >= positive_start and event_matches(record, positive, run):
            positive_alerts.append(record)
        else:
            unexpected_ids.append(record["document_id"])
    evidence = control_evidence(control, events, run)
    last = evidence["last_manager_record_at"]
    settled = bool(last and snapshot_at >= datetime.fromisoformat(last) + INDEX_SETTLE)
    ready = (bool(positive_alerts) and evidence["manager_records"] >= evidence["expected_records"] and settled)
    return {"scenario": case, "source": source, "expected_rule": rule_id, "positive": positive, "control": control,
            "control_evidence": evidence, "control_index_settled": settled, "control_alert_ids": control_ids,
            "unexpected_target_alert_ids": unexpected_ids, "observed_alerts": positive_alerts,
            "passed": ready and not evidence["manager_target_record_ids"] and not control_ids and not unexpected_ids}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=120, help="upper bound for alert arrival after emission")
    args = parser.parse_args()
    if not 30 <= args.timeout <= 300:
        parser.error("timeout must be between 30 and 300 seconds")
    os.umask(0o077)
    # Concurrency can cause two exercises to share a correlation window.
    import fcntl
    results = ROOT / "local-results"
    results.mkdir(exist_ok=True, mode=0o700)
    with (results / "exercise.lock").open("a") as guard:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error("an exercise is already running")
        return run_exercise(results, args.timeout)


def run_exercise(results, timeout):
    health.checks("soc-linux")
    if "restrict=on (isolated)" not in guest("status"):
        raise RuntimeError("Run the exercise only with the guest in restricted network mode")
    agent = next(item for item in health.api("/agents?name=soc-linux")["data"]["affected_items"]
                 if item["name"] == "soc-linux")
    before_clock = utc().timestamp()
    guest_clock = float(guest("ssh", "date -u +%s.%N"))
    after_clock = utc().timestamp()
    clock_offset = round(guest_clock - (before_clock + after_clock) / 2, 3)
    if abs(clock_offset) > 2:
        raise RuntimeError(f"Guest and collector clocks are {clock_offset:+.3f} seconds apart")
    guest("put", str(EXERCISE))
    run = secrets.token_hex(4)
    output = results / run
    output.mkdir()
    control_start = utc()
    controls = records(run, "control", output)
    print(f"{run}: emitted ten negative controls. Waiting for collector and index refresh.", flush=True)
    time.sleep(25)
    positive_start = utc()
    positives = records(run, "positive", output)
    print(f"{run}: emitted ten positive scenarios. Checking the indexer for exact rule IDs.", flush=True)

    deadline = time.monotonic() + timeout
    while True:
        events = archives(agent["id"], control_start)
        snapshot_at = utc()
        indexed = [alert_record(item) for item in alerts(agent["id"], control_start)]
        rows = [evaluate_scenario(control, positive, indexed, events, run, positive_start, snapshot_at)
                for control, positive in zip(controls, positives, strict=True)]
        if all(row["passed"] for row in rows) or time.monotonic() >= deadline:
            break
        time.sleep(3)
    checked = utc()
    report = {"run": run, "agent": {name: agent.get(name) for name in ("id", "name", "status", "version")},
              "control_start": control_start.isoformat(), "positive_start": positive_start.isoformat(),
              "index_snapshot_at": snapshot_at.isoformat(), "checked_at": checked.isoformat(),
              "clock_offset_seconds": clock_offset, "scenarios": rows}
    (output / "manager-archives.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
    (output / "indexed-targets.jsonl").write_text("".join(json.dumps(record) + "\n" for record in indexed))
    staging = output / "run.json.pending"
    staging.write_text(json.dumps(report, indent=2) + "\n")
    staging.replace(output / "run.json")
    for row in rows:
        evidence = row["control_evidence"]
        details = (f'{len(row["observed_alerts"])} positive, {len(row["control_alert_ids"])} control and '
                   f'{len(row["unexpected_target_alert_ids"])} unattributed target alert(s). '
                   f'{evidence["manager_records"]}/{evidence["expected_records"]} control record(s).')
        if evidence["manager_target_record_ids"]:
            details += f' Manager matched the target rule for {len(evidence["manager_target_record_ids"])} control record(s).'
        if not row["control_index_settled"]:
            details += " Control receipt or index settle interval pending."
        print(f'{row["scenario"]} {"PASS" if row["passed"] else "FAIL"}  {details}')
    print(f"Private run evidence is in {output}")
    return int(not all(row["passed"] for row in rows))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
