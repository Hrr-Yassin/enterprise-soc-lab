#!/usr/bin/env python3
"""Generate bounded lab activity and labeled log fixtures inside soc-linux."""

import argparse
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
from threading import Thread

LOG = Path("/var/log/soc-lab")
DATA = Path("/var/lib/soc-lab")


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def append(path, record):
    with path.open("a", encoding="utf-8") as output:
        output.write(record + "\n")


def ssh_failures(run, positive):
    stamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)
    # TEST-NET addresses are log data. No SSH login attempts are sent by this exercise.
    block = int(run[-2:], 16)
    ip = f"198.51.100.{block}" if positive else f"203.0.113.{block}"
    events = 8 if positive else 7
    for index in range(events):
        append(LOG / "auth-fixture.log", f"{stamp} soc-linux sshd[{17000 + index}]: "
               f"Failed password for lab-{run} from {ip} port {25000 + index} ssh2")
    return {"source_ip": ip, "records": events, "fixture": True}


def windows_event(run, positive, case):
    if case == "D02":
        event_id, channel, provider = "4732", "Security", "Microsoft-Windows-Security-Auditing"
        event_data = {"targetSid": "S-1-5-32-544" if positive else "S-1-5-32-545",
                      "subjectUserName": "LabOperator", "memberName": f"LabMember-{run}"}
    else:
        event_id, channel, provider = "1", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon"
        folder = r"C:\Users\Public" if positive else r"C:\Program Files\SocLab"
        event_data = {"image": folder + r"\InventoryProbe.exe",
                      "parentImage": r"C:\Windows\explorer.exe", "user": "SOC-WINDOWS\\LabOperator"}
    append(LOG / "windows-fixture.jsonl", json.dumps({
        "soc_fixture": "windows-eventchannel-v1", "soc_run": run, "soc_case": case,
        "soc_phase": "positive" if positive else "control",
        "win": {"system": {"eventID": event_id, "channel": channel, "providerName": provider,
                           "computer": "SOC-FIXTURE.invalid", "severityValue": "INFORMATION",
                           "systemTime": timestamp()}, "eventdata": event_data},
    }, separators=(",", ":")))
    return {"event_id": event_id, "fixture": True}


def sudo_test(run, positive):
    phase = "positive" if positive else "control"
    probe = ["/usr/bin/true", f"soc-d03-{run}-{phase}"]
    if positive:
        command = ["/usr/sbin/runuser", "-u", "soc-probe", "--", "/usr/bin/sudo", "-n", *probe]
    else:
        command = ["/usr/bin/sudo", "-n", "-u", "root", *probe]
    result = subprocess.run(command, capture_output=True, timeout=15)
    if (result.returncode != 0) != positive:
        raise RuntimeError(f"Unexpected exit status for the no-op sudo control: {result.returncode}")
    return {"command": " ".join(probe), "exit_code": result.returncode,
            "user": "soc-probe" if positive else "root"}


def fim_test(run, positive):
    path = DATA / "files" / ("inventory.txt" if positive else "notes.txt")
    if not path.is_file():
        raise RuntimeError("FIM baseline file is missing")
    path.write_text(f"baseline\nlab change {run}\n")
    return {"path": str(path)}


def service_test(run, positive):
    policy = "sandbox" if positive else "inventory"
    unit = f"soc-lab-{policy}-{run}.service"
    subprocess.run(["systemd-run", "--quiet", "--collect", "--wait", "--service-type=exec",
                    "--unit", unit, "--description", f"SOC lab job {policy}-{run}", "/usr/bin/true"],
                   check=True, capture_output=True, timeout=18)
    return {"unit": unit, "execution": "transient no-op"}


def dns_test(run, positive):
    domain = f"{run}.{'unapproved' if positive else 'approved'}.soc.test"
    question = b"".join(bytes([len(label)]) + label.encode() for label in domain.split(".")) + b"\0"
    question += struct.pack("!HH", 1, 1)
    transaction = int(run[-4:], 16)
    packet = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        client.settimeout(2)
        server.settimeout(2)
        server.bind(("127.0.0.1", 15353))
        client.sendto(packet, server.getsockname())
        received, source = server.recvfrom(512)
        if received != packet:
            raise RuntimeError("Local DNS test received an unexpected packet")
        answer = struct.pack("!HHHHHH", transaction, 0x8183, 1, 0, 0, 0) + question
        server.sendto(answer, source)
        if client.recvfrom(512)[0] != answer:
            raise RuntimeError("Local DNS test did not receive its NXDOMAIN response")
    return {"query": domain, "transaction_id": transaction, "destination": "127.0.0.1:15353"}


def network_test(run, positive):
    port = 15941 if positive else 15940
    payload = f"SOC UDP policy probe {run}".encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        server.settimeout(2)
        server.bind(("127.0.0.1", port))
        client.sendto(payload, server.getsockname())
        actual, source = server.recvfrom(512)
        if actual != payload:
            raise RuntimeError("Local UDP test received an unexpected payload")
    return {"destination_port": port, "source_port": source[1], "bytes_received": len(actual)}


def policy_test(run, positive):
    path = DATA / "policy/service.conf"
    contents = path.read_text()
    if positive:
        if "export_enabled=false" not in contents:
            raise RuntimeError("Unexpected lab policy baseline")
        path.write_text(f"export_enabled=false\n# lab change {run}\n")
        return {"path": str(path), "operation": "write"}
    control = path.with_name("control.conf")
    control.write_text(f"# lab control {run}\n")
    return {"path": str(path), "operation": "read", "audited_control_path": str(control)}


def application_test(run, positive):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            action = "export" if self.path == "/inventory/export" else "health"
            decision = "deny" if action == "export" else "allow"
            append(LOG / "app.jsonl", json.dumps({
                "soc_run": run, "soc_phase": "positive" if positive else "control",
                "app": {"service": "soc-inventory", "actor": "inventory-worker",
                        "actor_type": "service", "action": action, "decision": decision,
                        "event_time": timestamp()},
            }, separators=(",", ":")))
            self.send_response(403 if decision == "deny" else 200)
            self.end_headers()

        def log_message(self, *_):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        server.timeout = 5
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        try:
            connection.request("GET", "/inventory/export" if positive else "/health")
            code = connection.getresponse().status
            if code != (403 if positive else 200):
                raise RuntimeError(f"Unexpected lab application response: {code}")
        finally:
            connection.close()
            thread.join(5)
    return {"http_status": code}


SCENARIOS = {
    "D01": ssh_failures, "D02": lambda run, positive: windows_event(run, positive, "D02"),
    "D03": sudo_test, "D04": fim_test, "D05": service_test,
    "D06": lambda run, positive: windows_event(run, positive, "D06"), "D07": dns_test,
    "D08": network_test, "D09": policy_test, "D10": application_test,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run")
    parser.add_argument("phase", choices=("positive", "control"))
    args = parser.parse_args()
    if os.geteuid() != 0 or socket.gethostname() != "soc-linux" or not LOG.is_dir():
        parser.error("run as root only in the dedicated and provisioned soc-linux guest")
    if not re.fullmatch(r"[0-9a-f]{8}", args.run):
        parser.error("run must be an eight-character hexadecimal ID")
    for case, execute in SCENARIOS.items():
        started = timestamp()
        details = execute(args.run, args.phase == "positive")
        print(json.dumps({"scenario": case, "phase": args.phase, "started": started,
                          "finished": timestamp(), **details}), flush=True)


if __name__ == "__main__":
    main()
