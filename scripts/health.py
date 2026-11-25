#!/usr/bin/env python3
"""Verify the central processes, TLS listeners and authenticated backend APIs."""

import argparse
import base64
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "restricted/wazuh/native"
PODMAN = os.environ.get("SOC_PODMAN", "/usr/bin/podman")
MANAGER = "enterprise-soc-manager"
INDEXER = "enterprise-soc-indexer"
DASHBOARD = "enterprise-soc-dashboard"
CA = "/etc/ssl/soc-ca.pem"


def request(url, *, username=None, password=None, token=None, method="GET", payload=None):
    """Use the manager's network namespace, with authorization supplied over stdin."""
    args = ["curl", "--silent", "--show-error", "--fail-with-body", "--max-time", "8",
            "--cacert", CA, "--request", method, "--config", "-", url]
    settings = []
    if username is not None:
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        settings.append(f'header = "Authorization: Basic {auth}"')
    if token is not None:
        settings.append(f'header = "Authorization: Bearer {token}"')
    if payload is not None:
        settings.append('header = "Content-Type: application/json"')
        settings.append("data = " + json.dumps(json.dumps(payload)))
    completed = subprocess.run([PODMAN, "exec", "-i", MANAGER, *args],
                               input="\n".join(settings), text=True, capture_output=True, timeout=12)
    if completed.returncode:
        raise RuntimeError(f"{method} {url.split('?')[0]} failed (curl exit {completed.returncode})")
    return json.loads(completed.stdout)


def config():
    return dict(line.split("=", 1) for line in (STATE / "manager.env").read_text().splitlines())


def indexer(path, **kwargs):
    env = config()
    return request("https://wazuh.indexer:9200" + path, username=env["INDEXER_USERNAME"],
                   password=env["INDEXER_PASSWORD"], **kwargs)


def api_token():
    env = config()
    result = request("https://wazuh.manager:55000/security/user/authenticate",
                     username=env["API_USERNAME"], password=env["API_PASSWORD"], method="POST")
    return result["data"]["token"]


def api(path, **kwargs):
    return request("https://wazuh.manager:55000" + path, token=api_token(), **kwargs)


def dashboard_tls():
    context = ssl.create_default_context(cafile=STATE / "pki/ca.pem")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    with opener.open("https://127.0.0.1:8443/app/login", timeout=8) as response:
        if response.status != 200 or "text/html" not in response.headers.get("Content-Type", ""):
            raise RuntimeError(f"Unexpected dashboard status: {response.status}")
        return response.status


def checks(expected_agent=None):
    for name in (INDEXER, MANAGER, DASHBOARD):
        result = subprocess.run([PODMAN, "container", "inspect", "--format", "{{.State.Running}}", name],
                                text=True, capture_output=True, timeout=10)
        if result.returncode or result.stdout.strip() != "true":
            raise RuntimeError(f"{name} is not running")
    cluster = indexer("/_cluster/health")
    if cluster["status"] not in {"green", "yellow"} or cluster["number_of_data_nodes"] != 1:
        raise RuntimeError(f"Unexpected indexer health: {cluster['status']}")
    status = api("/manager/status")["data"]["affected_items"][0]
    for process in ("wazuh-analysisd", "wazuh-remoted", "wazuh-logcollector"):
        if status.get(process) != "running":
            raise RuntimeError(f"Manager process {process} is {status.get(process)}")
    if status.get("wazuh-authd") != "running":
        raise RuntimeError("Local enrollment service is not available")
    listeners = subprocess.run([PODMAN, "exec", MANAGER, "awk",
                                '$2 ~ /:05EB$/ && $4 == "0A" { print "listener" }',
                                "/proc/net/tcp", "/proc/net/tcp6"],
                               text=True, capture_output=True, timeout=8)
    if listeners.returncode or listeners.stdout.strip():
        raise RuntimeError("Could not verify the absence of a remote enrollment listener")
    if expected_agent:
        names = {item["name"] for item in api("/agents?status=active&select=name")["data"]["affected_items"]}
        if expected_agent not in names:
            raise RuntimeError(f"Expected active endpoint is missing: {expected_agent}")
    return {"indexer": cluster["status"], "dashboard_https": dashboard_tls(),
            "manager": "ready", "verified_active_endpoint": expected_agent}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", type=int, default=0, help="allow up to this many seconds for readiness")
    parser.add_argument("--require-agent", metavar="NAME")
    args = parser.parse_args()
    expires = time.monotonic() + max(0, args.wait)
    last_message = None
    while True:
        try:
            print(json.dumps(checks(args.require_agent), indent=2))
            return 0
        except (OSError, KeyError, RuntimeError, ValueError, subprocess.TimeoutExpired,
                urllib.error.URLError) as exc:
            error = str(exc)
            if error != last_message:
                print(f"Health check: {error}", file=sys.stderr, flush=True)
                last_message = error
            if time.monotonic() >= expires:
                return 1
            time.sleep(3)


if __name__ == "__main__":
    sys.exit(main())
